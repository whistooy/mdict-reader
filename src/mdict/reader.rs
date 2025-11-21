use std::fs::File;
use std::io::{Read, Seek};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};
use log::info;

use super::format::content;
use super::format;
use super::iter::{KeysIterator, RecordIterator};
use super::types::error::{MdictError, Result};
use super::types::filetypes::FileType;
use super::types::models::*;

/// The main reader for MDict dictionary files.
/// 
/// Parses both .mdx (dictionary) and .mdd (data) files.
/// Supports MDict format versions 1.x, 2.x, and 3.x.
#[derive(Debug)]
pub struct MdictReader<T: FileType> {
    file: Arc<Mutex<File>>,
    pub header: MdictHeader,
    
    key_blocks: Vec<BlockMeta>,
    record_blocks: Vec<BlockMeta>,
    pub total_record_decomp_size: u64,

    /// Cached entry count, available if found in header/index.
    num_entries: u64,
    _file_type: PhantomData<T>,
}

impl<T: FileType> MdictReader<T> {
    /// Read an MDict file from the given path.
    ///
    /// Priority for determining text encoding (highest → lowest):
    /// 1. FileType::ENCODING_OVERRIDE (hard override for a given file type — e.g., MDD forces UTF-16LE)
    /// 2. `user_encoding` (explicit override provided by caller/CLI)
    /// 3. Encoding declared in the dictionary header
    ///
    /// **Note:** `user_encoding` has no effect on MDD files, which always use UTF-16LE per specification.
    ///
    /// # Arguments
    /// * `path` - File path to the .mdx or .mdd file
    /// * `passcode` - Optional (`regcode_hex`, `user_email`) tuple for encrypted files
    /// * `user_encoding` - Optional explicit encoding override (only applies to MDX; ignored for MDD)
    ///
    /// # Errors
    /// Returns an error if:
    /// - File cannot be opened
    /// - File format is invalid or corrupted
    /// - Unsupported version (4.0+)
    /// - Checksum verification fails
    pub fn new(
        path: impl AsRef<Path>,
        passcode: Option<(&str, &str)>,
        user_encoding: Option<&str>,
    ) -> Result<Self> {
        let path = path.as_ref();
        info!("Opening MDict file: {}", path.display());
        let mut file = File::open(path)?;

        // Parse header
        let mut mdict_header = format::header::parse(&mut file, passcode)?;

        // V3.0 forces UTF-8
        if mdict_header.version == MdictVersion::V3 {
            info!("V3.0 detected: forcing UTF-8 encoding");
            mdict_header.encoding = encoding_rs::UTF_8;
        } else {
            // Apply encoding override for v1/v2
            let final_encoding = T::ENCODING_OVERRIDE
                .or_else(|| user_encoding.map(super::utils::parse_encoding))
                .unwrap_or(mdict_header.encoding);
            if mdict_header.encoding != final_encoding {
                info!(
                    "Text encoding overridden: header='{}', final='{}'",
                    mdict_header.encoding.name(),
                    final_encoding.name()
                );
            }
            mdict_header.encoding = final_encoding;
        }

        // Branch on version
        let (key_blocks, record_blocks, total_record_decomp_size, num_entries) =
            format::index::parse(&mut file, &mdict_header)?;

        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            header: mdict_header,
            key_blocks,
            record_blocks,
            total_record_decomp_size,
            num_entries,
            _file_type: PhantomData,
        })
    }

    /// Returns the number of key blocks.
    pub fn num_key_blocks(&self) -> usize {
        self.key_blocks.len()
    }
    
    /// Returns the number of record blocks.
    pub fn num_record_blocks(&self) -> usize {
        self.record_blocks.len()
    }
    
    /// Returns the total number of entries in the dictionary.
    /// This is an O(1) operation, as the count is determined during initial parsing.
    pub fn num_entries(&self) -> u64 {
        self.num_entries
    }
    
    /// Returns the base iterator over all `(key_text, record_id)` pairs.
    ///
    /// This is the most primitive and fastest way to scan all keys. It only
    /// decodes key blocks and does not touch record blocks.
    ///
    /// Chain this with `.with_record_info()` and `.with_records()`
    /// for more complete data.
    pub fn iter_keys(&self) -> KeysIterator<'_, T> {
        KeysIterator::new(self)
    }

    /// A convenience method that returns an iterator over all `(key, record)` pairs.
    ///
    /// This is a shortcut for `reader.iter_keys().with_record_info().with_records()`.
    ///
    /// It handles all the intermediate steps of decoding key blocks, resolving record
    /// metadata, and decoding record blocks efficiently.
    ///
    /// The iterator yields `Result<(String, T::Record)>`, where `T::Record` is:
    /// - `String` for MDX files.
    /// - `Vec<u8>` for MDD files.
    pub fn iter_records(&self) -> RecordIterator<'_, T> {
        self.iter_keys().with_record_info().with_records()
    }
    
    /// Finds the record metadata for a given record ID (random access).
    ///
    /// Performs a binary search on the record blocks to locate the containing block.
    /// Returns an index-based `RecordInfo` for efficient storage.
    pub fn get_record_info(&self, id: u64, next_id: u64) -> Result<RecordInfo> {
        if self.record_blocks.is_empty() {
            return Err(MdictError::InvalidFormat("No record blocks available".to_string()));
        }
        // Binary search: find first block where decompressed_offset > id, then take prev.
        let block_index = self.record_blocks
            .partition_point(|block| block.decompressed_offset <= id) - 1;
        let block_meta = self.record_blocks.get(block_index).ok_or_else(|| {
            MdictError::InvalidFormat(format!("Record ID {} is out of bounds", id))
        })?;
        // Out-of-bounds if beyond this block
        if id >= block_meta.decompressed_offset + block_meta.decompressed_size {
            return Err(MdictError::InvalidFormat(format!("Record ID {} exceeds block bounds", id)));
        }
        let offset_in_block = id - block_meta.decompressed_offset;
        let size = next_id - id;
        Ok(RecordInfo {
            block_index,
            offset_in_block,
            size,
        })
    }
    
    /// Reads, decodes, and processes a single record into its final type.
    ///
    /// This is the primary method for random-access lookups.
    /// - For `MdictReader<Mdx>`, this returns `Result<String>`.
    /// - For `MdictReader<Mdd>`, this returns `Result<Vec<u8>>`.
    ///
    /// It performs a file read to get the necessary block, so it's best to
    /// use iterators for sequential access.
    pub fn read_record(&self, record_info: &RecordInfo) -> Result<T::Record> {
        let block_bytes = self.read_record_block(record_info.block_index)?;
        self.parse_record(&block_bytes, record_info)
    }

    /// Extracts and processes a record from a pre-loaded block's byte slice.
    ///
    /// This is a lower-level version of `read_record` that operates on data
    /// already in memory. The `RecordIterator` uses this internally to
    /// avoid re-reading the same block for multiple entries.
    pub fn parse_record(&self, block_bytes: &[u8], info: &RecordInfo) -> Result<T::Record> {
        content::parse_record::<T>(block_bytes, info, &self.header)
    }
    
    /// Reads and decodes a full record block from the file given its block index.
    ///
    /// This method is kept public for applications that wish to implement their
    /// own record caching strategies on top of the raw blocks.
    pub fn read_record_block(&self, block_index: usize) -> Result<Vec<u8>> {
        self.read_block(BlockType::Record, block_index)
    }

    pub(crate) fn read_key_block_entries(&self, block_index: usize) -> Result<Vec<KeyEntry>> {
        let decompressed = self.read_block(BlockType::Key, block_index)?;
        content::parse_key_entries(&decompressed, &self.header)
    }

    fn read_block(&self, block_type: BlockType, block_index: usize) -> Result<Vec<u8>> {
        let block_meta = self
            .get_block_meta(block_type, block_index)
            .ok_or_else(|| MdictError::InvalidFormat(format!("Invalid {} block index: {}", block_type, block_index)))?;
        self.read_and_decode_block(*block_meta)
    }

    fn get_block_meta(&self, block_type: BlockType, block_index: usize) -> Option<&BlockMeta> {
        match block_type {
            BlockType::Key => self.key_blocks.get(block_index),
            BlockType::Record => self.record_blocks.get(block_index),
        }
    }

    /// Generic function to read a raw block from disk and decode it.
    fn read_and_decode_block(&self, block_meta: BlockMeta) -> Result<Vec<u8>> {
        let mut file = self.file.lock().map_err(|_| MdictError::LockPoisoned)?;
        file.seek(std::io::SeekFrom::Start(block_meta.file_offset))?;
        let mut raw_block = vec![0u8; block_meta.compressed_size as usize];
        file.read_exact(&mut raw_block)?;

        content::decode_block(
            &mut raw_block,
            block_meta.decompressed_size,
            self.header.master_key.as_ref(),
            self.header.version,
        )
    }

    pub(crate) fn key_blocks(&self) -> &[BlockMeta] {
        &self.key_blocks
    }

    pub(crate) fn record_blocks(&self) -> &[BlockMeta] {
        &self.record_blocks
    }
}
