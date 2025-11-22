use std::fs::File;
use std::io::{Read, Seek};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};
use log::{debug, info, trace};

use super::format::content;
use super::format;
use super::iter::{KeysIterator, RecordIterator};
use super::types::error::{MdictError, Result};
use super::types::filetypes::FileType;
use super::types::models::*;

/// The main reader for MDict dictionary files.
///
/// This type-parameterized reader handles both MDX (dictionary definitions)
/// and MDD (resource data) files across all MDict format versions (1.x, 2.x, 3.x).
///
/// # Type Parameter
/// * `T` - File type marker: [`Mdx`] for dictionaries, [`Mdd`] for resources
///
/// # Thread Safety
/// The internal file handle is wrapped in `Arc<Mutex<File>>`, making the reader
/// `Send` and `Sync` for concurrent access from multiple threads.
#[derive(Debug)]
pub struct MdictReader<T: FileType> {
    file: Arc<Mutex<File>>,
    pub header: MdictHeader,
    
    key_blocks: Vec<BlockMeta>,
    record_blocks: Vec<BlockMeta>,
    pub total_record_decomp_size: u64,

    /// Total number of entries in the dictionary (cached from index parsing).
    num_entries: u64,
    _file_type: PhantomData<T>,
}

impl<T: FileType> MdictReader<T> {
    /// Opens and parses an MDict file from the given path.
    ///
    /// # Text Encoding Priority
    /// Encoding is determined in this order (highest to lowest):
    /// 1. **Version 3.0**: Always uses UTF-8 regardless of file type or user settings
    /// 2. **MDD files**: Always use UTF-16LE per format specification
    /// 3. **MDX v1/v2**: `user_encoding` parameter if provided
    /// 4. **Fallback**: Encoding declared in the file's XML header
    ///
    /// # Arguments
    /// * `path` - Path to the MDict file (.mdx or .mdd)
    /// * `passcode` - Optional decryption credentials as `(regcode_hex, user_email)`
    /// * `user_encoding` - Optional encoding override (only applies to MDX v1/v2 files)
    ///
    /// # Errors
    /// Returns [`MdictError`] if:
    /// - File cannot be opened or read
    /// - File format is invalid or corrupted
    /// - Version is unsupported (4.0+)
    /// - Checksum verification fails
    /// - File is encrypted but no valid passcode provided
    pub fn new(
        path: impl AsRef<Path>,
        passcode: Option<(&str, &str)>,
        user_encoding: Option<&str>,
    ) -> Result<Self> {
        let path = path.as_ref();
        info!("Opening {} file: {}", T::DEBUG_NAME, path.display());
        let mut file = File::open(path)?;

        // Step 1: Parse file header and extract metadata
        debug!("Parsing file header");
        let mut mdict_header = format::header::parse(&mut file, passcode)?;

        // Step 2: Apply version-specific encoding rules
        let original_encoding = mdict_header.encoding;
        let final_encoding = if mdict_header.version == MdictVersion::V3 {
            // V3.0 always uses UTF-8 regardless of header or user settings
            encoding_rs::UTF_8
        } else {
            // For v1/v2, apply encoding override priority:
            // 1. File type override (MDD → UTF-16LE)
            // 2. User-provided encoding parameter
            // 3. Encoding from file header
            T::ENCODING_OVERRIDE
                .or_else(|| user_encoding.map(super::utils::parse_encoding))
                .unwrap_or(mdict_header.encoding)
        };
        
        // Log encoding changes for clarity
        if original_encoding != final_encoding {
            debug!(
                "Encoding override applied: header='{}' → final='{}' (reason: {})",
                original_encoding.name(),
                final_encoding.name(),
                if mdict_header.version == MdictVersion::V3 {
                    "V3.0 specification"
                } else if T::ENCODING_OVERRIDE.is_some() {
                    "MDD file type requires UTF-16LE"
                } else {
                    "user parameter"
                }
            );
        }
        mdict_header.encoding = final_encoding;

        // Step 3: Parse index blocks (version-specific)
        debug!("Parsing block indexes");
        let (key_blocks, record_blocks, total_record_decomp_size, num_entries) =
            format::index::parse(&mut file, &mdict_header)?;

        info!(
            "{} file loaded: {} entries, {} key blocks, {} record blocks",
            T::DEBUG_NAME,
            num_entries,
            key_blocks.len(),
            record_blocks.len()
        );

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

    /// Returns the total number of key blocks in the file.
    pub fn num_key_blocks(&self) -> usize {
        self.key_blocks.len()
    }
    
    /// Returns the total number of record blocks in the file.
    pub fn num_record_blocks(&self) -> usize {
        self.record_blocks.len()
    }
    
    /// Returns the total number of dictionary entries.
    ///
    /// This is O(1) as the count is cached during index parsing.
    pub fn num_entries(&self) -> u64 {
        self.num_entries
    }
    
    /// Returns an iterator over `(key_text, record_id)` pairs.
    ///
    /// This is the lightest-weight iterator, only decoding key blocks without
    /// accessing record data. Use this for tasks like:
    /// - Building search indexes
    /// - Listing all dictionary keys
    /// - Counting entries
    ///
    /// Chain with [`.with_record_info()`](KeysIterator::with_record_info) and
    /// [`.with_records()`](RecordInfoIterator::with_records) to access definitions.
    pub fn iter_keys(&self) -> KeysIterator<'_, T> {
        KeysIterator::new(self)
    }

    /// Returns an iterator over all `(key, record)` pairs.
    ///
    /// This is equivalent to `reader.iter_keys().with_record_info().with_records()`.
    ///
    /// The iterator handles all decoding steps:
    /// 1. Decodes key blocks to get search keys
    /// 2. Resolves record locations via block metadata
    /// 3. Decodes and extracts record data
    ///
    /// # Yield Type
    /// - **MDX files**: `Result<(String, String)>` - key and definition text
    /// - **MDD files**: `Result<(String, Vec<u8>)>` - key and binary resource data
    pub fn iter_records(&self) -> RecordIterator<'_, T> {
        self.iter_keys().with_record_info().with_records()
    }
    
    /// Locates record metadata for a given record ID.
    ///
    /// Uses binary search on record blocks to efficiently find the containing block.
    /// Returns [`RecordInfo`] which describes the record's location within a block.
    ///
    /// # Parameters
    /// * `id` - Starting offset of the record in the virtual decompressed stream
    /// * `next_id` - Starting offset of the next record (defines record size)
    pub fn get_record_info(&self, id: u64, next_id: u64) -> Result<RecordInfo> {
        trace!("Locating record: id={}, next_id={}", id, next_id);
        
        if self.record_blocks.is_empty() {
            return Err(MdictError::InvalidFormat("No record blocks available".to_string()));
        }
        
        // Binary search: find first block where decompressed_offset > id, then take prev.
        let block_index = self.record_blocks
            .partition_point(|block| block.decompressed_offset <= id) - 1;
        let block_meta = self.record_blocks.get(block_index).ok_or_else(|| {
            MdictError::InvalidFormat(format!("Record ID {} is out of bounds", id))
        })?;
        // Validate record is within block bounds
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
    
    /// Reads and decodes a single record from the file.
    ///
    /// This is the main method for random-access record retrieval.
    ///
    /// # Return Type
    /// - **MDX**: `Result<String>` - decoded definition text
    /// - **MDD**: `Result<Vec<u8>>` - binary resource data
    ///
    /// # Performance Note
    /// This method performs file I/O for each call. For sequential access,
    /// prefer using [`iter_records()`](Self::iter_records) which caches blocks.
    pub fn read_record(&self, record_info: &RecordInfo) -> Result<T::Record> {
        trace!(
            "Reading record from block {}, offset {}, size {}",
            record_info.block_index,
            record_info.offset_in_block,
            record_info.size
        );
        let block_bytes = self.read_record_block(record_info.block_index)?;
        self.parse_record(&block_bytes, record_info)
    }

    /// Extracts a record from an already-decompressed block.
    ///
    /// This is a zero-copy operation on in-memory data, used internally by
    /// [`RecordIterator`] to avoid redundant block decompression.
    ///
    /// # Parameters
    /// * `block_bytes` - Decompressed block data
    /// * `info` - Record location within the block
    pub fn parse_record(&self, block_bytes: &[u8], info: &RecordInfo) -> Result<T::Record> {
        content::parse_record::<T>(block_bytes, info, &self.header)
    }
    
    /// Reads and decompresses a record block by index.
    ///
    /// This method is public to enable custom caching strategies. Most users
    /// should use the higher-level iterator APIs instead.
    ///
    /// # Returns
    /// The fully decompressed block data ready for record extraction.
    pub fn read_record_block(&self, block_index: usize) -> Result<Vec<u8>> {
        self.read_block(BlockType::Record, block_index)
    }

    /// Reads and parses all key entries from a key block.
    pub(crate) fn read_key_block_entries(&self, block_index: usize) -> Result<Vec<KeyEntry>> {
        trace!("Reading key block {} entries", block_index);
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

    /// Reads, decrypts, and decompresses a block from the file.
    fn read_and_decode_block(&self, block_meta: BlockMeta) -> Result<Vec<u8>> {
        trace!(
            "Reading block: offset={}, compressed={} bytes, decompressed={} bytes",
            block_meta.file_offset,
            block_meta.compressed_size,
            block_meta.decompressed_size
        );
        
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
