//! Core MDict reader module

pub mod models;
pub mod error;
pub mod filetypes;
mod header;
mod blocks;
mod key_blocks;
mod record_blocks;
mod crypto;
mod compression;
mod decoder;
mod utils;

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::iter::Peekable;
use std::vec::IntoIter;
use log::info;
use models::*;
use filetypes::FileType;
pub use error::{MdictError, Result};

/// The main reader for MDict dictionary files.
/// 
/// Parses both .mdx (dictionary) and .mdd (data) files.
/// Supports MDict format versions 1.x, 2.x, and 3.x.
#[derive(Debug)]
pub struct MdictReader<T: FileType> {
    file_path: PathBuf,
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
        let mut mdict_header = header::parse(&mut file, passcode)?;

        // V3.0 forces UTF-8
        if mdict_header.version == MdictVersion::V3 {
            info!("V3.0 detected: forcing UTF-8 encoding");
            mdict_header.encoding = encoding_rs::UTF_8;
        } else {
            // Apply encoding override for v1/v2
            let final_encoding = T::ENCODING_OVERRIDE
                .or_else(|| user_encoding.map(utils::parse_encoding))
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
        match mdict_header.version {
            MdictVersion::V3 => {
                Self::new_v3(path, &mut file, mdict_header)
            }
            MdictVersion::V1 | MdictVersion::V2 => {
                Self::new_v1v2(path, &mut file, mdict_header)
            }
        }
    }

    /// Constructor for v1.x and v2.x files (existing logic)
    fn new_v1v2(
        path: &Path,
        file: &mut File,
        mdict_header: MdictHeader,
    ) -> Result<Self> {
        let (key_blocks, num_entries) = key_blocks::parse_v1v2(file, &mdict_header)?;
        
        // Skip to record section
        let total_key_blocks_size: u64 = key_blocks.iter().map(|b| b.compressed_size).sum();
        file.seek(SeekFrom::Current(total_key_blocks_size as i64))?;
        
        let record_blocks = record_blocks::parse_v1v2(file, &mdict_header)?;

        let total_record_decomp_size: u64 = record_blocks.iter().map(|b| b.decompressed_size).sum();

        info!("MDict file opened: {} key blocks, {} record blocks", 
              key_blocks.len(), record_blocks.len());

        Ok(Self {
            file_path: path.to_path_buf(),
            header: mdict_header,
            key_blocks,
            record_blocks,
            total_record_decomp_size,
            num_entries,
            _file_type: PhantomData,
        })
    }

    /// Constructor for v3.0 files
    fn new_v3(
        path: &Path,
        file: &mut File,
        mdict_header: MdictHeader,
    ) -> Result<Self> {
        info!("Parsing v3.0 MDict file");
        
        let key_block_offset = file.stream_position()?;
        
        // Scan for block offsets
        let (key_data_offset, key_index_offset, record_data_offset, record_index_offset) =
            header::scan_v3_block_offsets(file, key_block_offset)?;
        
        let (num_entries, key_index) = key_blocks::parse_v3_key_index(
            file,
            &mdict_header,
            key_index_offset,
        )?;
        
        let record_index = record_blocks::parse_v3_record_index(
            file,
            &mdict_header,
            record_index_offset,
        )?;
        let key_blocks = key_blocks::parse_v3(
            file,
            key_data_offset,
            &key_index,
        )?;
        
        let record_blocks = record_blocks::parse_v3(
            file,
            record_data_offset,
            &record_index,
        )?;

        let total_record_decomp_size: u64 = record_blocks.iter().map(|b| b.decompressed_size).sum();

        info!("V3.0 file opened: {} key blocks, {} record blocks", 
              key_blocks.len(), record_blocks.len());

        Ok(Self {
            file_path: path.to_path_buf(),
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
        KeysIterator {
            reader: self,
            key_block_idx: 0,
            current_keys: Vec::new().into_iter(),
        }
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
        let start = info.offset_in_block as usize;
        let end = start + info.size as usize;
        if end > block_bytes.len() {
            return Err(MdictError::InvalidFormat(format!(
                "Record location [{}..{}] is out of bounds for block of size {}",
                start, end, block_bytes.len()
            )));
        }
        
        // Extract the raw bytes for this specific record
        let record_slice = &block_bytes[start..end];
        
        // Delegate to the file-type specific processing logic
        T::process_record(record_slice, &self.header)
    }
    
    /// Reads and decodes a full record block from the file given its block index.
    ///
    /// This method is kept public for applications that wish to implement their
    /// own record caching strategies on top of the raw blocks.
    pub fn read_record_block(&self, block_index: usize) -> Result<Vec<u8>> {
        let block_meta = self.record_blocks
            .get(block_index)
            .ok_or_else(|| MdictError::InvalidFormat(format!("Invalid block index: {}", block_index)))?;
        let mut file = File::open(&self.file_path)?;
        blocks::decode_block(&mut file, block_meta, &self.header)
    }
}

// --- ITERATORS ---

/// An iterator over `Result<(key_text, record_id)>` pairs.
///
/// Created by [`MdictReader::iter_keys()`].
pub struct KeysIterator<'a, T: FileType> {
    reader: &'a MdictReader<T>,
    key_block_idx: usize,
    current_keys: IntoIter<KeyEntry>,
}

impl<'a, T: FileType> KeysIterator<'a, T> {
    /// Consumes the keys iterator and returns a new iterator that yields
    /// `Result<(key_text, RecordInfo)>` pairs.
    pub fn with_record_info(self) -> RecordInfoIterator<'a, T> {
        RecordInfoIterator {
            reader: self.reader, 
            keys_iter: self.peekable(),
            record_block_idx: 0,
            cumulative_offset: 0,
        }
    }
}

impl<'a, T: FileType> Iterator for KeysIterator<'a, T> {
    type Item = Result<(String, u64)>;
    
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If there are keys in the current block, yield one
            if let Some(entry) = self.current_keys.next() {
                return Some(Ok((entry.text, entry.id)));
            }

            // If we've processed all blocks, we're done
            if self.key_block_idx >= self.reader.key_blocks.len() {
                return None;
            }

            // Otherwise, load the next block of keys
            let mut file = match File::open(&self.reader.file_path) {
                Ok(f) => f,
                Err(e) => return Some(Err(e.into())),
            };
            let block_meta = &self.reader.key_blocks[self.key_block_idx];
            match key_blocks::decode_and_parse_block(&mut file, block_meta, &self.reader.header) {
                Ok(entries) => {
                    self.current_keys = entries.into_iter();
                    self.key_block_idx += 1;
                    // Loop again to get the first entry from the new block
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// An iterator over `Result<(key_text, RecordInfo)>` pairs.
///
/// Created by calling `.with_record_info()` on a [`KeysIterator`].
pub struct RecordInfoIterator<'a, T: FileType> {
    keys_iter: Peekable<KeysIterator<'a, T>>,
    reader: &'a MdictReader<T>,
    record_block_idx: usize,
    cumulative_offset: u64,
}

impl<'a, T: FileType> RecordInfoIterator<'a, T> {
    /// Consumes this iterator and returns a new one that yields the full
    /// `Result<(key_text, definition_string)>` pair for each entry.
    pub fn with_records(self) -> RecordIterator<'a, T> {
        RecordIterator {
            reader: self.reader,
            record_info_iter: self,
            cached_block_index: None,
            cached_block_bytes: Vec::new(),
        }
    }
}

impl<'a, T: FileType> Iterator for RecordInfoIterator<'a, T> {
    type Item = Result<(String, RecordInfo)>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key_text, entry_id) = match self.keys_iter.next()? {
            Ok(pair) => pair,
            Err(e) => return Some(Err(e)),
        };

        while self.record_block_idx < self.reader.record_blocks.len() {
            let block = &self.reader.record_blocks[self.record_block_idx];
            if entry_id < self.cumulative_offset + block.decompressed_size { break; }
            self.cumulative_offset += block.decompressed_size;
            self.record_block_idx += 1;
        }

        if self.record_block_idx >= self.reader.record_blocks.len() {
            return Some(Err(MdictError::InvalidFormat(
                format!("Record ID {} not found in any block", entry_id)
            )));
        }
        
        let block = &self.reader.record_blocks[self.record_block_idx];

        let next_id = match self.keys_iter.peek() {
            Some(Ok((_, next_id))) => *next_id,
            _ => self.cumulative_offset + block.decompressed_size,
        };
        
        let record_info = RecordInfo {
            block_index: self.record_block_idx,
            offset_in_block: entry_id - self.cumulative_offset,
            size: next_id - entry_id,
        };
        
        Some(Ok((key_text, record_info)))
    }
}

/// An iterator over `Result<(key, definition)>` pairs.
///
/// This iterator is stateful and performs internal caching to efficiently
/// read the dictionary sequentially. Created by calling `.with_records()`
/// on a [`RecordInfoIterator`].
pub struct RecordIterator<'a, T: FileType> {
    record_info_iter: RecordInfoIterator<'a, T>,
    reader: &'a MdictReader<T>,
    cached_block_index: Option<usize>,
    cached_block_bytes: Vec<u8>,
}

impl<'a, T: FileType> Iterator for RecordIterator<'a, T> {
    type Item = Result<(String, T::Record)>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key_text, record_info) = match self.record_info_iter.next()? {
            Ok(pair) => pair,
            Err(e) => return Some(Err(e)),
        };

        // Check if we need to decode a new record block
        if self.cached_block_index != Some(record_info.block_index) {
            match self.reader.read_record_block(record_info.block_index) {
                Ok(bytes) => {
                    self.cached_block_bytes = bytes;
                    self.cached_block_index = Some(record_info.block_index);
                }
                Err(e) => return Some(Err(e)),
            }
        }
        
        // Parse the record from the cached block
        match self.reader.parse_record(&self.cached_block_bytes, &record_info) {
            Ok(record) => Some(Ok((key_text, record))),
            Err(e) => Some(Err(e)),
        }
    }
}
