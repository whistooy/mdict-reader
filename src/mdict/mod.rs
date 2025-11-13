//! Core MDict reader module

pub mod models;
pub mod error;
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
use std::path::{Path, PathBuf};
use std::iter::Peekable;
use std::vec::IntoIter;
use log::info;
use models::*;
pub use error::{MdictError, Result};

/// The main reader for MDict dictionary files.
/// 
/// Parses both .mdx (dictionary) and .mdd (data) files.
/// Supports MDict format versions 1.x and 2.x.
pub struct MdictReader {
    file_path: PathBuf,
    pub header: MdictHeader,
    pub key_block_info: KeyBlockInfo,
    pub record_block_info: RecordBlockInfo,
    
    key_blocks: Vec<BlockMeta>,
    record_blocks: Vec<BlockMeta>,
    /// Total size of the virtual decompressed record stream (sum of all record block decompressed sizes).
    /// Used for exact sizing of the last record.
    pub total_record_decomp_size: u64,
}

impl MdictReader {
    /// Read an MDict file from the given path.
    /// 
    /// # Arguments
    /// * `path` - File path to the .mdx or .mdd file
    /// * `passcode` - Optional (`regcode_hex`, `user_email`) tuple for encrypted files
    /// 
    /// # Errors
    /// Returns an error if:
    /// - File cannot be opened
    /// - File format is invalid or corrupted
    /// - Unsupported version (3.0+)
    /// - Checksum verification fails
    pub fn new(path: impl AsRef<Path>, passcode: Option<(&str, &str)>) -> Result<Self> {
        let path = path.as_ref();
        info!("Opening MDict file: {}", path.display());
        let mut file = File::open(path)?;

        // Parse header (includes master key derivation if encrypted)
        let mdict_header = header::parse(&mut file, passcode)?;
    
        // Parse key block metadata
        let key_block_info = key_blocks::parse_info(
            &mut file,
            &mdict_header
        )?;
    
        // Parse key block index
        let key_blocks = key_blocks::parse_index(
            &mut file,
            &key_block_info,
            &mdict_header
        )?;
        
        // Skip to record section
        let total_key_blocks_size: u64 = key_blocks.iter().map(|b| b.compressed_size).sum();
        file.seek(SeekFrom::Current(total_key_blocks_size as i64))?;
    
        // Parse record block metadata
        let record_block_info = record_blocks::parse_info(
            &mut file,
            &mdict_header,
            &key_block_info
        )?;
    
        // Parse record block index
        let record_blocks = record_blocks::parse_index(
            &mut file,
            &record_block_info,
            &mdict_header
        )?;

        // Precompute total decompressed size for exact last-record sizing
        let total_record_decomp_size: u64 = record_blocks.iter().map(|b| b.decompressed_size).sum();

        info!("MDict file opened: {} entries, {} key blocks, {} record blocks", 
              key_block_info.num_entries, key_blocks.len(), record_blocks.len());

        Ok(Self {
            file_path: path.to_path_buf(),
            header: mdict_header,
            key_block_info,
            record_block_info,
            key_blocks,
            record_blocks,
            total_record_decomp_size,
        })
    }
    
    /// Returns the base iterator over all `(key_text, record_id)` pairs.
    ///
    /// This is the most primitive and fastest way to scan all keys. It only
    /// decodes key blocks and does not touch record blocks.
    ///
    /// Chain this with `.with_record_info()` and `.with_definitions()`
    /// for more complete data.
    pub fn iter_keys(&self) -> KeysIterator<'_> {
        KeysIterator {
            reader: self,
            key_block_idx: 0,
            current_keys: Vec::new().into_iter(),
        }
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
    
    /// Reads and returns the decoded definition string for a single record.
    ///
    /// This method is a convenience for random lookups. For iterating over many
    /// records sequentially, prefer `iter_keys().with_record_info().with_definitions()`
    /// for significantly better performance due to internal caching.
    pub fn read_record_text(&self, record_info: &RecordInfo) -> Result<String> {
        let block_bytes = self.read_record_block(record_info.block_index)?;
        self.parse_record_text(&block_bytes, record_info)
    }
    
    /// Decode record bytes to string using the dictionary's encoding
    pub fn decode_record_text(&self, record_bytes: &[u8]) -> String {
        let (text, _, _) = self.header.encoding.decode(record_bytes);
        text.into_owned()
    }

    /// Reads and decodes a full record block from the file given its block index.
    pub fn read_record_block(&self, block_index: usize) -> Result<Vec<u8>> {
        let block_meta = self.record_blocks
            .get(block_index)
            .ok_or_else(|| MdictError::InvalidFormat(format!("Invalid block index: {}", block_index)))?;
        let mut file = File::open(&self.file_path)?;
        blocks::decode_block(&mut file, block_meta, &self.header)
    }

    /// Parses a record from a decoded block and decodes it to a String.
    pub fn parse_record_text(&self, block_bytes: &[u8], info: &RecordInfo) -> Result<String> {
        let start = info.offset_in_block as usize;
        let end = start + info.size as usize;
        if end > block_bytes.len() {
            return Err(MdictError::InvalidFormat(format!(
                "Record location [{}..{}] out of bounds for block of size {}",
                start, end, block_bytes.len()
            )));
        }
        let record_slice = &block_bytes[start..end];
        Ok(self.decode_record_text(record_slice))
    }
}

// --- ITERATORS ---

/// An iterator over `(key_text, record_id)` pairs.
///
/// Created by [`MdictReader::iter_keys()`].
pub struct KeysIterator<'a> {
    reader: &'a MdictReader,
    key_block_idx: usize,
    current_keys: IntoIter<KeyEntry>,
}

impl<'a> KeysIterator<'a> {
    /// Consumes the keys iterator and returns a new iterator that yields
    /// `(key_text, RecordInfo)` pairs.
    pub fn with_record_info(self) -> RecordInfoIterator<'a> {
        RecordInfoIterator {
            reader: self.reader, 
            keys_iter: self.peekable(),
            record_block_idx: 0,
            cumulative_offset: 0,
        }
    }
}

impl<'a> Iterator for KeysIterator<'a> {
    type Item = Result<(String, u64)>;
    
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(entry) = self.current_keys.next() {
                return Some(Ok((entry.text, entry.id)));
            }
            if self.key_block_idx >= self.reader.key_blocks.len() {
                return None;
            }
            let mut file: File = match File::open(&self.reader.file_path) {
                Ok(f) => f,
                Err(e) => return Some(Err(e.into())),
            };
            let block_meta = &self.reader.key_blocks[self.key_block_idx];
            match key_blocks::decode_and_parse_block(&mut file, block_meta, &self.reader.header) {
                Ok(entries) => {
                    self.current_keys = entries.into_iter();
                    self.key_block_idx += 1;
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// An iterator over `(key_text, RecordInfo)` pairs.
///
/// Created by calling `.with_record_info()` on a [`KeysIterator`].
pub struct RecordInfoIterator<'a> {
    keys_iter: Peekable<KeysIterator<'a>>,
    reader: &'a MdictReader,
    record_block_idx: usize,
    cumulative_offset: u64,
}

impl<'a> RecordInfoIterator<'a> {
    /// Consumes this iterator and returns a new one that yields the full
    /// `(key_text, definition_string)` pair for each entry.
    pub fn with_definitions(self) -> DefinitionsIterator<'a> {
        DefinitionsIterator {
            reader: self.reader,
            record_info_iter: self,
            cached_block_index: None,
            cached_block_bytes: Vec::new(),
        }
    }
}

impl<'a> Iterator for RecordInfoIterator<'a> {
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

/// An iterator over `(key, definition)` string pairs.
///
/// This iterator is stateful and performs internal caching to efficiently
/// read the dictionary sequentially. Created by calling `.with_definitions()`
/// on a [`RecordInfoIterator`].
pub struct DefinitionsIterator<'a> {
    record_info_iter: RecordInfoIterator<'a>,
    reader: &'a MdictReader,
    cached_block_index: Option<usize>,
    cached_block_bytes: Vec<u8>,
}

impl<'a> Iterator for DefinitionsIterator<'a> {
    type Item = Result<(String, String)>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key_text, record_info) = match self.record_info_iter.next()? {
            Ok(pair) => pair,
            Err(e) => return Some(Err(e)),
        };
        // Check if we need to decode a new record block (compare indices)
        if self.cached_block_index != Some(record_info.block_index) {
            // Use the new public method for consistency (could be cached externally too)
            match self.reader.read_record_block(record_info.block_index) {
                Ok(bytes) => {
                    self.cached_block_bytes = bytes;
                    self.cached_block_index = Some(record_info.block_index);
                }
                Err(e) => return Some(Err(e)),
            }
        }
        
        match self.reader.parse_record_text(&self.cached_block_bytes, &record_info) {
            Ok(definition) => Some(Ok((key_text, definition))),
            Err(e) => Some(Err(e)),
        }
    }
}
