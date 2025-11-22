//! Iterators for sequential access to MDict dictionary entries.
//!
//! This module provides a layered iterator design for efficiently traversing
//! dictionary data with progressive enrichment:
//!
//! 1. [`KeysIterator`] - Base iterator yielding `(key, record_id)` pairs
//! 2. [`RecordInfoIterator`] - Adds record location metadata
//! 3. [`RecordIterator`] - Fully resolved `(key, record)` pairs with caching
//!
//! # Example
//! ```no_run
//! # use mdict_reader::{MdictReader, Mdx};
//! # let reader = MdictReader::<Mdx>::new("dict.mdx", None, None).unwrap();
//! // Iterate through all definitions
//! for result in reader.iter_records() {
//!     let (key, definition) = result.unwrap();
//!     println!("{}: {}", key, definition);
//! }
//! ```

use std::iter::Peekable;
use std::vec::IntoIter;

use super::reader::MdictReader;
use super::types::error::{MdictError, Result};
use super::types::filetypes::FileType;
use super::types::models::{KeyEntry, RecordInfo};

/// Iterator over dictionary keys and their record IDs.
///
/// This is the lightest-weight iterator, only decoding key blocks without
/// touching record data. It yields `Result<(String, u64)>` pairs where the
/// u64 is the record's offset in the virtual decompressed stream.
///
/// Created by [`MdictReader::iter_keys()`](crate::MdictReader::iter_keys).
pub struct KeysIterator<'a, T: FileType> {
    reader: &'a MdictReader<T>,
    key_block_idx: usize,
    current_keys: IntoIter<KeyEntry>,
}

impl<'a, T: FileType> KeysIterator<'a, T> {
    pub(super) fn new(reader: &'a MdictReader<T>) -> Self {
        Self {
            reader,
            key_block_idx: 0,
            current_keys: Vec::new().into_iter(),
        }
    }

    /// Transforms this iterator to include record location metadata.
    ///
    /// The returned [`RecordInfoIterator`] resolves each record ID to a
    /// [`RecordInfo`] structure containing block index and offset information.
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
            // Try to get next key from current block
            if let Some(entry) = self.current_keys.next() {
                return Some(Ok((entry.text, entry.id)));
            }

            // Check if all key blocks have been processed
            let key_blocks = self.reader.key_blocks();
            if self.key_block_idx >= key_blocks.len() {
                return None;
            }

            // Load and decompress next key block
            match self.reader.read_key_block_entries(self.key_block_idx) {
                Ok(entries) => {
                    self.current_keys = entries.into_iter();
                    self.key_block_idx += 1;
                    // Continue loop to yield first entry from new block
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// Iterator over keys with resolved record location metadata.
///
/// This iterator extends [`KeysIterator`] by resolving record IDs to
/// [`RecordInfo`] structures, which describe exactly where each record
/// is located within the file's block structure.
///
/// Created by [`KeysIterator::with_record_info()`].
pub struct RecordInfoIterator<'a, T: FileType> {
    keys_iter: Peekable<KeysIterator<'a, T>>,
    reader: &'a MdictReader<T>,
    record_block_idx: usize,
    cumulative_offset: u64,
}

impl<'a, T: FileType> RecordInfoIterator<'a, T> {
    /// Transforms this iterator to include full record data.
    ///
    /// The returned [`RecordIterator`] decodes and caches record blocks,
    /// yielding complete `(key, record)` pairs.
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

        let record_blocks = self.reader.record_blocks();
        while self.record_block_idx < record_blocks.len() {
            let block = &record_blocks[self.record_block_idx];
            if entry_id < self.cumulative_offset + block.decompressed_size { break; }
            self.cumulative_offset += block.decompressed_size;
            self.record_block_idx += 1;
        }

        if self.record_block_idx >= record_blocks.len() {
            return Some(Err(MdictError::InvalidFormat(
                format!("Record ID {} not found in any block", entry_id)
            )));
        }
        
        let block = &record_blocks[self.record_block_idx];

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

/// Iterator over complete dictionary entries with record data.
///
/// This is the most complete iterator, yielding `Result<(String, T::Record)>`
/// where `T::Record` is `String` for MDX files and `Vec<u8>` for MDD files.
///
/// # Performance
/// This iterator caches decompressed record blocks to avoid redundant
/// decompression when multiple entries reside in the same block.
///
/// Created by [`RecordInfoIterator::with_records()`].
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

        // Check if we need to load a new record block
        if self.cached_block_index != Some(record_info.block_index) {
            match self.reader.read_record_block(record_info.block_index) {
                Ok(bytes) => {
                    self.cached_block_bytes = bytes;
                    self.cached_block_index = Some(record_info.block_index);
                }
                Err(e) => return Some(Err(e)),
            }
        }
        
        // Extract record from cached block data
        match self.reader.parse_record(&self.cached_block_bytes, &record_info) {
            Ok(record) => Some(Ok((key_text, record))),
            Err(e) => Some(Err(e)),
        }
    }
}
