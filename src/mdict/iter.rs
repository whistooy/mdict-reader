//! Iterators for sequential access to MDict dictionary entries.
//!
//! This module provides a layered iterator design for efficiently traversing
//! dictionary data with progressive enrichment:
//!
//! 1. [`KeysIterator`] - Base iterator yielding `(key, record_id)` pairs
//! 2. [`RecordIterator`] - Fully resolved `(key, RecordData)` pairs with redirect detection
//!
//! # Example
//! ```no_run
//! # use mdict_reader::{MdictReader, Mdx, RecordData};
//! # let reader = MdictReader::<Mdx>::new("dict.mdx", None, None).unwrap();
//! // Iterate through all definitions
//! for result in reader.iter_records() {
//!     let (key, record_data) = result.unwrap();
//!     match record_data {
//!         RecordData::Content(text) => println!("{}: {}", key, text),
//!         RecordData::Redirect(target) => println!("{} → {}", key, target),
//!     }
//! }
//! ```

use std::iter::Peekable;
use std::vec::IntoIter;

use super::reader::MdictReader;
use super::types::error::{MdictError, Result};
use super::types::filetypes::FileType;
use super::types::models::{KeyEntry, RecordData};

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

    /// Transforms this iterator to include full record data with redirect detection.
    ///
    /// The returned [`RecordIterator`] decodes and caches record blocks,
    /// yielding complete `(key, RecordData)` pairs where RecordData can be
    /// either Content or Redirect.
    pub fn with_records(self) -> RecordIterator<'a, T> {
        RecordIterator {
            reader: self.reader,
            keys_iter: self.peekable(),
            record_block_idx: 0,
            cumulative_offset: 0,
            cached_block_index: None,
            cached_block_bytes: Vec::new(),
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
            let block = &key_blocks[self.key_block_idx];

            // Load and decompress next key block
            match self.reader.read_key_block_entries(*block) {
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

/// Iterator over complete dictionary entries with record data and redirect detection.
///
/// Yields `Result<(String, RecordData<T::Record>)>` where `RecordData` can be:
/// - `RecordData::Content(data)` - Actual record content
/// - `RecordData::Redirect(target)` - Internal redirect to another key
///
/// Users are responsible for resolving redirects if desired.
///
/// # Performance
/// This iterator caches decompressed record blocks to avoid redundant
/// decompression when multiple entries reside in the same block.
///
/// Created by [`KeysIterator::with_records()`].
pub struct RecordIterator<'a, T: FileType> {
    keys_iter: Peekable<KeysIterator<'a, T>>,
    reader: &'a MdictReader<T>,
    record_block_idx: usize,
    cumulative_offset: u64,
    cached_block_index: Option<usize>,
    cached_block_bytes: Vec<u8>,
}

impl<'a, T: FileType> Iterator for RecordIterator<'a, T> {
    type Item = Result<(String, RecordData<T::Record>)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Get next key-id pair
        let (key_text, entry_id) = match self.keys_iter.next()? {
            Ok(pair) => pair,
            Err(e) => return Some(Err(e)),
        };

        // Find the block containing this record
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

        // Calculate record boundaries
        let next_id = match self.keys_iter.peek() {
            Some(Ok((_, next_id))) => *next_id,
            _ => self.cumulative_offset + block.decompressed_size,
        };
        
        let block_index = self.record_block_idx;
        let start = entry_id - self.cumulative_offset;
        let end = next_id - self.cumulative_offset;

        // Load block if needed
        if self.cached_block_index != Some(block_index) {
            match self.reader.read_and_decode_block(*block) {
                Ok(bytes) => {
                    self.cached_block_bytes = bytes;
                    self.cached_block_index = Some(block_index);
                }
                Err(e) => return Some(Err(e)),
            }
        }
        
        // Extract record from cached block data
        match self.reader.parse_record(&self.cached_block_bytes, start, end) {
            Ok(record_data) => Some(Ok((key_text, record_data))),
            Err(e) => Some(Err(e)),
        }
    }
}
