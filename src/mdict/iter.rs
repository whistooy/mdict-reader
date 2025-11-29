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

use super::layout::blocks;
use super::reader::MdictReader;
use super::types::error::{MdictError, Result};
use super::types::filetypes::FileType;
use super::types::models::RecordData;

/// Iterator over dictionary keys and their record IDs.
///
/// Lightweight iterator that only decodes key blocks without touching record data.
/// It yields `Result<(String, u64)>` pairs where the u64 is the record's offset in
/// the virtual decompressed stream.
///
/// Created by [`MdictReader::iter_keys()`](crate::MdictReader::iter_keys).
pub struct KeysIterator<'a, T: FileType> {
    reader: &'a MdictReader<T>,
    cached_block_index: Option<usize>,
    // Decompressed key block bytes and current read position within the block
    cached_block_bytes: Vec<u8>,
    cached_block_pos: usize,
}

impl<'a, T: FileType> KeysIterator<'a, T> {
    pub(super) fn new(reader: &'a MdictReader<T>) -> Self {
        Self {
            reader,
            cached_block_index: None,
            cached_block_bytes: Vec::new(),
            cached_block_pos: 0,
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
            cached_block_index: None,
            cached_block_bytes: Vec::new(),
        }
    }

    /// Ensure there is a key block ready for reading the next item.
    ///
    /// If the current block is exhausted, this advances to the next block.
    /// Returns `Ok(true)` if a block is available, or `Ok(false)` if iteration
    /// is complete.
    fn ensure_block(&mut self) -> Result<bool> {
        // If current block still has unread bytes, keep using it.
        if self.cached_block_pos < self.cached_block_bytes.len() {
            return Ok(true);
        }

        // Otherwise, move to the next block.
        let next_index = self.cached_block_index.map(|i| i + 1).unwrap_or(0);
        let key_blocks = self.reader.key_blocks();

        if next_index >= key_blocks.len() {
            // No more blocks → iteration finished.
            return Ok(false);
        }

        self.load_block(next_index)?;
        Ok(true)
    }

    /// Load and decode the key block at `block_index` into the cache.
    fn load_block(&mut self, block_index: usize) -> Result<()> {
        let key_blocks = self.reader.key_blocks();
        let block = key_blocks.get(block_index).ok_or_else(|| {
            MdictError::InvalidFormat(format!("Key block index {} out of range", block_index))
        })?;

        self.reader
            .read_and_decode_block_into(&mut self.cached_block_bytes, *block)?;
        self.cached_block_pos = 0;
        self.cached_block_index = Some(block_index);
        Ok(())
    }

    /// Read the next `(key, id)` pair from the current key block.
    fn read_item(&mut self) -> Result<(String, u64)> {
        // Work on a subslice starting at the current position
        let mut slice = &self.cached_block_bytes[self.cached_block_pos..];
        let before = slice.len();

        let result =
            blocks::read_next_key_entry(&mut slice, self.reader.version(), self.reader.encoding());

        let after = slice.len();
        self.cached_block_pos += before - after;

        result
    }
}

impl<'a, T: FileType> Iterator for KeysIterator<'a, T> {
    type Item = Result<(String, u64)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.ensure_block() {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => return Some(Err(e)),
        }

        Some(self.read_item())
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
    cached_block_index: Option<usize>,
    cached_block_bytes: Vec<u8>,
}

impl<'a, T: FileType> RecordIterator<'a, T> {
    /// Ensure the record block containing `entry_id` is loaded.
    ///
    /// Amortized O(1) by reusing `cached_block_index` and only advancing forward
    /// as `entry_id` increases.
    fn ensure_block(&mut self, entry_id: u64) -> Result<()> {
        let record_blocks = self.reader.record_blocks();

        // Start from the last used block index (or 0) and move forward only.
        let mut block_idx = self.cached_block_index.unwrap_or(0);

        while block_idx < record_blocks.len() {
            let block = &record_blocks[block_idx];
            if entry_id < block.decompressed_offset + block.decompressed_size {
                break;
            }
            block_idx += 1;
        }

        if block_idx >= record_blocks.len() {
            return Err(MdictError::InvalidFormat(format!(
                "Record ID {} not found in any block",
                entry_id
            )));
        }

        self.load_block(block_idx)
    }

    /// Load and decode the record block at `block_index` into the cache.
    fn load_block(&mut self, block_index: usize) -> Result<()> {
        if self.cached_block_index == Some(block_index) {
            return Ok(());
        }

        let record_blocks = self.reader.record_blocks();
        let block = record_blocks.get(block_index).ok_or_else(|| {
            MdictError::InvalidFormat(format!("Record block index {} out of range", block_index))
        })?;

        self.reader
            .read_and_decode_block_into(&mut self.cached_block_bytes, *block)?;
        self.cached_block_index = Some(block_index);
        Ok(())
    }

    /// Read the record for `(key_text, entry_id)` from the currently loaded block.
    fn read_item(
        &mut self,
        key_text: String,
        entry_id: u64,
    ) -> Result<(String, RecordData<T::Record>)> {
        let block_idx = self.cached_block_index.ok_or_else(|| {
            MdictError::InvalidFormat("No record block loaded for current entry".to_string())
        })?;

        let record_blocks = self.reader.record_blocks();
        let block = record_blocks.get(block_idx).ok_or_else(|| {
            MdictError::InvalidFormat(format!("Record block index {} out of range", block_idx))
        })?;

        // Determine end offset using the next key's entry_id, or block end.
        let next_id = match self.keys_iter.peek() {
            Some(Ok((_, next_id))) => *next_id,
            _ => block.decompressed_offset + block.decompressed_size,
        };

        let start = entry_id - block.decompressed_offset;
        let end = next_id - block.decompressed_offset;

        let record_data = self
            .reader
            .parse_record(&self.cached_block_bytes, start, end)?;
        Ok((key_text, record_data))
    }
}

impl<'a, T: FileType> Iterator for RecordIterator<'a, T> {
    type Item = Result<(String, RecordData<T::Record>)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Get next key-id pair
        let (key_text, entry_id) = match self.keys_iter.next()? {
            Ok(pair) => pair,
            Err(e) => return Some(Err(e)),
        };

        // Ensure the correct record block is loaded for this entry
        match self.ensure_block(entry_id) {
            Ok(()) => {}
            Err(e) => return Some(Err(e)),
        }

        // Read the record from the current block
        Some(self.read_item(key_text, entry_id))
    }
}
