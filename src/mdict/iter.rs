use std::iter::Peekable;
use std::vec::IntoIter;

use super::reader::MdictReader;
use super::types::error::{MdictError, Result};
use super::types::filetypes::FileType;
use super::types::models::{KeyEntry, RecordInfo};

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
    pub(super) fn new(reader: &'a MdictReader<T>) -> Self {
        Self {
            reader,
            key_block_idx: 0,
            current_keys: Vec::new().into_iter(),
        }
    }

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
            let key_blocks = self.reader.key_blocks();
            if self.key_block_idx >= key_blocks.len() {
                return None;
            }

            // Otherwise, load the next block of keys
            match self.reader.read_key_block_entries(self.key_block_idx) {
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
