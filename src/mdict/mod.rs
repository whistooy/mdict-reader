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
}

impl MdictReader {
    /// Read an MDict file from the given path.
    /// 
    /// # Arguments
    /// * `path` - File path to the .mdx or .mdd file
    /// * `passcode` - Optional (regcode_hex, user_email) tuple for encrypted files
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

        info!("MDict file opened: {} entries, {} key blocks, {} record blocks", 
              key_block_info.num_entries, key_blocks.len(), record_blocks.len());

        Ok(Self {
            file_path: path.to_path_buf(),
            header: mdict_header,
            key_block_info,
            record_block_info,
            key_blocks,
            record_blocks,
        })
    }
    
    /// Returns an iterator over all (key, location) pairs
    /// 
    /// Memory efficient: decompresses one key block at a time.
    /// The returned `RecordInfo` can be stored in a database for later lookup.
    pub fn iter_entries(&self) -> EntryIterator<'_> {
        EntryIterator::new(self)
    }
    
    /// Extract a specific record using its location
    /// 
    /// Decompresses the containing block and extracts the record.
    /// Consider caching decompressed blocks to avoid repeated decompression.
    pub fn read_record(&self, location: &RecordInfo) -> Result<Vec<u8>> {
        let mut file = File::open(&self.file_path)?;
        
        let block_meta = BlockMeta {
            compressed_size: location.block_compressed_size,
            decompressed_size: location.block_decompressed_size,
            file_offset: location.block_file_offset,
        };
        
        let decompressed = blocks::decode_block(&mut file, &block_meta, &self.header)?;
        
        let start = location.offset_in_block as usize;
        let end = start + location.size as usize;
        
        if end > decompressed.len() {
            return Err(MdictError::InvalidFormat(
                format!("Record location out of bounds: {} > {}", end, decompressed.len())
            ));
        }
        
        Ok(decompressed[start..end].to_vec())
    }
    
    /// Decode record bytes to string using the dictionary's encoding
    pub fn decode_record_text(&self, record_bytes: &[u8]) -> String {
        let (text, _, _) = self.header.encoding.decode(record_bytes);
        text.into_owned()
    }
    
    /// Convenience method: get all keys
    /// 
    /// Decompresses all key blocks. Use for testing or small dictionaries.
    pub fn keys(&self) -> Result<Vec<String>> {
        self.iter_entries()
            .map(|result| result.map(|(key, _)| key))
            .collect()
    }
    
    /// Convenience method: get all definitions
    /// 
    /// **Warning: Memory intensive!** Only use for testing.
    pub fn definitions(&self) -> Result<Vec<String>> {
        self.iter_entries()
            .map(|result| {
                let (_, location) = result?;
                let bytes = self.read_record(&location)?;
                Ok(self.decode_record_text(&bytes))
            })
            .collect()
    }
}

/// Iterator over (key, RecordInfo) pairs
pub struct EntryIterator<'a> {
    reader: &'a MdictReader,
    key_block_idx: usize,
    current_keys: Peekable<IntoIter<KeyEntry>>,
    record_block_idx: usize,
    cumulative_offset: u64,
}

impl<'a> EntryIterator<'a> {
    fn new(reader: &'a MdictReader) -> Self {
        Self {
            reader,
            key_block_idx: 0,
            current_keys: Vec::new().into_iter().peekable(),
            record_block_idx: 0,
            cumulative_offset: 0,
        }
    }
}

impl<'a> Iterator for EntryIterator<'a> {
    type Item = Result<(String, RecordInfo)>;
    
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get next key from current block
            if let Some(entry) = self.current_keys.next() {
                // Find which record block contains this entry
                while self.record_block_idx < self.reader.record_blocks.len() {
                    let block = &self.reader.record_blocks[self.record_block_idx];
                    let block_end = self.cumulative_offset + block.decompressed_size;
                    
                    if entry.id < block_end {
                        break; // Found the right block
                    }

                    // Move to next block
                    self.cumulative_offset += block.decompressed_size;
                    self.record_block_idx += 1;
                }
                
                if self.record_block_idx >= self.reader.record_blocks.len() {
                    return Some(Err(MdictError::InvalidFormat(
                        format!("Record ID {} not found in any block", entry.id)
                    )));
                }
                
                let block = &self.reader.record_blocks[self.record_block_idx];

                // Calculate record size by peeking at next entry
                let next_id = self.current_keys.peek()
                    .map(|next_entry| next_entry.id)
                    .unwrap_or(self.cumulative_offset + block.decompressed_size);
                
                let record_size = next_id - entry.id;
                
                let location = RecordInfo {
                    block_file_offset: block.file_offset,
                    block_compressed_size: block.compressed_size,
                    block_decompressed_size: block.decompressed_size,
                    offset_in_block: entry.id - self.cumulative_offset,
                    size: record_size,
                };
                
                return Some(Ok((entry.text, location)));
            }
            
            // Current block exhausted, load next key block
            if self.key_block_idx >= self.reader.key_blocks.len() {
                return None; // All done
            }
            
            let mut file = match File::open(&self.reader.file_path) {
                Ok(f) => f,
                Err(e) => return Some(Err(e.into())),
            };
            
            let block_meta = &self.reader.key_blocks[self.key_block_idx];
            match key_blocks::decode_and_parse_block(&mut file, block_meta, &self.reader.header) {
                Ok(entries) => {
                    self.current_keys = entries.into_iter().peekable();
                    self.key_block_idx += 1;
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}
