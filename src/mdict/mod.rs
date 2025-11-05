//! Core MDict reader module

pub mod models;
mod header;
mod key_blocks;
mod record_blocks;
mod crypto;
mod compression;
mod decoder;
mod utils;

use std::error::Error;
use std::fs::File;
use models::*;

/// The main reader for MDict dictionary files.
/// 
/// Parses both .mdx (dictionary) and .mdd (data) files.
/// Supports MDict format versions 1.x and 2.x.
pub struct MdictReader {
    pub header: MdictHeader,
    pub key_block_info: KeyBlockInfo,
    pub key_blocks: Vec<KeyBlock>,
    pub record_block_info: RecordBlockInfo,
    pub record_blocks: Vec<RecordBlock>,
    pub all_keys: Vec<KeyEntry>,
    /// Raw decompressed record data (to be split by clients)
    pub all_records_decompressed: Vec<u8>,
}

impl MdictReader {
    /// Read an MDict file from the given path.
    /// 
    /// # Arguments
    /// * `path` - File path to the .mdx or .mdd file
    /// 
    /// # Errors
    /// Returns an error if:
    /// - File cannot be opened
    /// - File format is invalid or corrupted
    /// - Unsupported version (3.0+)
    /// - Checksum verification fails
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        let mut file = File::open(path)?;

        // Parse header (includes master key derivation if encrypted)
        let mdict_header = header::parse(&mut file)?;
        
        // Parse key block metadata
        let key_block_info = key_blocks::parse_info(
            &mut file, 
            &mdict_header
        )?;
        
        // Parse key index to get key block boundaries
        let key_index_decomp = key_blocks::parse_index(
            &mut file, 
            &key_block_info, 
            &mdict_header
        )?;
        
        // Extract key block metadata from index
        let key_blocks_meta = key_blocks::parse_index_metadata(
            &key_index_decomp, 
            &mdict_header, 
            &key_block_info
        )?;
        
        // Parse and decode all key blocks to extract key entries
        let all_key_entries = key_blocks::parse_blocks(
            &mut file, 
            &key_block_info, 
            &key_blocks_meta, 
            &mdict_header
        )?;
        
        // Parse record block metadata
        let record_block_info = record_blocks::parse_info(
            &mut file, 
            &mdict_header, 
            &key_block_info
        )?;
        
        // Parse record block index
        let record_blocks_meta = record_blocks::parse_index(
            &mut file, 
            &record_block_info, 
            &mdict_header
        )?;
        
        // Decompress all record blocks
        let all_records_decompressed = record_blocks::decompress_all(
            &mut file, 
            &record_blocks_meta, 
            &mdict_header
        )?;

        Ok(Self {
            header: mdict_header,
            key_block_info,
            key_blocks: key_blocks_meta,
            record_block_info,
            record_blocks: record_blocks_meta,
            all_keys: all_key_entries,
            all_records_decompressed,
        })
    }
}
