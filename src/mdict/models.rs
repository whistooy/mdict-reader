//! Data structures representing MDict format components

use encoding_rs::Encoding;

/// Encryption flags from MDict header.
/// 
/// Bit 0x01: Record blocks are encrypted
/// Bit 0x02: Key index is encrypted
#[derive(Debug, Default)]
pub struct EncryptionFlags {
    pub encrypt_record_blocks: bool,
    pub encrypt_key_index: bool,
}

/// Parsed MDict file header.
/// 
/// Contains version, encoding, encryption settings, and metadata.
#[derive(Debug)]
pub struct MdictHeader {
    pub version: f32,
    pub encryption_flags: EncryptionFlags,
    pub encoding: &'static Encoding,
    pub number_width: usize,
    pub title: String,
    pub description: Option<String>,
    pub stylesheet: Option<String>,
    /// Master decryption key (derived from passcode if encrypted, None otherwise)
    pub master_key: Option<[u8; 16]>,
}

/// Metadata about the key blocks section.
#[derive(Debug)]
pub struct KeyBlockInfo {
    pub num_key_blocks: u64,
    pub num_entries: u64,
    /// Only present in v2.0+ (decompressed size of key index)
    pub key_index_decomp_len: Option<u64>,
    pub key_index_comp_len: u64,
    pub key_blocks_len: u64,
}

/// Metadata for a single key block.
#[derive(Debug)]
pub struct KeyBlock {
    pub compressed_size: u64,
    pub decompressed_size: u64,
}

/// A dictionary key entry with its record ID.
#[derive(Debug)]
pub struct KeyEntry {
    pub id: u64,
    pub text: String,
}

/// Metadata about the record blocks section.
#[derive(Debug)]
pub struct RecordBlockInfo {
    pub num_record_blocks: u64,
    pub num_entries: u64,
    pub record_index_len: u64,
    pub record_blocks_len: u64,
}

/// Metadata for a single record block.
#[derive(Debug)]
pub struct RecordBlock {
    pub compressed_size: u64,
    pub decompressed_size: u64,
}
