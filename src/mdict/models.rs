//! Data structures representing MDict format components

use encoding_rs::Encoding;
use super::error::{MdictError, Result};

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
    pub version: MdictVersion,
    pub engine_version: String,
    pub encryption_flags: EncryptionFlags,
    pub encoding: &'static Encoding,
    pub title: String,
    pub description: Option<String>,
    pub stylesheet: Option<String>,
    /// Master decryption key (derived from passcode if encrypted, None otherwise)
    pub master_key: Option<[u8; 16]>,
    pub uuid: Option<Vec<u8>>, // UUID for v3.0 key derivation
}

/// Information needed to locate and extract a specific record
#[derive(Debug, Clone)]
pub struct RecordInfo {
    pub block_index: usize,
    pub offset_in_block: u64,
    pub size: u64,
}

/// A dictionary key entry with its record ID.
#[derive(Debug)]
pub struct KeyEntry {
    pub id: u64,
    pub text: String,
}

/// Metadata for a single data block.
#[derive(Debug, Clone, Copy)]
pub struct BlockMeta {
    /// Size of the compressed data for this block (in bytes).
    pub compressed_size: u64,
    /// Size of the decompressed data for this block (in bytes).
    pub decompressed_size: u64,
    /// Starting offset of this block's compressed data in the file.
    pub file_offset: u64,
    /// Starting offset of this block in the virtual concatenated decompressed stream.
    /// (0 for the first block; used for random access via binary search on record_id.)
    pub decompressed_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdictVersion {
    V1,
    V2,
    V3,
}

impl MdictVersion {
    /// Get the width (in bytes) for numbers in this format version.
    pub fn number_width(&self) -> usize {
        match self {
            MdictVersion::V1 => 4,
            MdictVersion::V2 | MdictVersion::V3 => 8,
        }
    }

    /// Get the width (in bytes) for small numbers (text length prefixes) in this format version.
    pub fn small_number_width(&self) -> usize {
        match self {
            MdictVersion::V1 => 1,
            MdictVersion::V2 | MdictVersion::V3 => 2,
        }
    }
}

impl TryFrom<f32> for MdictVersion {
    type Error = MdictError;
    fn try_from(v: f32) -> Result<Self> {
        if v < 2.0 {
            Ok(Self::V1)
        } else if v < 3.0 {
            Ok(Self::V2)
        } else if v < 4.0 {
            Ok(Self::V3)
        } else {
            Err(MdictError::UnsupportedVersion(v))
        }
    }
}

/// Block type markers used in MDict v3.0
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    RecordData = 0x01000000,
    RecordIndex = 0x02000000,
    KeyData = 0x03000000,
    KeyIndex = 0x04000000,
}

impl TryFrom<u32> for BlockType {
    type Error = MdictError;
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x01000000 => Ok(Self::RecordData),
            0x02000000 => Ok(Self::RecordIndex),
            0x03000000 => Ok(Self::KeyData),
            0x04000000 => Ok(Self::KeyIndex),
            _ => Err(MdictError::InvalidFormat(
                format!("Unknown v3 block type: {:#010x}", value)
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None,
    Lzo,
    Zlib,
}

impl TryFrom<u8> for CompressionType {
    type Error = MdictError;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Lzo),
            2 => Ok(Self::Zlib),
            _ => Err(MdictError::InvalidFormat(format!("Unknown compression type: {}", value))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    None,
    Fast,
    Salsa20,
}

impl TryFrom<u8> for EncryptionType {
    type Error = MdictError;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Fast),
            2 => Ok(Self::Salsa20),
            _ => Err(MdictError::InvalidFormat(format!("Unknown encryption type: {}", value))),
        }
    }
}
