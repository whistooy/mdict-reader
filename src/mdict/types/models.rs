//! Core data structures for MDict format components.
//!
//! This module defines the fundamental types used throughout the library:
//! - File metadata and headers
//! - Block and entry information
//! - Version and type enumerations

use std::collections::HashMap;
use encoding_rs::Encoding;
use super::error::{MdictError, Result};

/// Type alias for the text encoding used in MDict files.
///
/// This is a static reference to an encoding from the `encoding_rs` crate.
pub type MdictEncoding = &'static Encoding;

/// Encryption flags parsed from the MDict header.
///
/// The MDict format uses a bitmask to indicate which parts of the file are encrypted:
/// - Bit 0x01: Record data blocks are encrypted
/// - Bit 0x02: Key index blocks are encrypted
#[derive(Debug, Default, Copy, Clone)]
pub struct EncryptionFlags {
    pub encrypt_record_blocks: bool,
    pub encrypt_key_index: bool,
}

/// Stylesheet tag mapping for text formatting.
///
/// Maps style identifiers (1-255) to opening and closing HTML/CSS tags.
/// Format in header: line triplets of (style_id, begin_tag, end_tag).
pub type StyleSheet = HashMap<u8, (String, String)>;

/// The result of processing a dictionary record.
///
/// Records can either contain actual content or redirect to another entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData<T> {
    /// Actual record content
    Content(T),
    /// Internal redirect to another key
    Redirect(String),
}

/// Display-only metadata from MDict file header.
///
/// This structure contains user-visible information that doesn't affect
/// parsing operations. Separated from parsing-critical fields for better
/// performance and clearer API.
#[derive(Debug)]
pub struct MdictMetadata {
    pub title: String,
    pub engine_version: String,
    pub description: Option<String>,
    pub stylesheet_raw: Option<String>,
    pub uuid: Option<Vec<u8>>,
}

/// Parses the stylesheet string into a usable map structure.
///
/// The stylesheet format is line-based triplets:
/// - Line 0: style_id (1-255)
/// - Line 1: opening tag
/// - Line 2: closing tag
///
/// Returns the parsed stylesheet (empty HashMap if no valid styles found).
pub fn parse_stylesheet(stylesheet_str: &str) -> StyleSheet {
    let mut map = HashMap::new();
    let lines: Vec<&str> = stylesheet_str.lines().collect();
    
    // Process in triplets (style_id, begin_tag, end_tag)
    let mut i = 0;
    while i + 2 < lines.len() {
        if let Ok(style_id) = lines[i].parse::<u8>() {
            let begin_tag = lines[i + 1].to_string();
            let end_tag = lines[i + 2].to_string();
            map.insert(style_id, (begin_tag, end_tag));
        }
        i += 3;
    }
    
    map
}

/// A single key entry from the dictionary index.
///
/// Associates a search key (word/term) with its record ID, which points to
/// the actual definition data in the record blocks.
#[derive(Debug)]
pub struct KeyEntry {
    pub id: u64,
    pub text: String,
}

/// Metadata describing a single compressed data block.
///
/// MDict files are divided into blocks for efficient random access and
/// memory management. Each block can be independently decompressed.
#[derive(Debug, Clone, Copy)]
pub struct BlockMeta {
    /// Size of the compressed block data as stored in the file (bytes).
    pub compressed_size: u64,
    /// Size of the block after decompression (bytes).
    pub decompressed_size: u64,
    /// Absolute byte offset where this block's compressed data begins in the file.
    pub file_offset: u64,
    /// Offset of this block in the virtual concatenated decompressed stream.
    /// Used for binary search when locating records by ID. The first block has offset 0.
    pub decompressed_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdictVersion {
    V1,
    V2,
    V3,
}

impl MdictVersion {
    /// Returns the byte width for numeric fields in this MDict version.
    ///
    /// - V1: 4 bytes (u32)
    /// - V2/V3: 8 bytes (u64)
    pub fn number_width(&self) -> usize {
        match self {
            MdictVersion::V1 => 4,
            MdictVersion::V2 | MdictVersion::V3 => 8,
        }
    }

    /// Returns the byte width for text length prefixes in this MDict version.
    ///
    /// - V1: 1 byte (u8)
    /// - V2/V3: 2 bytes (u16)
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

/// Block type identifiers used in MDict v3.0 files.
///
/// V3 files use explicit 32-bit type markers to identify different sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V3BlockType {
    RecordData = 0x01000000,
    RecordIndex = 0x02000000,
    KeyData = 0x03000000,
    KeyIndex = 0x04000000,
}

impl TryFrom<u32> for V3BlockType {
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
pub enum BlockType {
    Key,
    Record,
}

impl std::fmt::Display for BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BlockType::Key => write!(f, "key"),
            BlockType::Record => write!(f, "record"),
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
