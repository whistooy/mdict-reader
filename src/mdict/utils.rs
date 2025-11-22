//! Low-level utilities for binary data and text encoding operations.
//!
//! This module provides helper functions for reading numeric values and
//! handling text encodings according to the MDict format specification.

use std::io::Read;
use byteorder::{BigEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16BE, UTF_16LE};
use super::types::error::Result;

/// Reads a big-endian integer from the reader.
///
/// The width is version-dependent:
/// - v1.x: 4 bytes (u32)
/// - v2.x/v3.x: 8 bytes (u64)
///
/// # Panics
/// Panics if `number_width` is neither 4 nor 8. This is a programmer error,
/// as the width is determined by the file version during header parsing.
pub fn read_number(reader: &mut impl Read, number_width: usize) -> Result<u64> {
    match number_width {
        8 => Ok(reader.read_u64::<BigEndian>()?),
        4 => Ok(reader.read_u32::<BigEndian>()? as u64),
        // Unreachable if the version enum is used correctly
        _ => unreachable!("Invalid number width: must be 4 or 8"),
    }
}

/// Reads a small big-endian integer used for text length prefixes.
///
/// The width is version-dependent:
/// - v1.x: 1 byte (u8)
/// - v2.x/v3.x: 2 bytes (u16)
///
/// # Panics
/// Panics if `number_width` is neither 1 nor 2. This is a programmer error.
pub fn read_small_number(reader: &mut impl Read, number_width: usize) -> Result<u64> {
    match number_width {
        2 => Ok(reader.read_u16::<BigEndian>()? as u64),
        1 => Ok(reader.read_u8()? as u64),
        // Unreachable if the version enum is used correctly
        _ => unreachable!("Invalid small number width: must be 1 or 2"),
    }
}

/// Returns the byte width of a single character unit for the given encoding.
///
/// MDict text fields are encoded as:
/// - UTF-16LE/BE: 2 bytes per code unit
/// - All others (UTF-8, GB18030, etc.): 1 byte per code unit
pub fn unit_width(encoding: &'static Encoding) -> usize {
    if encoding == UTF_16LE || encoding == UTF_16BE {
        2
    } else {
        1
    }
}

/// Parses an encoding label and returns the corresponding `Encoding`.
///
/// Applies normalization rules:
/// - `GBK`/`GB2312` → `GB18030` (for broader character coverage)
/// - Unknown labels → `UTF-8` (safe fallback)
pub fn parse_encoding(label: &str) -> &'static Encoding {
    let trimmed = label.trim();

    let normalized_label = if trimmed.eq_ignore_ascii_case("GBK") || trimmed.eq_ignore_ascii_case("GB2312") {
        "GB18030"
    } else {
        trimmed
    };

    Encoding::for_label(normalized_label.as_bytes())
        .unwrap_or(encoding_rs::UTF_8)
}
