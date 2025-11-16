//! Low-level byte and encoding utilities for MDict format parsing.

use std::io::Read;
use byteorder::{BigEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16BE, UTF_16LE};
use super::error::Result;

/// Read a 4 or 8 byte big-endian number.
/// 
/// Used throughout MDict format for size and count fields.
/// Width depends on format version (v1.x uses 4 bytes, v2.x/v3.x uses 8 bytes).
///
/// # Panics
/// Panics if `number_width` is not 4 or 8. This is considered a programmer
/// error, as this value is fixed after parsing the header.
pub fn read_number(reader: &mut impl Read, number_width: usize) -> Result<u64> {
    match number_width {
        8 => Ok(reader.read_u64::<BigEndian>()?),
        4 => Ok(reader.read_u32::<BigEndian>()? as u64),
        // This path is logically impossible if the header is parsed correctly.
        _ => unreachable!("Invalid number width: must be 4 or 8"),
    }
}

/// Read a 1 or 2 byte big-endian number.
/// 
/// Used for text length prefixes in MDict format.
///
/// # Panics
/// Panics if `number_width` is not 1 or 2. This is a programmer error.
pub fn read_small_number(reader: &mut impl Read, number_width: usize) -> Result<u64> {
    match number_width {
        2 => Ok(reader.read_u16::<BigEndian>()? as u64),
        1 => Ok(reader.read_u8()? as u64),
        // This path is logically impossible.
        _ => unreachable!("Invalid small number width: must be 1 or 2"),
    }
}

/// Return the width in bytes of a single code unit for the given encoding.
///
/// In MDict format:
/// - UTF-16 encodings use 2-byte code units.
/// - All other supported encodings use 1-byte code units.
pub fn unit_width(encoding: &'static Encoding) -> usize {
    if encoding == UTF_16LE || encoding == UTF_16BE {
        2
    } else {
        1
    }
}

/// Parse and normalize an encoding label string.
///
/// - Normalizes GBK/GB2312 → GB18030 (broader compatibility)
/// - Returns UTF-8 as fallback if label is unknown
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
