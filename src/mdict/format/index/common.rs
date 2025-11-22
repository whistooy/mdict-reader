//! Common utilities for index parsing across all MDict versions.
//!
//! This module provides shared helper functions used by both v1/v2 and v3
//! index parsers, primarily for efficiently skipping text fields without
//! full decoding.

use crate::mdict::types::error::{MdictError, Result};
use crate::mdict::types::models::{MdictHeader, MdictVersion};
use crate::mdict::utils;

/// Skips a length-prefixed text field without decoding its content.
///
/// This function efficiently advances the reader position past a text field
/// by calculating its byte size based on encoding and version, avoiding the
/// overhead of full string decoding when only the field boundary is needed.
///
/// # Parameters
/// - `reader`: Mutable reference to the byte slice being read
/// - `header`: MDict header containing encoding and version information
///
/// # Returns
/// - `Ok(())` if the text was successfully skipped
/// - `Err(MdictError)` if the buffer is too short or format is invalid
pub fn skip_text(reader: &mut &[u8], header: &MdictHeader) -> Result<()> {
    // Read the length prefix (number of text units, not bytes)
    let text_len_units = utils::read_small_number(reader, header.version.small_number_width())?;
    
    // V1 uses no null terminator, V2/V3 include a terminator unit
    let terminator_units = match header.version {
        MdictVersion::V1 => 0,
        MdictVersion::V2 | MdictVersion::V3 => 1,
    };
    
    // Calculate total bytes: (text + terminator) * bytes_per_unit
    let total_bytes = ((text_len_units + terminator_units) as usize) * utils::unit_width(header.encoding);

    // Validate sufficient data remains
    if reader.len() < total_bytes {
        return Err(MdictError::InvalidFormat("Incomplete key text in index".to_string()));
    }

    // Advance the reader past the text field
    *reader = &reader[total_bytes..];
    Ok(())
}