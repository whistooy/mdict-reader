//! # Common Index Parsing Logic
//!
//! This module provides shared utilities for parsing index data from various
//! MDict format versions. It includes functions for skipping over text entries
//! without decoding them, which is a common operation in both v1/v2 and v3
//! index parsing.

use crate::mdict::types::error::{MdictError, Result};
use crate::mdict::types::models::{MdictHeader, MdictVersion};
use crate::mdict::utils;

/// Skips over a length-prefixed text without decoding it.
pub fn skip_text(reader: &mut &[u8], header: &MdictHeader) -> Result<()> {
    let text_len_units = utils::read_small_number(reader, header.version.small_number_width())?;
    let terminator_units = match header.version {
        MdictVersion::V1 => 0,
        MdictVersion::V2 | MdictVersion::V3 => 1,
    };
    let total_bytes = ((text_len_units + terminator_units) as usize) * utils::unit_width(header.encoding);

    if reader.len() < total_bytes {
        return Err(MdictError::InvalidFormat("Incomplete key text in index".to_string()));
    }

    *reader = &reader[total_bytes..];
    Ok(())
}