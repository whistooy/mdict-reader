//! # Index Parsing Dispatcher
//!
//! This module acts as the main entry point for parsing the key and record
//! block indexes of an MDict file. It dispatches to the appropriate
//! version-specific parser based on the `MdictHeader`.

use std::fs::File;
use crate::mdict::types::error::Result;
use crate::mdict::types::models::{BlockMeta, MdictHeader, MdictVersion};

pub mod common;
pub mod v1v2;
pub mod v3;

/// Parses the key and record block metadata based on the MDict version.
///
/// This function reads the index information from the file and returns the
/// metadata for both key and record blocks, along with the total decompressed
/// size of all record blocks and the total number of entries.
pub fn parse(
    file: &mut File,
    header: &MdictHeader,
) -> Result<(Vec<BlockMeta>, Vec<BlockMeta>, u64, u64)> {
    match header.version {
        MdictVersion::V3 => v3::parse(file, header),
        MdictVersion::V1 | MdictVersion::V2 => v1v2::parse(file, header),
    }
}