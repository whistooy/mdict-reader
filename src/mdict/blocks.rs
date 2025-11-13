//! Shared logic for handling compressed data blocks.

use std::io::{Read, Seek, SeekFrom};
use super::models::{BlockMeta, MdictHeader};
use super::error::Result;
use super::decoder;

/// Decode the raw data of any block.
/// This is the shared, low-level function.
pub fn decode_block<R: Seek + Read>(
    file: &mut R,
    block_meta: &BlockMeta,
    header: &MdictHeader,
) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(block_meta.file_offset))?;
    
    let mut compressed = vec![0u8; block_meta.compressed_size as usize];
    file.read_exact(&mut compressed)?;
    
    decoder::decode_payload(
        &mut compressed,
        block_meta.decompressed_size,
        header.master_key.as_ref(),
    )
}
