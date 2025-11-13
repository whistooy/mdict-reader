//! Record block parsing (actual dictionary content)

use std::io::{Read, Seek};
use log::{debug, info};
use super::models::{MdictHeader, KeyBlockInfo, RecordBlockInfo, BlockMeta};
use super::utils;
use super::error::{Result, MdictError};

/// Parse record block info section.
/// 
/// Structure (both v1.x and v2.x):
/// - Number of record blocks
/// - Number of entries
/// - Record index length
/// - Record blocks total length
/// 
/// Not encrypted, no checksum.
pub fn parse_info<R: Read>(
    file: &mut R,
    header: &MdictHeader,
    key_info: &KeyBlockInfo,
) -> Result<RecordBlockInfo> {
    info!("Parsing record block info section");

    let num_record_blocks = utils::read_number(file, header.version.number_width())?;
    let num_entries = utils::read_number(file, header.version.number_width())?;
    let record_index_len = utils::read_number(file, header.version.number_width())?;
    let record_blocks_len = utils::read_number(file, header.version.number_width())?;

    // Sanity check: entry count should match key blocks
    if num_entries != key_info.num_entries {
        return Err(MdictError::CountMismatch {
            item_type: "record entries vs key entries",
            expected: key_info.num_entries,
            found: num_entries,
        });
    }

    info!(
        "Record block info: blocks={}, entries={}, index={} bytes, data={} bytes",
        num_record_blocks, num_entries, record_index_len, record_blocks_len
    );

    Ok(RecordBlockInfo {
        num_record_blocks,
        num_entries,
        record_index_len,
        record_blocks_len,
    })
}

/// Parse record block index (metadata for each record block).
/// 
/// Simple list of (compressed_size, decompressed_size) pairs.
/// No compression or encryption.
pub fn parse_index<R: Seek + Read>(
    file: &mut R,
    info: &RecordBlockInfo,
    header: &MdictHeader,
) -> Result<Vec<BlockMeta>> {
    info!("Parsing record block index");

    let mut index_data = vec![0u8; info.record_index_len as usize];
    file.read_exact(&mut index_data)?;

    let mut blocks = Vec::with_capacity(info.num_record_blocks as usize);
    let mut reader = index_data.as_slice();
    let mut file_offset = file.stream_position()?;
    let mut decompressed_offset: u64 = 0;

    while !reader.is_empty() {
        let compressed_size = utils::read_number(&mut reader, header.version.number_width())?;
        let decompressed_size = utils::read_number(&mut reader, header.version.number_width())?;
        blocks.push(BlockMeta {
            compressed_size,
            decompressed_size,
            file_offset,
            decompressed_offset
        });
        file_offset += compressed_size;
        decompressed_offset += decompressed_size;
    }

    // Verify block count
    if blocks.len() as u64 != info.num_record_blocks {
        return Err(MdictError::CountMismatch {
            item_type: "record blocks in index",
            expected: info.num_record_blocks,
            found: blocks.len() as u64,
        });
    }

    debug!("Record block index parsed: {} blocks defined", blocks.len());
    Ok(blocks)
}
