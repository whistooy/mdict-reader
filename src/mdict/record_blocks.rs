//! Record block parsing (actual dictionary content)

use std::fs::File;
use std::io::Read;
use log::{debug, info, trace};
use super::models::{MdictHeader, KeyBlockInfo, RecordBlockInfo, RecordBlock};
use super::{utils, decoder};
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
pub fn parse_info(
    file: &mut File,
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
pub fn parse_index(
    file: &mut File,
    info: &RecordBlockInfo,
    header: &MdictHeader,
) -> Result<Vec<RecordBlock>> {
    info!("Parsing record block index");

    let mut index_data = vec![0u8; info.record_index_len as usize];
    file.read_exact(&mut index_data)?;

    let mut blocks = Vec::new();
    let mut reader = index_data.as_slice();

    while !reader.is_empty() {
        let compressed_size = utils::read_number(&mut reader, header.version.number_width())?;
        let decompressed_size = utils::read_number(&mut reader, header.version.number_width())?;
        blocks.push(RecordBlock {
            compressed_size,
            decompressed_size,
        });
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

/// Decompress all record blocks into a single contiguous buffer.
/// 
/// Each block is decoded (decrypted + decompressed + verified) and
/// concatenated together. The resulting buffer contains all dictionary
/// content in order.
pub fn decompress_all(
    file: &mut File,
    blocks: &[RecordBlock],
    header: &MdictHeader,
) -> Result<Vec<u8>> {
    info!("Decompressing record blocks ({} blocks)", blocks.len());

    // Calculate total decompressed size
    let total_size: usize = blocks
        .iter()
        .map(|b| b.decompressed_size as usize)
        .sum();
    debug!("Expected total decompressed size: {} bytes", total_size);

    let mut all_records = Vec::with_capacity(total_size);

    for (idx, block_meta) in blocks.iter().enumerate() {
        // Read compressed block
        let mut compressed = vec![0u8; block_meta.compressed_size as usize];
        file.read_exact(&mut compressed)?;

        // Decode block (decrypt + decompress + verify)
        let decompressed = decoder::decode_block(
            &compressed,
            block_meta.decompressed_size,
            header.master_key.as_ref(),
        )?;

        all_records.extend_from_slice(&decompressed);

        // Log progress at intervals
        if (idx + 1) % 100 == 0 || idx + 1 == blocks.len() {
            debug!("Decompressed {}/{} record blocks ({} bytes so far)", idx + 1, blocks.len(), all_records.len());
        } else {
            trace!("Decompressed {}/{} record blocks ({} bytes so far)", idx + 1, blocks.len(), all_records.len());
        }
    }

    // Verify total size
    if all_records.len() != total_size {
        return Err(MdictError::SizeMismatch {
            context: "total decompressed record buffer",
            expected: total_size as u64,
            found: all_records.len() as u64,
        });
    }

    info!("Record blocks decompressed successfully: {} bytes total", all_records.len());
    Ok(all_records)
}
