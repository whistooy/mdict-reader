//! Parser for MDict format version 3.0.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{BigEndian, ReadBytesExt};
use log::{debug, info, warn, trace};

use crate::mdict::{
    types::{
        error::{MdictError, Result},
        models::{V3BlockType, BlockMeta, MdictHeader, BlockType},
    },
    utils,
};
use super::common;
use crate::mdict::format::content;

use super::ParseResult;

/// Main parser for v3 files.
pub fn parse(
    file: &mut File,
    header: &MdictHeader,
) -> Result<ParseResult> {
    info!("Parsing v3.0 MDict file");

    let key_block_offset = file.stream_position()?;

    // Scan for block offsets
    let (key_data_offset, key_index_offset, record_data_offset, record_index_offset) =
        scan_block_offsets(file, key_block_offset)?;

    let (num_entries, key_index) = parse_key_index(file, header, key_index_offset)?;
    let record_index = parse_record_index(file, header, record_index_offset)?;

    let key_blocks = parse_block_metadata(file, key_data_offset, &key_index, BlockType::Key)?;
    let record_blocks = parse_block_metadata(file, record_data_offset, &record_index, BlockType::Record)?;

    let total_record_decomp_size: u64 = record_blocks.iter().map(|b| b.decompressed_size).sum();

    info!(
        "V3.0 file opened: {} key blocks, {} record blocks",
        key_blocks.len(),
        record_blocks.len()
    );

    Ok((key_blocks, record_blocks, total_record_decomp_size, num_entries))
}

/// Generic parser for v3 block metadata (used for both key and record blocks).
fn parse_block_metadata<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    index: &[(u64, u64)],
    block_type: BlockType,
) -> Result<Vec<BlockMeta>> {
    info!("Reading v3.0 {} blocks metadata", block_type);
    
    file.seek(SeekFrom::Start(offset))?;
    
    let num_blocks = file.read_u32::<BigEndian>()? as usize;
    let _total_size = file.read_u64::<BigEndian>()?;
    
    debug!("{} data section: {} blocks", block_type, num_blocks);
    
    let mut blocks = Vec::with_capacity(num_blocks);
    let mut decompressed_offset = 0u64;
    
    for i in 0..num_blocks {
        let inline_decomp = file.read_u32::<BigEndian>()? as u64;
        let inline_comp = file.read_u32::<BigEndian>()? as u64;
      
        let mut compressed_size = inline_comp;
        let mut decompressed_size = inline_decomp;
        
        if let Some(&(index_block_size, index_decomp)) = index.get(i) {
            // The size in the index includes the 8-byte header, so we subtract it to get the payload size.
            let index_comp = index_block_size.saturating_sub(8);
            if (inline_comp, inline_decomp) != (index_comp, index_decomp) {
                warn!(
                    "{} block {} size mismatch (inline: {}, {}) vs (index: {}, {}). Using index values.",
                    block_type, i, inline_comp, inline_decomp, index_block_size, index_decomp
                );
                compressed_size = index_comp;
                decompressed_size = index_decomp;
            }
        } else {
            return Err(MdictError::InvalidFormat(format!("Missing metadata for {} block {} in {} index", block_type, i, block_type)));
        }
        
        let file_offset = file.stream_position()?;
        
        blocks.push(BlockMeta {
            compressed_size,
            decompressed_size,
            file_offset,
            decompressed_offset,
        });
        
        file.seek(SeekFrom::Current(compressed_size as i64))?;
        
        decompressed_offset += decompressed_size;
    }
    
    debug!("Parsed {} {} block metadata entries", blocks.len(), block_type);
    Ok(blocks)
}

/// Result of parsing a v3 index block.
/// Contains an optional total entry count (for key indexes) and a list of (block_size, decompressed_size) pairs.
type IndexParseResult = (Option<u64>, Vec<(u64, u64)>);

/// Generic parser for v3 index blocks (key and record).
fn parse_index<R: Read + Seek>(
    file: &mut R,
    header: &MdictHeader,
    offset: u64,
    block_type: BlockType,
) -> Result<IndexParseResult> {
    info!("Parsing and decoding v3.0 {} index", block_type);

    file.seek(SeekFrom::Start(offset))?;

    let num_blocks = file.read_u32::<BigEndian>()? as usize;
    let _total_size = file.read_u64::<BigEndian>()?;
    debug!("{} index contains {} sub-blocks", block_type, num_blocks);

    let mut total_entries = if block_type == BlockType::Key { Some(0u64) } else { None };
    let mut index_pairs = Vec::new();

    for _ in 0..num_blocks {
        let decompressed_size = file.read_u32::<BigEndian>()? as u64;
        let compressed_size = file.read_u32::<BigEndian>()? as u64;

        let mut compressed = vec![0u8; compressed_size as usize];
        file.read_exact(&mut compressed)?;
        let decompressed = content::decode_block(
            &mut compressed,
            decompressed_size,
            header.master_key.as_ref(),
            header.version,
        )?;
        let mut reader = decompressed.as_slice();

        if block_type == BlockType::Record && decompressed.len() % 16 != 0 {
            return Err(MdictError::InvalidFormat(format!(
                "Record index block has invalid size: {}",
                decompressed.len()
            )));
        }

        while !reader.is_empty() {
            match block_type {
                BlockType::Key => {
                    let num_entries_in_block = reader.read_u32::<BigEndian>()? as u64;
                    if let Some(total) = total_entries.as_mut() {
                        *total += num_entries_in_block;
                    }

                    common::skip_text(&mut reader, header)?;
                    common::skip_text(&mut reader, header)?;

                    let block_size = utils::read_number(&mut reader, 4)?;
                    let decompressed_size = utils::read_number(&mut reader, 4)?;
                    index_pairs.push((block_size, decompressed_size));
                }
                BlockType::Record => {
                    let block_size = utils::read_number(&mut reader, 8)?;
                    let decompressed_size = utils::read_number(&mut reader, 8)?;
                    index_pairs.push((block_size, decompressed_size));
                }
            }
        }
    }

    if let Some(total) = total_entries {
        info!("Total entries from v3 index: {}", total);
    }
    debug!("Parsed {} {} index entries for validation", index_pairs.len(), block_type);
    Ok((total_entries, index_pairs))
}

/// Parse v3.0 key index to get total entry count and metadata.
fn parse_key_index<R: Read + Seek>(
    file: &mut R,
    header: &MdictHeader,
    offset: u64,
) -> Result<(u64, Vec<(u64, u64)>)> {
    let (total_entries, index_pairs) = parse_index(file, header, offset, BlockType::Key)?;
    Ok((total_entries.unwrap_or(0), index_pairs))
}

/// Read and parse the v3 record index block if present.
fn parse_record_index<R: Seek + Read>(
    file: &mut R,
    header: &MdictHeader,
    offset: u64,
) -> Result<Vec<(u64, u64)>> {
    let (_, index_pairs) = parse_index(file, header, offset, BlockType::Record)?;
    Ok(index_pairs)
}

/// Scan the file to locate block offsets.
/// Returns (key_data_offset, key_index_offset, record_data_offset, record_index_offset).
/// Returns an error if any of the four required blocks are missing.
pub fn scan_block_offsets<R: Read + Seek>(
    file: &mut R,
    start_offset: u64,
) -> Result<(u64, u64, u64, u64)> {
    info!("Scanning v3.0 file structure for block offsets");

    file.seek(SeekFrom::Start(start_offset))?;

    let mut offsets = [
        (V3BlockType::KeyData, None),
        (V3BlockType::KeyIndex, None),
        (V3BlockType::RecordData, None),
        (V3BlockType::RecordIndex, None),
    ];

    while let Ok(block_type_raw) = file.read_u32::<BigEndian>() {
        let block_type = V3BlockType::try_from(block_type_raw)?;
        let block_size = file.read_u64::<BigEndian>()?;
        let block_data_offset = file.stream_position()?;

        trace!(
            "Found block: type={:?}, size={} bytes, offset={}",
            block_type, block_size, block_data_offset
        );

        // Find the corresponding offset in our array and set it
        if let Some(offset) = offsets.iter_mut().find(|(t, _)| *t == block_type) {
            offset.1 = Some(block_data_offset);
        } else {
            // This case should not be reached with our BlockType enum, but good for safety
            warn!("Ignoring unknown block type: {:#010x}", block_type_raw);
        }

        // Skip to the next block header
        file.seek(SeekFrom::Current(block_size as i64))?;
    }

    // Unpack the results, checking for missing blocks
    let get_offset = |block_type: V3BlockType| {
        offsets
            .iter()
            .find(|(t, _)| *t == block_type)
            .and_then(|(_, o)| *o)
            .ok_or_else(|| MdictError::InvalidFormat(format!("Missing {:?} block in v3.0 file", block_type)))
    };

    let key_data_offset = get_offset(V3BlockType::KeyData)?;
    let key_index_offset = get_offset(V3BlockType::KeyIndex)?;
    let record_data_offset = get_offset(V3BlockType::RecordData)?;
    let record_index_offset = get_offset(V3BlockType::RecordIndex)?;

    info!(
        "V3.0 block scan complete: key_data={}, key_index={}, record_data={}, record_index={}",
        key_data_offset, key_index_offset, record_data_offset, record_index_offset
    );

    Ok((key_data_offset, key_index_offset, record_data_offset, record_index_offset))
}
