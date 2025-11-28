//! Index parser for MDict format version 3.0.
//!
//! V3 introduces a fundamentally different structure from v1/v2:
//! - Four separate blocks: KeyData, KeyIndex, RecordData, RecordIndex
//! - Blocks can appear in any order (requires scanning)
//! - Each block has a 12-byte header (4-byte type + 8-byte size)
//! - Index blocks are compressed and contain metadata for data blocks
//! - Data blocks have inline size headers that may conflict with index

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{BigEndian, ReadBytesExt};
use log::{debug, info, warn, trace};

use crate::mdict::{
    types::{
        error::{MdictError, Result},
        models::{V3BlockType, BlockMeta, BlockType, MdictVersion, MdictEncoding},
    },
    utils,
};
use super::common;
use crate::mdict::format::content;

use super::ParseResult;

/// Parses the complete index structure for v3.0 MDict files.
///
/// V3 parsing workflow:
/// 1. Scan file to locate all four block types
/// 2. Parse key index to get entry count and block metadata
/// 3. Parse record index to get block metadata
/// 4. Read data block headers and reconcile with index metadata
///
/// # Returns
/// A tuple containing:
/// - `Vec<BlockMeta>`: Key block metadata
/// - `Vec<BlockMeta>`: Record block metadata
/// - `u64`: Total decompressed size of all record blocks
/// - `u64`: Total number of dictionary entries
pub fn parse(
    file: &mut File,
    version: MdictVersion,
    encoding: MdictEncoding,
    master_key: Option<&[u8; 16]>,
) -> Result<ParseResult> {
    info!("Parsing v3.0 MDict file");

    let key_block_offset = file.stream_position()?;

    // Step 1: Scan to locate all four required blocks
    let (key_data_offset, key_index_offset, record_data_offset, record_index_offset) =
        scan_block_offsets(file, key_block_offset)?;

    // Step 2: Parse indexes to get metadata
    let (num_entries, key_index) = parse_key_index(file, version, encoding, master_key, key_index_offset)?;
    let record_index = parse_record_index(file, version, encoding, master_key, record_index_offset)?;

    // Step 3: Read data block headers and build final metadata
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

/// Parses data block headers and reconciles with index metadata.
///
/// V3 data blocks have inline size headers that sometimes conflict with
/// the index. This function reads both and uses index values when there's
/// a mismatch, as they're generally more reliable.
///
/// # Parameters
/// - `file`: File handle
/// - `offset`: Starting offset of the data section
/// - `index`: Metadata pairs from the corresponding index block
/// - `block_type`: Whether parsing key or record blocks
///
/// # Returns
/// Vector of [`BlockMeta`] with finalized size and offset information
fn parse_block_metadata<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    index: &[(u64, u64)],
    block_type: BlockType,
) -> Result<Vec<BlockMeta>> {
    info!("Reading v3.0 {} blocks metadata", block_type);
    
    file.seek(SeekFrom::Start(offset))?;
    
    // Read data section header
    let num_blocks = file.read_u32::<BigEndian>()? as usize;
    let _total_size = file.read_u64::<BigEndian>()?;
    
    debug!("{} data section: {} blocks", block_type, num_blocks);
    
    let mut blocks = Vec::with_capacity(num_blocks);
    let mut decompressed_offset = 0u64;
    
    // Process each data block
    for i in 0..num_blocks {
        // Read inline size headers (8 bytes total)
        let inline_decomp = file.read_u32::<BigEndian>()? as u64;
        let inline_comp = file.read_u32::<BigEndian>()? as u64;
      
        let mut compressed_size = inline_comp;
        let mut decompressed_size = inline_decomp;
        
        // Reconcile inline headers with index metadata
        if let Some(&(index_block_size, index_decomp)) = index.get(i) {
            // Index size includes the 8-byte header; subtract it for payload size
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
        
        // Record the actual data offset (after headers)
        let file_offset = file.stream_position()?;
        
        blocks.push(BlockMeta {
            compressed_size,
            decompressed_size,
            file_offset,
            decompressed_offset,
        });
        // Skip to next block
        file.seek(SeekFrom::Current(compressed_size as i64))?;
        
        
        decompressed_offset += decompressed_size;
    }
    
    debug!("Parsed {} {} block metadata entries", blocks.len(), block_type);
    Ok(blocks)
}

/// Result type for index parsing operations.
///
/// Contains:
/// - Optional total entry count (present only for key indexes)
/// - List of (block_size, decompressed_size) pairs for validation
type IndexParseResult = (Option<u64>, Vec<(u64, u64)>);

/// Generic parser for v3 index blocks.
///
/// Index blocks are structured as:
/// - Header: num_blocks (4 bytes) + total_size (8 bytes)
/// - Multiple compressed sub-blocks containing metadata entries
///
/// Each metadata entry format differs by type:
/// - Key: entry_count + first_key + last_key + block_size + decomp_size
/// - Record: block_size + decomp_size
///
/// # Returns
/// Tuple of (optional entry count, metadata pairs for validation)
fn parse_index<R: Read + Seek>(
    file: &mut R,
    version: MdictVersion,
    encoding: MdictEncoding,
    master_key: Option<&[u8; 16]>,
    offset: u64,
    block_type: BlockType,
) -> Result<IndexParseResult> {
    info!("Parsing and decoding v3.0 {} index", block_type);

    file.seek(SeekFrom::Start(offset))?;

    // Read index section header
    let num_blocks = file.read_u32::<BigEndian>()? as usize;
    let _total_size = file.read_u64::<BigEndian>()?;
    debug!("{} index contains {} sub-blocks", block_type, num_blocks);

    let mut total_entries = if block_type == BlockType::Key { Some(0u64) } else { None };
    let mut index_pairs = Vec::new();

    // Process each compressed sub-block
    for _ in 0..num_blocks {
        let decompressed_size = file.read_u32::<BigEndian>()? as u64;
        let compressed_size = file.read_u32::<BigEndian>()? as u64;

        let mut compressed = vec![0u8; compressed_size as usize];
        file.read_exact(&mut compressed)?;
        
        // Decompress and decrypt if necessary
        let mut decompressed = Vec::new();
        content::decode_block_into(
            &mut decompressed,
            &mut compressed,
            decompressed_size,
            master_key,
            version,
        )?;
        let mut reader = decompressed.as_slice();

        // Validate record index block size (must be multiple of 16)
        if block_type == BlockType::Record && decompressed.len() % 16 != 0 {
            return Err(MdictError::InvalidFormat(format!(
                "Record index block has invalid size: {}",
                decompressed.len()
            )));
        }

        // Extract metadata entries from this sub-block
        while !reader.is_empty() {
            match block_type {
                BlockType::Key => {
                    // Key entries include count and text ranges
                    let num_entries_in_block = reader.read_u32::<BigEndian>()? as u64;
                    if let Some(total) = total_entries.as_mut() {
                        *total += num_entries_in_block;
                    }

                    // Skip first and last key texts (boundary keys for range queries, not needed for metadata extraction)
                    common::skip_text(&mut reader, version, encoding)?;
                    common::skip_text(&mut reader, version, encoding)?;

                    // Read block sizes (4 bytes each in v3 key index)
                    let block_size = utils::read_number(&mut reader, 4)?;
                    let decompressed_size = utils::read_number(&mut reader, 4)?;
                    index_pairs.push((block_size, decompressed_size));
                }
                BlockType::Record => {
                    // Record entries are simpler (just sizes, 8 bytes each in v3 record index)
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

/// Parses the key index block and extracts entry count.
///
/// Wrapper around [`parse_index`] that ensures the entry count is returned.
fn parse_key_index<R: Read + Seek>(
    file: &mut R,
    version: MdictVersion,
    encoding: MdictEncoding,
    master_key: Option<&[u8; 16]>,
    offset: u64,
) -> Result<(u64, Vec<(u64, u64)>)> {
    let (total_entries, index_pairs) = parse_index(file, version, encoding, master_key, offset, BlockType::Key)?;
    Ok((total_entries.unwrap_or(0), index_pairs))
}

/// Parses the record index block.
///
/// Wrapper around [`parse_index`] that discards the entry count
/// (not present in record indexes).
fn parse_record_index<R: Seek + Read>(
    file: &mut R,
    version: MdictVersion,
    encoding: MdictEncoding,
    master_key: Option<&[u8; 16]>,
    offset: u64,
) -> Result<Vec<(u64, u64)>> {
    let (_, index_pairs) = parse_index(file, version, encoding, master_key, offset, BlockType::Record)?;
    Ok(index_pairs)
}

/// Scans the v3 file structure to locate all four required blocks.
///
/// V3 blocks can appear in any order, so we must scan the entire structure.
/// Each block starts with a 12-byte header:
/// - 4 bytes: block type identifier
/// - 8 bytes: block data size (excluding header)
///
/// # Returns
/// A tuple of (key_data_offset, key_index_offset, record_data_offset, record_index_offset)
///
/// # Errors
/// Returns an error if any of the four required blocks are missing.
pub fn scan_block_offsets<R: Read + Seek>(
    file: &mut R,
    start_offset: u64,
) -> Result<(u64, u64, u64, u64)> {
    info!("Scanning v3.0 file structure for block offsets");

    file.seek(SeekFrom::Start(start_offset))?;

    // Track which blocks we've found
    let mut offsets = [
        (V3BlockType::KeyData, None),
        (V3BlockType::KeyIndex, None),
        (V3BlockType::RecordData, None),
        (V3BlockType::RecordIndex, None),
    ];

    // Scan through all blocks until EOF
    while let Ok(block_type_raw) = file.read_u32::<BigEndian>() {
        let block_type = V3BlockType::try_from(block_type_raw)?;
        let block_size = file.read_u64::<BigEndian>()?;
        let block_data_offset = file.stream_position()?;

        trace!(
            "Found block: type={:?}, size={} bytes, offset={}",
            block_type, block_size, block_data_offset
        );

        // Record this block's offset
        if let Some(offset) = offsets.iter_mut().find(|(t, _)| *t == block_type) {
            offset.1 = Some(block_data_offset);
        } else {
            // Unknown block type (shouldn't happen with proper validation)
            warn!("Ignoring unknown block type: {:#010x}", block_type_raw);
        }

        // Skip this block's data to find the next header
        file.seek(SeekFrom::Current(block_size as i64))?;
    }

    // Validate all required blocks were found
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
