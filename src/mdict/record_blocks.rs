//! Record block parsing (actual dictionary content)

use std::io::{Read, Seek, SeekFrom};
use log::{debug, info, warn};
use super::models::{MdictHeader, BlockMeta};
use super::utils;
use super::error::{Result, MdictError};
use byteorder::{BigEndian, ReadBytesExt};
use super::decoder::decode_payload;

/// Parse record block metadata for v1/v2
pub fn parse_v1v2<R: Seek + Read>(
    file: &mut R,
    header: &MdictHeader,
) -> Result<Vec<BlockMeta>> {
    info!("Parsing record block info section");

    let num_blocks = utils::read_number(file, header.version.number_width())?;
    let num_entries = utils::read_number(file, header.version.number_width())?;
    let record_index_len = utils::read_number(file, header.version.number_width())?;
    let record_blocks_len = utils::read_number(file, header.version.number_width())?;

    info!(
        "Record block info: blocks={}, entries={}, index={} bytes, data={} bytes",
        num_blocks, num_entries, record_index_len, record_blocks_len
    );

    let mut index_data = vec![0u8; record_index_len as usize];
    file.read_exact(&mut index_data)?;

    let mut blocks = Vec::with_capacity(num_blocks as usize);
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
    if blocks.len() as u64 != num_blocks {
        return Err(MdictError::CountMismatch {
            item_type: "record blocks in index",
            expected: num_blocks,
            found: blocks.len() as u64,
        });
    }

    debug!("Record block index parsed: {} blocks defined", blocks.len());
    Ok(blocks)
}

/// Parse record block metadata for v3 (inline in record data block)
pub fn parse_v3<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    index: &[(u64, u64)],
) -> Result<Vec<BlockMeta>> {
    info!("Reading v3.0 record blocks metadata");
    
    file.seek(SeekFrom::Start(offset))?;
    
    let num_blocks = file.read_u32::<BigEndian>()? as usize;
    let _total_size = file.read_u64::<BigEndian>()?;
    
    debug!("Record data section: {} blocks", num_blocks);
    
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
                    "Record block {} size mismatch (inline: {}, {}) vs (index: {}, {}). Using index values.",
                    i, inline_comp, inline_decomp, index_block_size, index_decomp
                );
                compressed_size = index_comp;
                decompressed_size = index_decomp;
            }
        } else {
            // This should not happen if counts match, but as a safeguard:
            return Err(MdictError::InvalidFormat(format!("Missing metadata for key block {} in record index", i)));
        }

        // The current position is the start of this block's data.
        let file_offset = file.stream_position()?;
      
        blocks.push(BlockMeta {
            compressed_size,
            decompressed_size,
            file_offset,
            decompressed_offset,
        });
      
        // Seek past the compressed data to get to the next metadata pair.
        file.seek(SeekFrom::Current(compressed_size as i64))?;

        decompressed_offset += decompressed_size;
    }
    
    debug!("Parsed {} record block metadata entries", blocks.len());
    Ok(blocks)
}

/// Read and parse the v3 record index block if present.
///
/// Returns a list of (block_size, decompressed_size) pairs for validation.
pub fn parse_v3_record_index<R: Seek + Read>(
    file: &mut R,
    header: &MdictHeader,
    offset: u64,
) -> Result<Vec<(u64, u64)>> {

    info!("Parsing v3.0 record index for validation");

    file.seek(SeekFrom::Start(offset))?;

    let num_index_blocks = file.read_u32::<BigEndian>()? as usize;
    let _total_size = file.read_u64::<BigEndian>()?;

    let mut index_pairs = Vec::new();

    for _ in 0..num_index_blocks {
        let decompressed_size = file.read_u32::<BigEndian>()? as u64;
        let compressed_size = file.read_u32::<BigEndian>()? as u64;

        let mut compressed = vec![0u8; compressed_size as usize];
        file.read_exact(&mut compressed)?;

        let decompressed = decode_payload(
            &mut compressed,
            decompressed_size,
            header.master_key.as_ref(),
            header.version,
        )?;

        if decompressed.len() % 16 != 0 {
            return Err(MdictError::InvalidFormat(format!(
                "Record index block has invalid size: {}",
                decompressed.len()
            )));
        }

        let mut reader = decompressed.as_slice();

        while !reader.is_empty() {
            let block_size = utils::read_number(&mut reader, 8)?;
            let decompressed_size = utils::read_number(&mut reader, 8)?;
            index_pairs.push((block_size, decompressed_size));
        }
    }

    debug!("Parsed {} record index entries for validation", index_pairs.len());
    Ok(index_pairs)
}
