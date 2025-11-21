//! Parser for MDict format versions 1.x and 2.x.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, ByteOrder};
use adler2::adler32_slice;
use log::{debug, info};

use crate::mdict::{
    codec::{crypto, compression},
    types::{
        error::{MdictError, Result},
        models::{BlockMeta, CompressionType, MdictHeader, MdictVersion, BlockType},
    },
    utils,
};
use super::common;

/// Main parser for v1/v2 files.
pub fn parse(
    file: &mut File,
    header: &MdictHeader,
) -> Result<(Vec<BlockMeta>, Vec<BlockMeta>, u64, u64)> {
    let (key_blocks, num_entries) = parse_block_info(file, header, BlockType::Key)?;

    // Skip to record section
    let total_key_blocks_size: u64 = key_blocks.iter().map(|b| b.compressed_size).sum();
    file.seek(SeekFrom::Current(total_key_blocks_size as i64))?;

    let (record_blocks, _) = parse_block_info(file, header, BlockType::Record)?;

    let total_record_decomp_size: u64 = record_blocks.iter().map(|b| b.decompressed_size).sum();

    info!(
        "MDict file opened: {} key blocks, {} record blocks",
        key_blocks.len(),
        record_blocks.len()
    );

    Ok((key_blocks, record_blocks, total_record_decomp_size, num_entries))
}

/// Generic parser for v1/v2 block metadata (key and record).
fn parse_block_info<R: Seek + Read>(
    file: &mut R,
    header: &MdictHeader,
    block_type: BlockType,
) -> Result<(Vec<BlockMeta>, u64)> {
    info!("Parsing {} block info section", block_type);

    let (index_data, num_blocks, num_entries) = if block_type == BlockType::Key {
        parse_key_block_index(file, header)?
    } else {
        parse_record_block_index(file, header)?
    };

    info!("Extracting block boundaries from {} index", block_type);
    let initial_file_offset = file.stream_position()?;
    let (blocks, total_entries) =
        extract_block_metas(&index_data, header, block_type, initial_file_offset)?;

    if blocks.len() as u64 != num_blocks {
        return Err(MdictError::CountMismatch {
            item_type: format!("{} blocks in index", block_type),
            expected: num_blocks,
            found: blocks.len() as u64,
        });
    }

    if block_type == BlockType::Key && total_entries != num_entries {
        return Err(MdictError::CountMismatch {
            item_type: "key entries in index".to_string(),
            expected: num_entries,
            found: total_entries,
        });
    }

    info!("{} index metadata: {} blocks defined", block_type, blocks.len());
    Ok((blocks, num_entries))
}

/// Extracts block metadata from the decompressed index data.
fn extract_block_metas(
    index_data: &[u8],
    header: &MdictHeader,
    block_type: BlockType,
    initial_file_offset: u64,
) -> Result<(Vec<BlockMeta>, u64)> {
    let mut blocks = Vec::new();
    let mut reader = index_data;
    let mut total_entries = 0u64;
    let mut file_offset = initial_file_offset;
    let mut decompressed_offset: u64 = 0;

    while !reader.is_empty() {
        if block_type == BlockType::Key {
            let num_entries_in_block =
                utils::read_number(&mut reader, header.version.number_width())?;
            total_entries += num_entries_in_block;
            // Skip first and last key text
            common::skip_text(&mut reader, header)?;
            common::skip_text(&mut reader, header)?;
        }

        let compressed_size = utils::read_number(&mut reader, header.version.number_width())?;
        let decompressed_size = utils::read_number(&mut reader, header.version.number_width())?;

        blocks.push(BlockMeta {
            compressed_size,
            decompressed_size,
            file_offset,
            decompressed_offset,
        });
        file_offset += compressed_size;
        decompressed_offset += decompressed_size;
    }

    Ok((blocks, total_entries))
}


/// Parses the key block index header and data.
fn parse_key_block_index<R: Seek + Read>(
    file: &mut R,
    header: &MdictHeader,
) -> Result<(Vec<u8>, u64, u64)> {
    let info_size = match header.version {
        MdictVersion::V1 => 16, // 4 fields * 4 bytes
        MdictVersion::V2 => 40, // 5 fields * 8 bytes
        MdictVersion::V3 => unreachable!(),
    };
    let mut info_bytes = vec![0u8; info_size];
    file.read_exact(&mut info_bytes)?;

    if header.encryption_flags.encrypt_record_blocks {
        if let Some(ref key) = header.master_key {
            debug!("Decrypting key block info (Salsa20)");
            crypto::salsa_decrypt(&mut info_bytes, key);
        } else {
            return Err(MdictError::PasscodeRequired);
        }
    }

    if header.version == MdictVersion::V2 {
        let checksum_expected = file.read_u32::<BigEndian>()?;
        let checksum_actual = adler32_slice(&info_bytes);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }

    let mut reader = info_bytes.as_slice();
    let num_blocks = utils::read_number(&mut reader, header.version.number_width())?;
    let num_entries = utils::read_number(&mut reader, header.version.number_width())?;
    let key_index_decomp_len = if header.version == MdictVersion::V2 {
        Some(utils::read_number(&mut reader, header.version.number_width())?)
    } else {
        None
    };
    let key_index_comp_len = utils::read_number(&mut reader, header.version.number_width())?;
    let _key_blocks_len = utils::read_number(&mut reader, header.version.number_width())?;

    info!(
        "Key block info: blocks={}, entries={}, index_compressed={} bytes",
        num_blocks, num_entries, key_index_comp_len
    );

    let mut compressed = vec![0u8; key_index_comp_len as usize];
    file.read_exact(&mut compressed)?;
    let index_data = decompress_key_index(&compressed, key_index_decomp_len, header)?;

    Ok((index_data, num_blocks, num_entries))
}

/// Parses the record block index header and data.
fn parse_record_block_index<R: Seek + Read>(
    file: &mut R,
    header: &MdictHeader,
) -> Result<(Vec<u8>, u64, u64)> {
    let num_blocks = utils::read_number(file, header.version.number_width())?;
    let num_entries = utils::read_number(file, header.version.number_width())?;
    let record_index_len = utils::read_number(file, header.version.number_width())?;
    let _record_blocks_len = utils::read_number(file, header.version.number_width())?;

    let mut index_data_mut = vec![0u8; record_index_len as usize];
    file.read_exact(&mut index_data_mut)?;
    Ok((index_data_mut, num_blocks, num_entries))
}

/// Decompress the raw key index block.
fn decompress_key_index(
    compressed: &[u8],
    decomp_len: Option<u64>,
    header: &MdictHeader,
) -> Result<Vec<u8>> {
    if let Some(decomp_len) = decomp_len {
        debug!(
            "Processing v2.x key index (compressed: {} bytes, decompressed: {} bytes)",
            compressed.len(), decomp_len
        );
        
        let payload = if header.encryption_flags.encrypt_key_index {
            debug!("Decrypting key index (fast decrypt with checksum-derived key)");
            let key = crypto::derive_key_for_v2_index(compressed);
            let mut decrypted = compressed[8..].to_vec();
            crypto::fast_decrypt(&mut decrypted, &key);
            decrypted
        } else {
            compressed[8..].to_vec()
        };

        let compression_type = CompressionType::try_from(LittleEndian::read_u32(&compressed[0..4]) as u8)?;
        debug!("Decompressing key index using {:?}", compression_type);
        let decompressed =
            compression::decompress_payload(&payload, compression_type, decomp_len)?;

        let checksum_expected = BigEndian::read_u32(&compressed[4..8]);
        let checksum_actual = adler32_slice(decompressed.as_slice());
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
        debug!("Key index parsed successfully: {} bytes", decompressed.len());
        Ok(decompressed)
    } else {
        debug!("Processing v1.x key index ({} bytes, uncompressed)", compressed.len());
        Ok(compressed.to_vec())
    }
}
