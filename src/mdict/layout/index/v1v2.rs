//! Index parser for MDict format versions 1.x and 2.x.
//!
//! This module handles parsing of key and record block indexes for v1/v2 files.
//! The format structure:
//! 1. Key block info (encrypted if enabled, with checksum for v2)
//! 2. Key block index (compressed, optionally encrypted)
//! 3. Key blocks (actual data)
//! 4. Record block info (unencrypted)
//! 5. Record block index (unencrypted)
//! 6. Record blocks (actual data)

use adler2::adler32_slice;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use log::{debug, info};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::ParseResult;
use super::common;
use crate::mdict::{
    codec::{compression, crypto},
    types::{
        error::{MdictError, Result},
        models::{
            BlockMeta, BlockType, CompressionType, EncryptionFlags, MasterKey, MdictEncoding,
            MdictVersion,
        },
    },
    utils,
};

/// Parses the complete index structure for v1/v2 MDict files.
///
/// This is the entry point for v1/v2 index parsing. It sequentially processes:
/// 1. Key block metadata (locations, sizes, entry counts)
/// 2. Record block metadata (locations, sizes)
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
    encryption_flags: EncryptionFlags,
    master_key: MasterKey,
) -> Result<ParseResult> {
    // Parse key block index
    let (key_blocks, num_entries) = parse_block_info(
        file,
        version,
        encoding,
        encryption_flags,
        master_key,
        BlockType::Key,
    )?;

    // Skip past all key block data to reach record section
    let total_key_blocks_size: u64 = key_blocks.iter().map(|b| b.compressed_size).sum();
    file.seek(SeekFrom::Current(total_key_blocks_size as i64))?;

    // Parse record block index
    let (record_blocks, _) = parse_block_info(
        file,
        version,
        encoding,
        encryption_flags,
        master_key,
        BlockType::Record,
    )?;

    let total_record_decomp_size: u64 = record_blocks.iter().map(|b| b.decompressed_size).sum();

    info!(
        "MDict file opened: {} key blocks, {} record blocks",
        key_blocks.len(),
        record_blocks.len()
    );

    Ok((
        key_blocks,
        record_blocks,
        total_record_decomp_size,
        num_entries,
    ))
}

/// Parses block metadata for either key or record blocks.
///
/// This generic function handles both key and record block parsing by:
/// 1. Reading and decrypting the index header
/// 2. Decompressing the index data (key blocks only)
/// 3. Extracting individual block metadata from the index
/// 4. Validating counts against expected values
///
/// # Parameters
/// - `file`: File handle positioned at the start of the block info section
/// - `header`: MDict header with version and encryption settings
/// - `block_type`: Whether parsing key or record blocks
///
/// # Returns
/// A tuple of (block metadata vector, total entry count)
fn parse_block_info<R: Seek + Read>(
    file: &mut R,
    version: MdictVersion,
    encoding: MdictEncoding,
    encryption_flags: EncryptionFlags,
    master_key: MasterKey,
    block_type: BlockType,
) -> Result<(Vec<BlockMeta>, u64)> {
    info!("Parsing {} block info section", block_type);

    // Read and decompress the appropriate index
    let (index_data, num_blocks, num_entries) = if block_type == BlockType::Key {
        parse_key_block_index(file, version, encryption_flags, master_key)?
    } else {
        parse_record_block_index(file, version)?
    };

    // Extract individual block metadata from the decompressed index
    info!("Extracting block boundaries from {} index", block_type);
    let initial_file_offset = file.stream_position()?;
    let (blocks, total_entries) = extract_block_metas(
        &index_data,
        version,
        encoding,
        block_type,
        initial_file_offset,
    )?;

    // Validate block count matches the index header
    if blocks.len() as u64 != num_blocks {
        return Err(MdictError::CountMismatch {
            item_type: format!("{} blocks in index", block_type),
            expected: num_blocks,
            found: blocks.len() as u64,
        });
    }

    // Validate entry count for key blocks
    if block_type == BlockType::Key && total_entries != num_entries {
        return Err(MdictError::CountMismatch {
            item_type: "key entries in index".to_string(),
            expected: num_entries,
            found: total_entries,
        });
    }

    info!(
        "{} index metadata: {} blocks defined",
        block_type,
        blocks.len()
    );
    Ok((blocks, num_entries))
}

/// Extracts individual block metadata entries from decompressed index data.
///
/// Iterates through the index buffer, reading metadata for each block:
/// - For key blocks: entry count, first key, last key, sizes
/// - For record blocks: only sizes
///
/// # Returns
/// A tuple of (block metadata vector, total entry count across all blocks)
fn extract_block_metas(
    index_data: &[u8],
    version: MdictVersion,
    encoding: MdictEncoding,
    block_type: BlockType,
    initial_file_offset: u64,
) -> Result<(Vec<BlockMeta>, u64)> {
    let mut blocks = Vec::new();
    let mut reader = index_data;
    let mut total_entries = 0u64;
    let mut file_offset = initial_file_offset;
    let mut decompressed_offset: u64 = 0;

    // Process each block's metadata entry
    while !reader.is_empty() {
        // Key blocks include entry count and key range
        if block_type == BlockType::Key {
            let num_entries_in_block = utils::read_number(&mut reader, version.number_width())?;
            total_entries += num_entries_in_block;

            // Skip first and last key texts (boundary keys used for range queries, not needed for sequential access)
            common::skip_text(&mut reader, version, encoding)?;
            common::skip_text(&mut reader, version, encoding)?;
        }

        // Read block size information (present for both key and record blocks)
        let compressed_size = utils::read_number(&mut reader, version.number_width())?;
        let decompressed_size = utils::read_number(&mut reader, version.number_width())?;

        blocks.push(BlockMeta {
            compressed_size,
            decompressed_size,
            file_offset,
            decompressed_offset,
        });

        // Advance offsets for next block
        file_offset += compressed_size;
        decompressed_offset += decompressed_size;
    }

    Ok((blocks, total_entries))
}

/// Parses the key block index header and decompresses the index data.
///
/// Key block index structure:
/// - Info block (encrypted if flag set, checksummed in v2)
/// - Compressed index data (encrypted in v2 if flag set)
///
/// # Returns
/// A tuple of (decompressed index data, block count, entry count)
fn parse_key_block_index<R: Seek + Read>(
    file: &mut R,
    version: MdictVersion,
    encryption_flags: EncryptionFlags,
    master_key: MasterKey,
) -> Result<(Vec<u8>, u64, u64)> {
    // Read the info block (fixed size based on version)
    let info_size = match version {
        MdictVersion::V1 => 16, // 4 fields × 4 bytes each
        MdictVersion::V2 => 40, // 5 fields × 8 bytes each
        MdictVersion::V3 => unreachable!(),
    };
    let mut info_bytes = vec![0u8; info_size];
    file.read_exact(&mut info_bytes)?;

    // Decrypt info block if encryption is enabled
    if encryption_flags.encrypt_record_blocks {
        if let Some(key) = master_key {
            debug!("Decrypting key block info (Salsa20)");
            crypto::salsa_decrypt(&mut info_bytes, &key);
        } else {
            return Err(MdictError::PasscodeRequired);
        }
    }

    // V2 includes an Adler32 checksum after the info block
    if version == MdictVersion::V2 {
        let checksum_expected = file.read_u32::<BigEndian>()?;
        let checksum_actual = adler32_slice(&info_bytes);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }

    // Parse the info block fields
    let mut reader = info_bytes.as_slice();
    let num_blocks = utils::read_number(&mut reader, version.number_width())?;
    let num_entries = utils::read_number(&mut reader, version.number_width())?;
    let key_index_decomp_len = if version == MdictVersion::V2 {
        Some(utils::read_number(&mut reader, version.number_width())?)
    } else {
        None
    };
    let key_index_comp_len = utils::read_number(&mut reader, version.number_width())?;
    let _key_blocks_len = utils::read_number(&mut reader, version.number_width())?;

    info!(
        "Key block info: blocks={}, entries={}, index_compressed={} bytes",
        num_blocks, num_entries, key_index_comp_len
    );

    // Read and decompress the key index data
    let mut compressed = vec![0u8; key_index_comp_len as usize];
    file.read_exact(&mut compressed)?;
    let index_data = decompress_key_index(&mut compressed, key_index_decomp_len, encryption_flags)?;

    Ok((index_data, num_blocks, num_entries))
}

/// Parses the record block index header and reads the index data.
///
/// Record block index is simpler than key block:
/// - No encryption
/// - No compression
/// - No checksums
///
/// # Returns
/// A tuple of (index data, block count, entry count)
fn parse_record_block_index<R: Seek + Read>(
    file: &mut R,
    version: MdictVersion,
) -> Result<(Vec<u8>, u64, u64)> {
    let num_blocks = utils::read_number(file, version.number_width())?;
    let num_entries = utils::read_number(file, version.number_width())?;
    let record_index_len = utils::read_number(file, version.number_width())?;
    let _record_blocks_len = utils::read_number(file, version.number_width())?;

    let mut index_data_mut = vec![0u8; record_index_len as usize];
    file.read_exact(&mut index_data_mut)?;
    Ok((index_data_mut, num_blocks, num_entries))
}

/// Decompresses and validates the key index block.
///
/// For v2:
/// - Decrypts if encryption flag is set
/// - Decompresses using specified algorithm
/// - Verifies Adler32 checksum
///
/// For v1:
/// - Returns data as-is (uncompressed)
///
/// # Parameters
/// - `compressed`: Raw compressed index data
/// - `decomp_len`: Expected decompressed length (None for v1)
/// - `header`: MDict header with encryption settings
fn decompress_key_index(
    compressed: &mut [u8],
    decomp_len: Option<u64>,
    encryption_flags: EncryptionFlags,
) -> Result<Vec<u8>> {
    // V2 uses compression with checksum verification
    if let Some(decomp_len) = decomp_len {
        debug!(
            "Processing v2.x key index (compressed: {} bytes, decompressed: {} bytes)",
            compressed.len(),
            decomp_len
        );

        // Decrypt if key index encryption is enabled
        let payload_start = 8;
        if encryption_flags.encrypt_key_index {
            debug!("Decrypting key index (fast decrypt with checksum-derived key)");
            let key = crypto::derive_key_for_v2_index(compressed);
            let payload_slice = &mut compressed[payload_start..];
            crypto::fast_decrypt(payload_slice, &key);
        }
        let payload = &compressed[payload_start..];

        // Read compression type from header and decompress
        let compression_type =
            CompressionType::try_from(LittleEndian::read_u32(&compressed[0..4]) as u8)?;
        debug!("Decompressing key index using {:?}", compression_type);
        let mut decompressed = Vec::new();
        compression::decompress_payload_into(
            &mut decompressed,
            payload,
            compression_type,
            decomp_len,
        )?;

        // Verify checksum to ensure data integrity
        let checksum_expected = BigEndian::read_u32(&compressed[4..8]);
        let checksum_actual = adler32_slice(decompressed.as_slice());
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
        debug!(
            "Key index parsed successfully: {} bytes",
            decompressed.len()
        );
        Ok(decompressed)
    } else {
        // V1 does not compress the key index
        debug!(
            "Processing v1.x key index ({} bytes, uncompressed)",
            compressed.len()
        );
        Ok(compressed.to_vec())
    }
}
