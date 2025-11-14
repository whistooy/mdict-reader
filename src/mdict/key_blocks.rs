//! Key block parsing (index and blocks containing key entries)

use std::io::{Read, Seek};
use byteorder::{BigEndian, LittleEndian, ByteOrder, ReadBytesExt};
use adler32::adler32;
use log::{debug, info, trace};
use super::models::{MdictHeader, MdictVersion, KeyBlockInfo, KeyEntry, CompressionType, BlockMeta};
use super::{utils, crypto, blocks};
use super::error::{Result, MdictError};

/// Parse key block info section.
/// 
/// Structure (v2.0+):
/// - 8 bytes: Number of key blocks
/// - 8 bytes: Number of entries
/// - 8 bytes: Key index decompressed length
/// - 8 bytes: Key index compressed length
/// - 8 bytes: Key blocks total length
/// - 4 bytes: Adler32 checksum
/// 
/// Structure (v1.x):
/// - 4 bytes: Number of key blocks
/// - 4 bytes: Number of entries
/// - 4 bytes: Key index compressed length
/// - 4 bytes: Key blocks total length
/// - (no checksum)
/// 
/// If encrypted, entire block is Salsa20-encrypted.
pub fn parse_info<R: Read>(
    file: &mut R,
    header: &MdictHeader
) -> Result<KeyBlockInfo> {
    info!("Parsing key block info section");

    let info_size = match header.version {
        MdictVersion::V1 => 16,
        MdictVersion::V2 => 40,
    };
    let mut info_bytes = vec![0u8; info_size];
    file.read_exact(&mut info_bytes)?;

    // Check if decryption is needed
    if header.encryption_flags.encrypt_record_blocks {
        if let Some(ref key) = header.master_key {
            debug!("Decrypting key block info (Salsa20)");
            crypto::salsa_decrypt(&mut info_bytes, key);
        } else {
            // No key available, but one is required. Fail now.
            return Err(MdictError::PasscodeRequired);
        }
    }

    // Verify checksum (v2.0+ only)
    if header.version == MdictVersion::V2 {
        let checksum_expected = file.read_u32::<BigEndian>()?;
        let checksum_actual = adler32(info_bytes.as_slice())?;
        trace!("Key block info checksum: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }

    // Parse fields
    let mut reader = info_bytes.as_slice();
    let num_key_blocks = utils::read_number(&mut reader, header.version.number_width())?;
    let num_entries = utils::read_number(&mut reader, header.version.number_width())?;
    let key_index_decomp_len = match header.version {
        MdictVersion::V1 => None,
        MdictVersion::V2 => Some(utils::read_number(&mut reader, header.version.number_width())?),
    };
    let key_index_comp_len = utils::read_number(&mut reader, header.version.number_width())?;
    let key_blocks_len = utils::read_number(&mut reader, header.version.number_width())?;

    info!(
        "Key block info: blocks={}, entries={}, index_compressed={} bytes, data={}  bytes",
        num_key_blocks, num_entries, key_index_comp_len, key_blocks_len
    );

    Ok(KeyBlockInfo {
        num_key_blocks,
        num_entries,
        key_index_decomp_len,
        key_index_comp_len,
        key_blocks_len,
    })
}

/// Decompress the raw key index block.
/// 
/// This function handles decryption and decompression but does not parse the
/// content of the index.
/// 
/// v2.0+ format:
/// - 4 bytes: Compression type
/// - 4 bytes: Adler32 checksum (of decompressed data)
/// - N bytes: Encrypted/compressed payload
/// 
/// v1.x format:
/// - N bytes: Raw uncompressed data
fn decompress_index(
    compressed: &[u8],
    info: &KeyBlockInfo,
    header: &MdictHeader,
) -> Result<Vec<u8>> {
    if let Some(decomp_len) = info.key_index_decomp_len {
        // v2.0+ path: may be encrypted and/or compressed
        debug!(
            "Processing v2.x key index (compressed: {} bytes, decompressed: {} bytes)",
            info.key_index_comp_len, decomp_len
        );
        
        let payload = if header.encryption_flags.encrypt_key_index {
            // Decrypt using key derived from block checksum
            debug!("Decrypting key index (fast decrypt with checksum-derived key)");
            let key = crypto::derive_key_for_v2_index(compressed);
            let mut decrypted = compressed[8..].to_vec();
            crypto::fast_decrypt(&mut decrypted, &key);
            decrypted
        } else {
            compressed[8..].to_vec()
        };

        // Decompress
        let compression_type = CompressionType::try_from(LittleEndian::read_u32(&compressed[0..4]) as u8)?;
        debug!("Decompressing key index using {:?}", compression_type);
        let decompressed = super::compression::decompress_payload(
            &payload,
            compression_type,
            decomp_len,
        )?;

        // Verify checksum
        let checksum_expected = BigEndian::read_u32(&compressed[4..8]);
        let checksum_actual = adler32(decompressed.as_slice())?;
        trace!("Key index checksum: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
        debug!("Key index parsed successfully: {} bytes", decompressed.len());
        Ok(decompressed)
    } else {
        // v1.x path: raw uncompressed data
        debug!("Processing v1.x key index ({} bytes, uncompressed)", info.key_index_comp_len);
        Ok(compressed.to_vec())
    }
}

/// Reads the key index from the file, decompresses it, and parses it to
/// extract metadata for each key block.
/// 
/// Each entry in the decompressed index describes one key block:
/// - Number of entries in this block
/// - First key text (length-prefixed string)
/// - Last key text (length-prefixed string)
/// - Compressed size
/// - Decompressed size
pub fn parse_index<R: Seek + Read>(
    file: &mut R,
    info: &KeyBlockInfo,
    header: &MdictHeader,
) -> Result<Vec<BlockMeta>> {
    info!("Parsing key index");

    let mut compressed = vec![0u8; info.key_index_comp_len as usize];
    file.read_exact(&mut compressed)?;

    let index_data = decompress_index(compressed.as_slice(), info, header)?;
    
    info!("Extracting block boundaries from key index");
    let mut blocks = Vec::with_capacity(info.num_key_blocks as usize);
    let mut reader = index_data.as_slice();
    let mut total_entries = 0u64;
    let mut file_offset = file.stream_position()?;
    let mut decompressed_offset: u64 = 0;

    while !reader.is_empty() {
        // Number of entries in this block
        let num_entries = utils::read_number(&mut reader, header.version.number_width())?;
        total_entries += num_entries;

        // Skip first and last key text (we don't need them)
        skip_key_text(&mut reader, header)?;
        skip_key_text(&mut reader, header)?;

        // Block sizes
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
    if blocks.len() as u64 != info.num_key_blocks {
        return Err(MdictError::CountMismatch {
            item_type: "key blocks in index",
            expected: info.num_key_blocks,
            found: blocks.len() as u64,
        });
    }

    // Verify total entry count
    if total_entries != info.num_entries {
        return Err(MdictError::CountMismatch {
            item_type: "key entries in index",
            expected: info.num_entries,
            found: total_entries,
        });
    }

    info!("Key index metadata: {} key blocks defined", blocks.len());
    Ok(blocks)
}

/// Decode a specific key block and parse its entries.
pub fn decode_and_parse_block<R: Seek + Read>(
    file: &mut R,
    block_meta: &BlockMeta,
    header: &MdictHeader,
) -> Result<Vec<KeyEntry>> {
    let decompressed_data = blocks::decode_block(file, block_meta, header)?;
    parse_entries(&decompressed_data, header)
}

/// Parse key entries from decompressed data.
fn parse_entries(data: &[u8], header: &MdictHeader) -> Result<Vec<KeyEntry>> {
    let mut entries = Vec::new();
    let mut reader = data;
    
    while !reader.is_empty() {
        let record_id = utils::read_number(&mut reader, header.version.number_width())?;
        let text = read_null_terminated_string(&mut reader, header.encoding)?;
        entries.push(KeyEntry { id: record_id, text });
    }
    
    Ok(entries)
}

// --- Format-specific helper functions ---

/// Skip over a length-prefixed key text without decoding it.
/// 
/// MDict format stores text as:
/// - v1.x: 1-byte length + text (no terminator)
/// - v2.x: 2-byte length + text + terminator (1 or 2 bytes)
fn skip_key_text(reader: &mut &[u8], header: &MdictHeader) -> Result<()> {
    // Read text length in "units" (1 unit = 1 byte for UTF-8, 2 bytes for UTF-16)
    let text_len_units = utils::read_small_number(reader, header.version.small_number_width())?;

    // v2.x has a terminator (1 unit)
    let terminator_units = match header.version {
        MdictVersion::V1 => 0,
        MdictVersion::V2 => 1,
    };

    // Calculate total bytes to skip
    let total_bytes = ((text_len_units + terminator_units) as usize) * utils::unit_width(header.encoding);

    if reader.len() < total_bytes {
        return Err(MdictError::InvalidFormat("Incomplete key text in index".to_string()));
    }

    *reader = &reader[total_bytes..];
    Ok(())
}

/// Read a null-terminated string from a byte slice and advance the slice.
/// 
/// This is MDict-format-specific: strings in key blocks are null-terminated
/// rather than length-prefixed. UTF-16 uses 2-byte null, others use 1-byte.
fn read_null_terminated_string(
    reader: &mut &[u8],
    encoding: &'static encoding_rs::Encoding,
) -> Result<String> {
    let width = utils::unit_width(encoding);
    let end_pos = if width == 2 {
        // Find the index of the null terminator chunk...
        reader
            .chunks_exact(2)
            .position(|chunk| chunk == [0, 0])
            // ...then map that chunk index to the final byte position.
            .map(|chunk_index| chunk_index * 2)
    } else {
        // Find the position of the null terminator byte directly.
        reader
            .iter()
            .position(|&byte| byte == 0)
    }
    .ok_or_else(|| MdictError::InvalidFormat("Missing null terminator in string".to_string()))?;
    
    // Decode text from the bytes before the terminator
    let text_bytes = &reader[..end_pos];
    let (decoded, _, _) = encoding.decode(text_bytes);
    
    // Advance reader past the text AND the terminator
    *reader = &reader[end_pos + width..];
    
    Ok(decoded.into_owned())
}