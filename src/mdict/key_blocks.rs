//! Key block parsing (index and blocks containing key entries)

use std::fs::File;
use std::io::{Read, Cursor};
use byteorder::{BigEndian, LittleEndian, ByteOrder, ReadBytesExt};
use adler32::adler32;
use super::models::{MdictHeader, MdictVersion, KeyBlockInfo, KeyBlock, KeyEntry, CompressionType};
use super::{utils, crypto, decoder};
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
/// (no checksum)
/// 
/// If encrypted, entire block is Salsa20-encrypted.
pub fn parse_info(file: &mut File, header: &MdictHeader) -> Result<KeyBlockInfo> {
    println!("=== Parsing Key Block Info ===");
    
    let info_size = match header.version {
        MdictVersion::V1 => 16,
        MdictVersion::V2 => 40,
    };
    let mut info_bytes = vec![0u8; info_size];
    file.read_exact(&mut info_bytes)?;
    
    // Decrypt if master key present
    if let Some(ref key) = header.master_key {
        crypto::salsa_decrypt(&mut info_bytes, key);
    }
    
    // Verify checksum (v2.0+ only)
    if header.version == MdictVersion::V2 {
        let checksum_expected = file.read_u32::<BigEndian>()?;
        let checksum_actual = adler32(&info_bytes[..])?;
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }
    
    // Parse fields
    let mut reader = &info_bytes[..];
    let num_key_blocks = utils::read_number(&mut reader, header.version.number_width())?;
    let num_entries = utils::read_number(&mut reader, header.version.number_width())?;
    let key_index_decomp_len = match header.version {
        MdictVersion::V1 => None,
        MdictVersion::V2 => Some(utils::read_number(&mut reader, header.version.number_width())?),
    };
    let key_index_comp_len = utils::read_number(&mut reader, header.version.number_width())?;
    let key_blocks_len = utils::read_number(&mut reader, header.version.number_width())?;
    
    println!("Key block info: {} blocks, {} entries", num_key_blocks, num_entries);
    
    Ok(KeyBlockInfo {
        num_key_blocks,
        num_entries,
        key_index_decomp_len,
        key_index_comp_len,
        key_blocks_len,
    })
}

/// Parse key index (metadata about each key block).
/// 
/// v2.0+ format:
/// - 4 bytes: Compression type
/// - 4 bytes: Adler32 checksum (of decompressed data)
/// - N bytes: Encrypted/compressed payload
/// 
/// v1.x format:
/// - N bytes: Raw uncompressed data
pub fn parse_index(
    file: &mut File,
    info: &KeyBlockInfo,
    header: &MdictHeader,
) -> Result<Vec<u8>> {
    println!("=== Parsing Key Index ===");
    
    let mut compressed = vec![0u8; info.key_index_comp_len as usize];
    file.read_exact(&mut compressed)?;
    
    let decompressed = if let Some(decomp_len) = info.key_index_decomp_len {
        // v2.0+ path: may be encrypted and/or compressed
        let payload = if header.encryption_flags.encrypt_key_index {
            // Decrypt using key derived from block checksum
            let key = crypto::derive_key_for_v2_index(&compressed);
            let mut decrypted = compressed[8..].to_vec();
            crypto::fast_decrypt(&mut decrypted, &key);
            decrypted
        } else {
            compressed[8..].to_vec()
        };
        
        // Decompress
        let compression_type = CompressionType::try_from(LittleEndian::read_u32(&compressed[0..4]) as u8)?;
        let decompressed = super::compression::decompress_payload(
            &payload,
            compression_type,
            decomp_len,
        )?;
        
        // Verify checksum
        let checksum_expected = BigEndian::read_u32(&compressed[4..8]);
        let checksum_actual = adler32(&decompressed[..])?;
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
        
        decompressed
    } else {
        // v1.x path: raw uncompressed data
        compressed
    };
    
    println!("Key index parsed: {} bytes", decompressed.len());
    Ok(decompressed)
}

/// Parse key index metadata to extract key block boundaries.
/// 
/// Each entry in the index describes one key block:
/// - Number of entries in this block
/// - First key text (length-prefixed string)
/// - Last key text (length-prefixed string)
/// - Compressed size
/// - Decompressed size
pub fn parse_index_metadata(
    index_data: &[u8],
    header: &MdictHeader,
    info: &KeyBlockInfo,
) -> Result<Vec<KeyBlock>> {
    println!("=== Parsing Key Index Metadata ===");
    
    let mut blocks = Vec::new();
    let mut reader = index_data;
    let mut total_entries = 0u64;
    
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
        
        blocks.push(KeyBlock {
            compressed_size,
            decompressed_size,
        });
    }
    
    // Verify total entry count matches
    if total_entries != info.num_entries {
        return Err(MdictError::CountMismatch {
            item_type: "key entries in index",
            expected: info.num_entries,
            found: total_entries,
        });
    }
    
    println!("Key index metadata: {} key blocks", blocks.len());
    Ok(blocks)
}

/// Parse all key blocks to extract key entries.
/// 
/// Each block is decoded (decrypted + decompressed), then parsed to extract
/// individual key entries.
pub fn parse_blocks(
    file: &mut File,
    info: &KeyBlockInfo,
    blocks: &[KeyBlock],
    header: &MdictHeader,
) -> Result<Vec<KeyEntry>> {
    println!("=== Parsing Key Blocks ===");
    
    // Read all key block data at once
    let mut all_blocks_data = vec![0u8; info.key_blocks_len as usize];
    file.read_exact(&mut all_blocks_data)?;
    let mut cursor = Cursor::new(all_blocks_data);
    
    let mut key_entries = Vec::new();
    
    for block_meta in blocks {
        // Read one compressed block
        let mut compressed = vec![0u8; block_meta.compressed_size as usize];
        cursor.read_exact(&mut compressed)?;
        
        // Decode block (decrypt + decompress + verify)
        let decompressed = decoder::decode_block(
            &compressed,
            block_meta.decompressed_size,
            header.master_key.as_ref(),
        )?;
        
        // Parse entries from decompressed data
        let mut block_reader = &decompressed[..];
        while !block_reader.is_empty() {
            let record_id = utils::read_number(&mut block_reader, header.version.number_width())?;
            let text = read_null_terminated_string(&mut block_reader, header.encoding)?;
            key_entries.push(KeyEntry {
                id: record_id,
                text,
            });
        }
    }
    
    if key_entries.len() as u64 != info.num_entries {
        return Err(MdictError::CountMismatch {
            item_type: "parsed key entries",
            expected: info.num_entries,
            found: key_entries.len() as u64,
        });
    }
    
    println!("Key blocks parsed: {} entries", key_entries.len());
    Ok(key_entries)
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
    let terminator = vec![0u8; width];
    
    // Find null terminator
    let end_pos = reader
        .windows(width)
        .position(|w| w == terminator.as_slice())
        .ok_or_else(|| MdictError::InvalidFormat("Missing null terminator in string".to_string()))?;
    
    // Decode text
    let text_bytes = &reader[..end_pos];
    let (decoded, _, _) = encoding.decode(text_bytes);
    
    // Advance reader past text and terminator
    *reader = &reader[end_pos + width..];
    
    Ok(decoded.into_owned())
}
