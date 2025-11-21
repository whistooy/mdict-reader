//! # Block Content Parsing & Decoding
//!
//! This module is responsible for taking a raw, on-disk block and turning it
//! into structured data (key entries or a record definition). It sits between
//! the high-level `reader` (which handles I/O) and the low-level `codec`
//! (which handles pure data transformation).
//!
//! ## Responsibilities
//! 1.  **Parse Block Header**: Reads the 8-byte header to determine compression,
//!     encryption, and checksum information.
//! 2.  **Decode Payload**: Orchestrates decryption and decompression by calling
//!     the `codec` module.
//! 3.  **Verify Checksum**: Validates the block's integrity.
//! 4.  **Parse Entries**: Parses the decompressed data into `KeyEntry` structs.
//! 5.  **Extract Record**: Extracts a record definition from a decompressed block.

use std::cmp::min;
use adler2::adler32_slice;
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use log::trace;
use ripemd::{Digest, Ripemd128};

use crate::mdict::codec::{compression, crypto};
use crate::mdict::types::error::{MdictError, Result};
use crate::mdict::types::filetypes::FileType;
use crate::mdict::types::models::*;
use crate::mdict::utils;

/// Decodes a raw, compressed/encrypted block payload.
pub fn decode_block(
    raw_block: &mut [u8],
    expected_decompressed_size: u64,
    master_key: Option<&[u8; 16]>,
    version: MdictVersion,
) -> Result<Vec<u8>> {
    if raw_block.len() < 8 {
        return Err(MdictError::InvalidFormat("Block too short (minimum 8 bytes required)".to_string()));
    }

    // Parse block header
    let info = LittleEndian::read_u32(&raw_block[0..4]);
    let compression_type = CompressionType::try_from((info & 0xF) as u8)?;
    let encryption_type = EncryptionType::try_from(((info >> 4) & 0xF) as u8)?;
    let encryption_size = ((info >> 8) & 0xFF) as usize;
    let checksum_expected = BigEndian::read_u32(&raw_block[4..8]);

    trace!(
        "Decoding block: compression={:?}, encryption={:?}, expected_size={} bytes",
        compression_type, encryption_type, expected_decompressed_size
    );

    let decryption_key: [u8; 16] = match master_key {
        Some(key) => {
            trace!("Using master key for decryption");
            *key
        }
        None => {
            trace!("Deriving decryption key from block checksum");
            let mut hasher = Ripemd128::new();
            hasher.update(&raw_block[4..8]);
            hasher.finalize().into()
        }
    };

    let payload = &mut raw_block[8..];

    let decrypt_len = min(encryption_size, payload.len());
    crypto::decrypt_payload_in_place(
        &mut payload[..decrypt_len],
        encryption_type,
        &decryption_key,
    );

    if version == MdictVersion::V3 {
        let checksum_actual = adler32_slice(payload);
        trace!("V3 block checksum on decrypted data: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }

    let decompressed = compression::decompress_payload(
        payload,
        compression_type,
        expected_decompressed_size,
    )?;

    if version != MdictVersion::V3 {
        let checksum_actual = adler32_slice(decompressed.as_slice());
        trace!("V1/V2 block checksum on decrypted data: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }

    Ok(decompressed)
}

/// Parses key entries from a decompressed data block.
pub fn parse_key_entries(data: &[u8], header: &MdictHeader) -> Result<Vec<KeyEntry>> {
    let mut entries = Vec::new();
    let mut reader = data;
    
    while !reader.is_empty() {
        let record_id = utils::read_number(&mut reader, header.version.number_width())?;
        let text = read_null_terminated_string(&mut reader, header.encoding)?;
        entries.push(KeyEntry { id: record_id, text });
    }
    
    Ok(entries)
}

/// Extracts and processes a record from a pre-loaded, decompressed block.
pub fn parse_record<T: FileType>(
    block_bytes: &[u8],
    info: &RecordInfo,
    header: &MdictHeader,
) -> Result<T::Record> {
    let start = info.offset_in_block as usize;
    let end = start + info.size as usize;
    if end > block_bytes.len() {
        return Err(MdictError::InvalidFormat(format!(
            "Record location [{}..{}] is out of bounds for block of size {}",
            start, end, block_bytes.len()
        )));
    }
    
    let record_slice = &block_bytes[start..end];
    T::process_record(record_slice, header)
}

/// Reads a null-terminated string from a byte slice and advances the slice.
fn read_null_terminated_string(
    reader: &mut &[u8],
    encoding: &'static encoding_rs::Encoding,
) -> Result<String> {
    let width = utils::unit_width(encoding);
    let end_pos = if width == 2 {
        reader
            .chunks_exact(2)
            .position(|chunk| chunk == [0, 0])
            .map(|chunk_index| chunk_index * 2)
    } else {
        reader
            .iter()
            .position(|&byte| byte == 0)
    }
    .ok_or_else(|| MdictError::InvalidFormat("Missing null terminator in string".to_string()))?;
    
    let text_bytes = &reader[..end_pos];
    let (decoded, _, _) = encoding.decode(text_bytes);
    
    *reader = &reader[end_pos + width..];
    
    Ok(decoded.into_owned())
}
