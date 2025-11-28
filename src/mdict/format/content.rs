//! Block content parsing, decoding, and validation.
//!
//! This module bridges the gap between raw file data and structured records:
//! - Decrypts and decompresses data blocks
//! - Validates block checksums
//! - Parses key entries from index blocks
//! - Extracts individual records from decompressed data
//!
//! # Architecture Position
//! ```text
//! Reader (I/O) → Content (this module) → Codec (crypto/compression)
//! ```

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

/// Decodes a raw block: decrypts, decompresses, and validates.
///
/// # Block Header Format (8 bytes)
/// ```text
/// [0-3] Compression & encryption info (little-endian u32)
///       - Bits 0-3: Compression type
///       - Bits 4-7: Encryption type
///       - Bits 8-15: Encryption size
/// [4-7] Adler32 checksum (big-endian u32)
/// ```
///
/// # Parameters
/// * `raw_block` - Complete block including 8-byte header
/// * `expected_decompressed_size` - Expected size after decompression
/// * `master_key` - Optional decryption key (None for unencrypted files)
/// * `version` - MDict version (affects checksum timing)
///
/// # Returns
/// Fully decoded block data ready for parsing.
pub fn decode_block_into(
    output: &mut Vec<u8>,
    raw_block: &mut [u8],
    expected_decompressed_size: u64,
    master_key: Option<&[u8; 16]>,
    version: MdictVersion,
) -> Result<()> {
    if raw_block.len() < 8 {
        return Err(MdictError::InvalidFormat("Block too short (minimum 8 bytes required)".to_string()));
    }

    // Step 1: Parse 8-byte block header
    let info = LittleEndian::read_u32(&raw_block[0..4]);
    let compression_type = CompressionType::try_from((info & 0xF) as u8)?;
    let encryption_type = EncryptionType::try_from(((info >> 4) & 0xF) as u8)?;
    let encryption_size = ((info >> 8) & 0xFF) as usize;
    let checksum_expected = BigEndian::read_u32(&raw_block[4..8]);

    trace!(
        "Decoding block: compression={:?}, encryption={:?}, expected_size={} bytes",
        compression_type, encryption_type, expected_decompressed_size
    );

    // Step 2: Determine decryption key
    let decryption_key: [u8; 16] = match master_key {
        Some(key) => {
            trace!("Using master key from file header");
            *key
        }
        None => {
            trace!("Deriving ephemeral key from block checksum");
            let mut hasher = Ripemd128::new();
            hasher.update(&raw_block[4..8]);
            hasher.finalize().into()
        }
    };

    // Step 3: Decrypt payload (skip 8-byte header)
    let payload = &mut raw_block[8..];

    let decrypt_len = min(encryption_size, payload.len());
    crypto::decrypt_payload_in_place(
        &mut payload[..decrypt_len],
        encryption_type,
        &decryption_key,
    );

    // Step 4: Validate checksum (v3 before decompression, v1/v2 after)
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

    // Step 5: Decompress payload
    compression::decompress_payload_into(
        output,
        payload,
        compression_type,
        expected_decompressed_size,
    )?;

    if version != MdictVersion::V3 {
        let checksum_actual = adler32_slice(output.as_slice());
        trace!("V1/V2 block checksum on decrypted data: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }

    Ok(())
}

/// Reads a single key entry from a key block stream.
///
/// Each entry consists of:
/// - Record ID (4 or 8 bytes depending on version)
/// - Null-terminated key text
///
/// # Parameters
/// * `reader` - Source providing decompressed key block data
/// * `version` - MDict version for field widths
/// * `encoding` - Text encoding for key strings
pub fn read_next_key_entry(
    reader: &mut &[u8],
    version: MdictVersion,
    encoding: &'static encoding_rs::Encoding,
) -> Result<(String, u64)> {
    let record_id = utils::read_number(reader, version.number_width())?;
    let text = read_null_terminated_string(reader, encoding)?;

    Ok((text, record_id))
}

/// Extracts and decodes a single record from a decompressed block.
///
/// This is a zero-copy operation that slices the block data and processes
/// it according to the file type (MDX → String, MDD → Vec<u8>).
///
/// # Parameters
/// * `block_bytes` - Complete decompressed block
/// * `start` - Start position of the record within the block
/// * `end` - End position of the record within the block (exclusive)
/// * `encoding` - Text encoding for record data
/// * `stylesheet` - Parsed stylesheet for MDX files (empty if none defined)
///
/// # Returns
/// A [`RecordData`] enum that can be either actual content or a redirect to another key.
pub fn parse_record<T: FileType>(
    block_bytes: &[u8],
    start: u64,
    end: u64,
    encoding: &'static encoding_rs::Encoding,
    stylesheet: &StyleSheet,
) -> Result<RecordData<T::Record>> {
    trace!(
        "Extracting {} record: range=[{}..{}], size={}",
        T::DEBUG_NAME,
        start,
        end,
        end - start
    );
    
    let start = start as usize;
    let end = end as usize;
    
    if end > block_bytes.len() {
        return Err(MdictError::InvalidFormat(format!(
            "Record location [{}..{}] is out of bounds for block of size {}",
            start, end, block_bytes.len()
        )));
    }
    
    let record_slice = &block_bytes[start..end];
    T::process_record(record_slice, encoding, stylesheet)
}

/// Reads and decodes a null-terminated string, advancing the reader.
///
/// Handles both single-byte (UTF-8, GB18030) and double-byte (UTF-16) encodings.
///
/// # Parameters
/// * `reader` - Mutable reference to byte slice (will be advanced past the string and terminator)
/// * `encoding` - Text encoding for decoding
///
/// # Returns
/// The decoded string without the null terminator
fn read_null_terminated_string(
    reader: &mut &[u8],
    encoding: &'static encoding_rs::Encoding,
) -> Result<String> {
    let width = utils::unit_width(encoding);
    
    // Find null terminator position (depends on encoding width)
    let end_pos = if width == 2 {
        // UTF-16: look for double-null (0x0000)
        reader
            .chunks_exact(2)
            .position(|chunk| chunk == [0, 0])
            .map(|chunk_index| chunk_index * 2)
    } else {
        // Single-byte encodings: look for single null
        reader
            .iter()
            .position(|&byte| byte == 0)
    }
    .ok_or_else(|| MdictError::InvalidFormat("Missing null terminator in string".to_string()))?;
    
    // Decode the text portion (excluding terminator)
    let text_bytes = &reader[..end_pos];
    let (decoded, _, _) = encoding.decode(text_bytes);
    
    // Advance reader past text and terminator
    *reader = &reader[end_pos + width..];
    
    Ok(decoded.into_owned())
}
