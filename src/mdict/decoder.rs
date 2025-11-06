//! Block decoding orchestration (decryption + decompression + verification)

use byteorder::{BigEndian, LittleEndian, ByteOrder};
use adler32::adler32;
use ripemd::{Digest, Ripemd128};
use super::{crypto, compression};
use super::error::{Result, MdictError};

/// Decode a compressed/encrypted block.
/// 
/// MDict block format:
/// - Bytes 0-3: Compression type (lower 4 bits) + Encryption type (next 4 bits)
/// - Bytes 4-7: Adler32 checksum of decompressed data
/// - Bytes 8+:  Encrypted/compressed payload
/// 
/// Process:
/// 1. Determine decryption key (master key or derived from checksum)
/// 2. Decrypt payload
/// 3. Decompress payload
/// 4. Verify checksum
pub fn decode_block(
    raw_block: &[u8],
    expected_decompressed_size: u64,
    master_key: Option<&[u8; 16]>,
) -> Result<Vec<u8>> {
    if raw_block.len() < 8 {
        return Err(MdictError::InvalidFormat("Block too short (minimum 8 bytes required)".to_string()));
    }

    // Parse block header
    let info = LittleEndian::read_u32(&raw_block[0..4]);
    let compression_type = (info & 0xF) as u8;
    let encryption_type = ((info >> 4) & 0xF) as u8;
    let checksum_expected = BigEndian::read_u32(&raw_block[4..8]);
    let payload = &raw_block[8..];

    // Determine decryption key
    let decryption_key: [u8; 16] = match master_key {
        Some(key) => *key,
        None => {
            // Derive key from block's own checksum (used when no master key)
            let mut hasher = Ripemd128::new();
            hasher.update(&raw_block[4..8]);
            hasher.finalize().into()
        }
    };

    // Step 1: Decrypt
    let decrypted = crypto::decrypt_payload(payload, encryption_type, &decryption_key)?;

    // Step 2: Decompress
    let decompressed = compression::decompress_payload(
        &decrypted,
        compression_type as u32,
        expected_decompressed_size,
    )?;

    // Step 3: Verify checksum
    let checksum_actual = adler32(&decompressed[..])?;
    if checksum_actual != checksum_expected {
        return Err(MdictError::ChecksumMismatch {
            expected: checksum_expected,
            actual: checksum_actual,
        });
    }

    Ok(decompressed)
}
