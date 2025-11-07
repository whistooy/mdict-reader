//! Block decoding orchestration (decryption + decompression + verification)

use byteorder::{BigEndian, LittleEndian, ByteOrder};
use adler32::adler32;
use ripemd::{Digest, Ripemd128};
use log::trace;
use super::{crypto, compression};
use super::models::{CompressionType, EncryptionType};
use super::error::{Result, MdictError};

/// Decode a compressed/encrypted block.
/// 
/// # Arguments
/// * `raw_block` - The raw block data from the file. **This buffer will be mutated**
///   during decryption, acting as scratch space for the decrypted payload. Its
///   contents should be considered invalid after this function returns.
/// * `expected_decompressed_size` - The expected final size after decompression.
/// * `master_key` - The master decryption key, if any.
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
    raw_block: &mut [u8],
    expected_decompressed_size: u64,
    master_key: Option<&[u8; 16]>,
) -> Result<Vec<u8>> {
    if raw_block.len() < 8 {
        return Err(MdictError::InvalidFormat("Block too short (minimum 8 bytes required)".to_string()));
    }

    // Parse block header
    let info = LittleEndian::read_u32(&raw_block[0..4]);
    let compression_type = CompressionType::try_from((info & 0xF) as u8)?;
    let encryption_type = EncryptionType::try_from(((info >> 4) & 0xF) as u8)?;
    let checksum_expected = BigEndian::read_u32(&raw_block[4..8]);

    trace!(
        "Decoding block: compression={:?}, encryption={:?}, expected_size={} bytes",
        compression_type, encryption_type, expected_decompressed_size
    );

    // Determine decryption key
    let decryption_key: [u8; 16] = match master_key {
        Some(key) => {
            trace!("Using master key for decryption");
            *key
        }
        None => {
            // Derive key from block's own checksum (used when no master key)
            trace!("Deriving decryption key from block checksum");
            let mut hasher = Ripemd128::new();
            hasher.update(&raw_block[4..8]);
            hasher.finalize().into()
        }
    };

    let payload = &mut raw_block[8..];
    // Step 1: Decrypt
    crypto::decrypt_payload_in_place(payload, encryption_type, &decryption_key);

    // Step 2: Decompress
    let decompressed = compression::decompress_payload(
        payload,
        compression_type,
        expected_decompressed_size,
    )?;

    // Step 3: Verify checksum
    let checksum_actual = adler32(decompressed.as_slice())?;
    if checksum_actual != checksum_expected {
        return Err(MdictError::ChecksumMismatch {
            expected: checksum_expected,
            actual: checksum_actual,
        });
    }
    trace!("Block checksum verified: {:#010x}", checksum_actual);

    Ok(decompressed)
}
