//! Block decoding orchestration (decryption + decompression + verification)

use byteorder::{BigEndian, LittleEndian, ByteOrder};
use adler2::adler32_slice;
use ripemd::{Digest, Ripemd128};
use std::cmp::min;
use log::trace;
use super::{crypto, compression};
use super::models::{CompressionType, EncryptionType, MdictVersion};
use super::error::{Result, MdictError};

/// Decode a compressed/encrypted payload.
/// 
/// # Arguments
/// * `raw_block` - The raw block data from the file. **This buffer will be mutated**
///   during decryption, acting as scratch space for the decrypted payload. Its
///   contents should be considered invalid after this function returns.
/// * `expected_decompressed_size` - The expected final size after decompression.
/// * `master_key` - The master decryption key, if any.
/// * `version` - The MDict format version, to determine checksum logic.
/// 
/// Process (v1/v2):
/// 1. Decrypt -> 2. Decompress -> 3. Verify checksum on decompressed data
/// 
/// Process (v3):
/// 1. Decrypt -> 2. Verify checksum on decrypted data -> 3. Decompress
pub fn decode_payload(
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

    // Step 1: Decrypt (with size limit)
    // Ensure we don't try to decrypt more data than exists.
    let decrypt_len = min(encryption_size, payload.len());
    crypto::decrypt_payload_in_place(
        &mut payload[..decrypt_len],
        encryption_type,
        &decryption_key,
    );
    // Step 2: Verify checksum (position depends on version)
    if version == MdictVersion::V3 {
        // V3 checksums the DECRYPTED data before decompression.
        let checksum_actual = adler32_slice(payload);
        trace!("V3 block checksum on decrypted data: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
        if checksum_actual != checksum_expected {
            return Err(MdictError::ChecksumMismatch {
                expected: checksum_expected,
                actual: checksum_actual,
            });
        }
    }

    // Step 3: Decompress (uses the full payload, which is now decrypted)
    let decompressed = compression::decompress_payload(
        payload,
        compression_type,
        expected_decompressed_size,
    )?;

    // Step 4: Verify checksum for v1/v2 (after decompression)
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
