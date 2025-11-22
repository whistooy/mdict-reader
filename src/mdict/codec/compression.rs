//! Decompression algorithms for MDict data blocks.
//!
//! MDict files support multiple compression formats:
//! - None (type 0): No compression
//! - LZO (type 1): Fast decompression using lzokay
//! - Zlib (type 2): Standard deflate compression

use std::io::Read;

use flate2::read::ZlibDecoder;
use log::trace;
use lzokay::decompress::decompress as lzokay_decompress;

use crate::mdict::types::error::{MdictError, Result};
use crate::mdict::types::models::CompressionType;

/// Decompresses a payload using the specified compression algorithm.
///
/// # Compression Types
/// - `None` (0): No compression, returns a copy of input
/// - `Lzo` (1): LZO compression via lzokay library
/// - `Zlib` (2): Zlib/deflate compression via flate2
///
/// # Validation
/// Verifies that the decompressed size exactly matches `expected_size`.
///
/// # Errors
/// Returns an error if decompression fails or size validation fails.
pub fn decompress_payload(
    payload: &[u8],
    compression_type: CompressionType,
    expected_size: u64,
) -> Result<Vec<u8>> {
    let decompressed = match compression_type {
        CompressionType::None => {
            trace!("No compression, copying {} bytes", payload.len());
            payload.to_vec()
        }
        CompressionType::Lzo => {
            trace!("Decompressing with LZO: {} bytes -> {} bytes (expected)", payload.len(), expected_size);
            let mut output = vec![0u8; expected_size as usize];
            lzokay_decompress(payload, &mut output)
                .map_err(|e| MdictError::DecompressionError(format!("LZO decompression failed: {}", e)))?;
            output
        }
        CompressionType::Zlib => {
            trace!("Decompressing with Zlib: {} bytes -> {} bytes (expected)", payload.len(), expected_size);
            let mut output = Vec::with_capacity(expected_size as usize);
            let mut decoder = ZlibDecoder::new(payload);
            decoder
                .read_to_end(&mut output)
                .map_err(|e| MdictError::DecompressionError(format!("Zlib decompression failed: {}", e)))?;
            output
        }
    };

    // Validate decompressed size
    if decompressed.len() as u64 != expected_size {
        return Err(MdictError::SizeMismatch {
            context: "decompressed block".to_string(),
            expected: expected_size,
            found: decompressed.len() as u64,
        });
    }

    Ok(decompressed)
}
