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

/// Decompresses a payload into a pre-allocated output buffer.
///
/// # Compression Types
/// - `None` (0): No compression, copies input to output
/// - `Lzo` (1): LZO compression via lzokay library
/// - `Zlib` (2): Zlib/deflate compression via flate2
///
/// # Validation
/// Verifies that the decompressed size exactly matches `expected_size`. The output
/// buffer will be resized to `expected_size` before decompression.
///
/// # Errors
/// Returns an error if decompression fails or size validation fails.
pub fn decompress_payload_into(
    output: &mut Vec<u8>,
    payload: &[u8],
    compression_type: CompressionType,
    expected_size: u64,
) -> Result<()> {
    output.clear();
    output.resize(expected_size as usize, 0);

    match compression_type {
        CompressionType::None => {
            trace!("No compression, copying {} bytes", payload.len());
            if payload.len() as u64 != expected_size {
                return Err(MdictError::SizeMismatch {
                    context: "no-compression payload".to_string(),
                    expected: expected_size,
                    found: payload.len() as u64,
                });
            }
            output.copy_from_slice(payload);
        }
        CompressionType::Lzo => {
            trace!(
                "Decompressing with LZO: {} bytes -> {} bytes (expected)",
                payload.len(),
                expected_size
            );
            let bytes_written = lzokay_decompress(payload, output).map_err(|e| {
                MdictError::DecompressionError(format!("LZO decompression failed: {}", e))
            })?;
            if bytes_written as u64 != expected_size {
                return Err(MdictError::SizeMismatch {
                    context: "LZO decompressed block".to_string(),
                    expected: expected_size,
                    found: bytes_written as u64,
                });
            }
        }
        CompressionType::Zlib => {
            trace!(
                "Decompressing with Zlib: {} bytes -> {} bytes (expected)",
                payload.len(),
                expected_size
            );
            let mut decoder = ZlibDecoder::new(payload);
            decoder.read_exact(output).map_err(|e| {
                MdictError::DecompressionError(format!("Zlib decompression failed: {}", e))
            })?;
        }
    };

    Ok(())
}
