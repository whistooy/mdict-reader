//! Decompression operations for MDict format

use std::io::Read;
use flate2::read::ZlibDecoder;
use lzokay::decompress::decompress as lzokay_decompress;
use log::trace;
use super::models::CompressionType;
use super::error::{Result, MdictError};

/// Decompress a payload using the specified compression type.
/// 
/// Types:
/// - 0: No compression
/// - 1: LZO (lzokay)
/// - 2: Zlib (deflate)
/// 
/// Validates that decompressed size matches expected size.
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

    // Verify decompressed size matches expectation
    if decompressed.len() as u64 != expected_size {
        return Err(MdictError::SizeMismatch {
            context: "decompressed block",
            expected: expected_size,
            found: decompressed.len() as u64,
        });
    }

    Ok(decompressed)
}
