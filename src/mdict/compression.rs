//! Decompression operations for MDict format

use std::error::Error;
use std::io::Read;
use flate2::read::ZlibDecoder;
use lzokay::decompress::decompress as lzokay_decompress;

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
    compression_type: u32,
    expected_size: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let decompressed = match compression_type {
        0 => payload.to_vec(), // No compression
        1 => {
            // LZO compression
            let mut output = vec![0u8; expected_size as usize];
            lzokay_decompress(payload, &mut output)?;
            output
        }
        2 => {
            // Zlib compression
            let mut output = Vec::with_capacity(expected_size as usize);
            let mut decoder = ZlibDecoder::new(payload);
            decoder.read_to_end(&mut output)?;
            output
        }
        _ => return Err(format!("Unknown compression type: {}", compression_type).into()),
    };

    // Verify decompressed size matches expectation
    if decompressed.len() as u64 != expected_size {
        return Err(format!(
            "Decompression size mismatch: expected {}, got {}",
            expected_size,
            decompressed.len()
        ).into());
    }

    Ok(decompressed)
}
