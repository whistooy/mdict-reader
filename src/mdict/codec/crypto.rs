//! Cryptographic operations for MDict file encryption and decryption.
//!
//! This module implements the encryption schemes used in MDict files:
//! - Master key derivation from registration codes and UUIDs
//! - Fast XOR-based encryption (v1/v2)
//! - Salsa20/8 stream cipher (v2/v3)

use crate::mdict::types::error::{MdictError, Result};
use crate::mdict::types::models::EncryptionType;
use byteorder::{ByteOrder, LittleEndian};
use log::{debug, trace};
use ripemd::{Digest, Ripemd128};
use twox_hash::XxHash64;

/// Derives the master decryption key from a registration code and user email.
///
/// # Algorithm
/// 1. Hash the user email with RIPEMD-128 → 16-byte digest
/// 2. Use digest as Salsa20/8 key to decrypt the registration code
/// 3. Decrypted registration code becomes the master key
///
/// # Arguments
/// * `reg_code` - 16-byte encrypted registration code (hex-decoded)
/// * `user_id` - User email address as bytes
pub fn derive_master_key(reg_code: &[u8], user_id: &[u8]) -> Result<[u8; 16]> {
    debug!("Deriving master key from registration code and user email");

    // Step 1: Hash the user email to create the Salsa20 key
    let mut hasher = Ripemd128::new();
    hasher.update(user_id);
    let salsa_key: [u8; 16] = hasher.finalize().into();

    // Step 2: Decrypt the registration code using the hashed key
    let mut master_key_bytes = reg_code.to_vec();
    salsa_decrypt(&mut master_key_bytes, &salsa_key);

    // Step 3: Return the decrypted registration code as the master key
    master_key_bytes.try_into().map_err(|_| {
        MdictError::InvalidFormat("Internal error: derived key was not 16 bytes".to_string())
    })
}

/// Decrypts data using the fast XOR-based cipher (MDict v1/v2).
///
/// # Algorithm
/// For each byte at position `i`:
/// 1. Rotate byte left by 4 bits
/// 2. XOR with: `previous_byte ^ i ^ key[i % key.len()]`
/// 3. Store original byte for next iteration
///
/// Initial `previous_byte` is `0x36`.
pub fn fast_decrypt(data: &mut [u8], key: &[u8]) {
    trace!("Decrypting {} bytes with fast XOR method", data.len());

    let mut prev = 0x36u8;
    for (i, byte) in data.iter_mut().enumerate() {
        let current = *byte;
        let rotated = current.rotate_left(4);
        *byte = rotated ^ prev ^ (i as u8) ^ key[i % key.len()];
        prev = current;
    }
}

/// Derives the decryption key for MDict v2.x key index blocks.
///
/// # Formula
/// `Key = RIPEMD-128(checksum_bytes || 0x3695)`
///
/// The magic constant `0x3695` is part of the MDict v2.x specification.
pub fn derive_key_for_v2_index(key_index_block: &[u8]) -> [u8; 16] {
    trace!("Deriving key for v2.x key index using checksum and magic constant");

    let mut hasher = Ripemd128::new();
    hasher.update(&key_index_block[4..8]); // 4-byte checksum
    hasher.update(0x3695u32.to_le_bytes()); // MDict v2 magic constant
    hasher.finalize().into()
}

/// Decrypts a payload in-place using the specified encryption method.
///
/// # Encryption Types
/// - `None` (0): No encryption, no-op
/// - `Fast` (1): Fast XOR-based cipher
/// - `Salsa20` (2): Salsa20/8 stream cipher
pub fn decrypt_payload_in_place(
    payload: &mut [u8],
    encryption_type: EncryptionType,
    key: &[u8; 16],
) {
    match encryption_type {
        EncryptionType::None => {
            trace!("No encryption, skipping {} bytes", payload.len());
        }
        EncryptionType::Fast => {
            trace!(
                "Decrypting {} bytes in-place with fast XOR method",
                payload.len()
            );
            fast_decrypt(payload, key);
        }
        EncryptionType::Salsa20 => {
            trace!("Decrypting {} bytes in-place with Salsa20", payload.len());
            salsa_decrypt(payload, key);
        }
    }
}

/// Derives a 16-byte master key from a UUID (MDict v3.0).
///
/// # Algorithm
/// 1. Split UUID into two halves
/// 2. Hash each half with xxHash64 (seed=0) → 8 bytes each
/// 3. Concatenate hashes → 16-byte key
pub fn derive_key_from_uuid(uuid: &[u8]) -> Result<[u8; 16]> {
    debug!("Deriving master key from UUID ({} bytes)", uuid.len());

    let mid = uuid.len().div_ceil(2);
    let first_half = &uuid[..mid];
    let second_half = &uuid[mid..];

    let hash1 = XxHash64::oneshot(0, first_half).to_be_bytes();
    let hash2 = XxHash64::oneshot(0, second_half).to_be_bytes();

    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&hash1);
    key[8..].copy_from_slice(&hash2);

    Ok(key)
}

/// Decrypts data in-place using the Salsa20/8 stream cipher.
///
/// This implements Salsa20 with 8 rounds (instead of the standard 20) as required
/// by the MDict format specification. Only 128-bit (16-byte) keys are supported.
///
/// # State Matrix
/// The 64-byte state is arranged as a 4×4 matrix of 32-bit little-endian words:
/// ```text
/// [c0, k0, k1, k2]
/// [k3, c1, iv0, iv1]
/// [ctr0, ctr1, c2, k4]
/// [k5, k6, k7, c3]
/// ```
/// Where:
/// - `c0..c3` are constants ("expand 16-byte k").
/// - `k0..k7` are the key words. For a 16-byte key, `k0..k3` and `k4..k7` are identical.
/// - `iv0..iv1` is the 64-bit nonce (always zero in MDict).
/// - `ctr0..ctr1` is the 64-bit block counter.
///
/// # Parameters
/// * `data` - Data to decrypt (modified in-place)
/// * `key16` - 16-byte (128-bit) decryption key
pub fn salsa_decrypt(data: &mut [u8], key16: &[u8; 16]) {
    trace!(
        "Decrypting {} bytes with Salsa20/8 (128-bit key)",
        data.len()
    );

    let mut state = [0u32; 16];

    // Salsa20 constants: "expand 16-byte k"
    state[0] = 0x61707865;
    state[5] = 0x3120646e;
    state[10] = 0x79622d36;
    state[15] = 0x6b206574;
    // Key setup: For 128-bit keys, the same 16 bytes fill both key slots
    for i in 0..4 {
        state[1 + i] = LittleEndian::read_u32(&key16[i * 4..]);
        state[11 + i] = LittleEndian::read_u32(&key16[i * 4..]);
    }
    // Nonce: MDict always uses a zero nonce
    state[6] = 0;
    state[7] = 0;
    let mut keystream_block = [0u8; 64];

    for (block_index, chunk) in data.chunks_mut(64).enumerate() {
        // Set 64-bit block counter (little-endian split across two words)
        state[8] = block_index as u32;
        state[9] = (block_index as u64 >> 32) as u32;

        // Generate keystream using Salsa20 core function
        let mut x = state;
        for _ in 0..4 {
            // 8 rounds total (4 double-rounds)
            // Column rounds (vertical mixing)
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 5, 9, 13, 1);
            quarter_round(&mut x, 10, 14, 2, 6);
            quarter_round(&mut x, 15, 3, 7, 11);
            // Row rounds (horizontal mixing)
            quarter_round(&mut x, 0, 1, 2, 3);
            quarter_round(&mut x, 5, 6, 7, 4);
            quarter_round(&mut x, 10, 11, 8, 9);
            quarter_round(&mut x, 15, 12, 13, 14);
        }

        // Add original state to mixed state (prevents reversibility)
        for (i, val) in x.iter_mut().enumerate() {
            *val = val.wrapping_add(state[i]);
        }

        // Serialize 32-bit words to byte stream (little-endian)
        for (i, word) in x.iter().enumerate() {
            LittleEndian::write_u32(&mut keystream_block[i * 4..], *word);
        }

        // XOR data with keystream to decrypt
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream_block[i];
        }
    }
}
/// Performs a single Salsa20 quarter-round operation.
///
/// This is the core mixing function of Salsa20, applying a sequence of
/// addition, rotation, and XOR operations to four state words.
#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}
