//! Cryptographic operations for MDict format

use ripemd::{Digest, Ripemd128};
use log::{debug, trace};
use super::models::EncryptionType;
use super::error::{Result, MdictError};
use byteorder::{ByteOrder, LittleEndian};
use twox_hash::XxHash64;

/// Derive master encryption key from registration code and user ID.
/// 
/// Algorithm:
/// 1. Hash user ID with RIPEMD-128 to get a 16-byte digest.
/// 2. Use this digest as a 128-bit key for Salsa20/8.
/// 3. Decrypt the 16-byte registration code to get the final master key.
pub fn derive_master_key(reg_code: &[u8], user_id: &[u8]) -> Result<[u8; 16]> {
    debug!("Deriving master key from registration code and user ID");
    
    // 1. Hash the user ID to create the Salsa20 key.
    let mut hasher = Ripemd128::new();
    hasher.update(user_id);
    let salsa_key: [u8; 16] = hasher.finalize().into();
    // 2. Decrypt the registration code using the generated key.
    let mut master_key_bytes = reg_code.to_vec();
    salsa_decrypt(&mut master_key_bytes, &salsa_key);
    // 3. The decrypted data is the master key.
    master_key_bytes
        .try_into()
        .map_err(|_| MdictError::InvalidFormat("Internal error: derived key was not 16 bytes".to_string()))
}

/// Fast XOR-based decryption used in MDict format.
/// 
/// Algorithm:
/// - Each byte is rotated left by 4 bits
/// - Then XORed with: previous original byte + index + key byte
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

/// Derive decryption key for v2 key index.
/// 
/// Key = RIPEMD-128(checksum_bytes + magic_number)
/// where magic_number = 0x3695
pub fn derive_key_for_v2_index(key_index_block: &[u8]) -> [u8; 16] {
    trace!("Deriving key for v2.x key index using checksum and magic constant");
    
    let mut hasher = Ripemd128::new();
    hasher.update(&key_index_block[4..8]); // Checksum bytes
    hasher.update(0x3695u32.to_le_bytes()); // Magic constant
    hasher.finalize().into()
}

/// Decrypt a payload using the specified encryption type.
/// 
/// Types:
/// - 0: No encryption
/// - 1: Fast decrypt (XOR-based)
/// - 2: Salsa20/8
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
            trace!("Decrypting {} bytes in-place with fast XOR method", payload.len());
            fast_decrypt(payload, key);
        }
        EncryptionType::Salsa20 => {
            trace!("Decrypting {} bytes in-place with Salsa20", payload.len());
            salsa_decrypt(payload, key);
        }
    }
}

/// Derive 16-byte master key from UUID using xxHash64 (v3.0 only).
/// 
/// Algorithm:
/// 1. Split UUID at midpoint
/// 2. Hash each half with xxh64 (seed=0)
/// 3. Concatenate to form 16-byte key
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
/// **Note: This implementation only supports 16-byte (128-bit) keys.**
///
/// This is a manual implementation of the Salsa20 core algorithm with 8 rounds,
/// as required by the MDict format specification.
///
/// # State Initialization
/// The 64-byte (512-bit) Salsa20 state is initialized as a 4x4 matrix of 32-bit words:
/// ```
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
/// - `data`: The data to decrypt (modified in-place).
/// - `key16`: The 16-byte decryption key.
pub fn salsa_decrypt(data: &mut [u8], key16: &[u8; 16]) {
    trace!("Decrypting {} bytes with Salsa20/8 (16-byte key)", data.len());
    let mut state = [0u32; 16];
    // Constants: "expand 16-byte k" as 32-bit little-endian words
    state[0] = 0x61707865;
    state[5] = 0x3120646e;
    state[10] = 0x79622d36;
    state[15] = 0x6b206574;
    // Key: A 16-byte key is used for both the first and second key slots.
    // This is the standard Salsa20 approach for 128-bit keys.
    for i in 0..4 {
        state[1 + i] = LittleEndian::read_u32(&key16[i*4..]);
        state[11 + i] = LittleEndian::read_u32(&key16[i*4..]);
    }
    // IV/Nonce: MDict uses a zero nonce.
    state[6] = 0;
    state[7] = 0;
    let mut keystream_block = [0u8; 64];
    for (block_index, chunk) in data.chunks_mut(64).enumerate() {
        // Set the 64-bit block counter for the current chunk.
        state[8] = block_index as u32;
        state[9] = (block_index as u64 >> 32) as u32;
        // Generate the keystream for this block.
        let mut x = state;
        for _ in 0..4 { // 8 rounds total (4 iterations of 2 rounds each)
            // Column rounds
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 5, 9, 13, 1);
            quarter_round(&mut x, 10, 14, 2, 6);
            quarter_round(&mut x, 15, 3, 7, 11);
            // Row rounds
            quarter_round(&mut x, 0, 1, 2, 3);
            quarter_round(&mut x, 5, 6, 7, 4);
            quarter_round(&mut x, 10, 11, 8, 9);
            quarter_round(&mut x, 15, 12, 13, 14);
        }
        for (i, val) in x.iter_mut().enumerate() {
            *val = val.wrapping_add(state[i]);
        }
        for (i, word) in x.iter().enumerate() {
            LittleEndian::write_u32(&mut keystream_block[i*4..], *word);
        }
        // Apply the keystream to the data chunk via XOR.
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream_block[i];
        }
    }
}
/// A single Salsa20 quarter round operation (add-rotate-XOR).
#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}