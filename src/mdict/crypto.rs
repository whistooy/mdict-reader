//! Cryptographic operations for MDict format

use ripemd::{Digest, Ripemd128};
use salsa20::{cipher::{KeyIvInit, StreamCipher}, Salsa8};
use super::models::EncryptionType;
use super::error::{Result, MdictError};

/// Derive master encryption key from registration code and user ID.
/// 
/// Algorithm:
/// 1. Hash user ID with RIPEMD-128 → 16-byte digest
/// 2. Duplicate digest to form 32-byte Salsa20 key
/// 3. Decrypt registration code with Salsa20/8
pub fn derive_master_key(reg_code: &[u8], user_id: &[u8]) -> Result<[u8; 16]> {
    // Hash user ID to create cipher key
    let mut hasher = Ripemd128::new();
    hasher.update(user_id);
    let user_id_digest: [u8; 16] = hasher.finalize().into();

    // Salsa20 requires 32-byte key (duplicate the 16-byte digest)
    let mut salsa_key = [0u8; 32];
    salsa_key[..16].copy_from_slice(&user_id_digest);
    salsa_key[16..].copy_from_slice(&user_id_digest);

    // Decrypt registration code to get final master key
    let mut key = reg_code.to_vec();
    let mut cipher = Salsa8::new((&salsa_key).into(), &([0u8; 8]).into());
    cipher.apply_keystream(&mut key);

    key.try_into()
        .map_err(|_| MdictError::DecryptionError("Registration code must be exactly 16 bytes".to_string()))
}

/// Decrypt data using Salsa20/8 stream cipher.
/// 
/// The 16-byte key is duplicated to form the required 32-byte key.
pub fn salsa_decrypt(data: &mut [u8], key16: &[u8; 16]) {
    let mut salsa_key = [0u8; 32];
    salsa_key[..16].copy_from_slice(key16);
    salsa_key[16..].copy_from_slice(key16);

    let mut cipher = Salsa8::new((&salsa_key).into(), &([0u8; 8]).into());
    cipher.apply_keystream(data);
}

/// Fast XOR-based decryption used in MDict format.
/// 
/// Algorithm:
/// - Each byte is rotated left by 4 bits
/// - Then XORed with: previous original byte + index + key byte
pub fn fast_decrypt(data: &mut [u8], key: &[u8]) {
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
    let mut hasher = Ripemd128::new();
    hasher.update(&key_index_block[4..8]); // Checksum bytes
    hasher.update(&0x3695u32.to_le_bytes()); // Magic constant
    hasher.finalize().into()
}

/// Decrypt a payload using the specified encryption type.
/// 
/// Types:
/// - 0: No encryption
/// - 1: Fast decrypt (XOR-based)
/// - 2: Salsa20/8
pub fn decrypt_payload(
    payload: &[u8],
    encryption_type: EncryptionType,
    key: &[u8; 16],
) -> Result<Vec<u8>> {
    match encryption_type {
        EncryptionType::None => Ok(payload.to_vec()), // No encryption
        EncryptionType::Fast => {
            let mut decrypted = payload.to_vec();
            fast_decrypt(&mut decrypted, key);
            Ok(decrypted)
        }
        EncryptionType::Salsa20 => {
            let mut decrypted = payload.to_vec();
            salsa_decrypt(&mut decrypted, key);
            Ok(decrypted)
        }
    }
}
