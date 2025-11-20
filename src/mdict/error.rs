//! Custom error types for the mdict-reader crate.

use thiserror::Error;

/// The primary error type for all operations in this crate.
#[derive(Debug, Error)]
pub enum MdictError {
    /// An error originating from I/O operations.
    #[error("I/O error: {0:?}")]
    Io(#[from] std::io::Error),

    /// The MDict file version is unsupported (e.g., 4.0+).
    #[error("Unsupported MDict version: {0}. Only v1.x, v2.x, and v3.x are supported.")]
    UnsupportedVersion(f32),

    /// A checksum validation failed, indicating data corruption.
    #[error("Checksum mismatch: expected {expected:#x}, got {actual:#x}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    /// An error occurred during decryption, often due to a wrong key or corrupted data.
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// An error occurred during decompression, often due to corrupted data or an unknown algorithm.
    #[error("Decompression failed: {0}")]
    DecompressionError(String),

    /// A declared count of items does not match the actual number of items found.
    #[error("Count mismatch for {item_type}: expected {expected}, but found {found}")]
    CountMismatch {
        item_type: &'static str,
        expected: u64,
        found: u64,
    },

    /// A buffer or data block has an unexpected size after an operation.
    #[error("Size mismatch for {context}: expected {expected} bytes, but found {found} bytes")]
    SizeMismatch {
        context: &'static str,
        expected: u64,
        found: u64,
    },

    /// The file is structurally invalid or does not conform to the MDict format specification.
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    /// The file is encrypted, but no passcode was provided to derive the decryption key.
    #[error("Encrypted file requires a passcode, but none was provided.")]
    PasscodeRequired,

    /// A mutex lock was poisoned, indicating a panic in another thread holding the lock.
    #[error("A mutex lock was poisoned, indicating a panic in another thread holding the lock.")]
    LockPoisoned,
}

/// A convenience `Result` type alias using the crate's `MdictError` type.
pub type Result<T> = std::result::Result<T, MdictError>;
