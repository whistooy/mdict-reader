//! Codec layer for encryption and compression operations.
//!
//! This module provides the cryptographic and compression primitives
//! used by MDict file format parsers.
//!
//! # Submodules
//!
//! - [`crypto`][]: Encryption/decryption (Salsa20, Fast XOR, key derivation)
//! - [`compression`][]: Decompression algorithms (LZO, Zlib/deflate)

pub mod compression;
pub mod crypto;