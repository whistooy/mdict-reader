//! # MDict Reader Core
//!
//! This module provides a layered architecture for reading MDict (`.mdx`/`.mdd`) files.
//!
//! ## Module Hierarchy & Data Flow
//!
//! The architecture is designed to separate concerns from high-level API to low-level data
//! transformation. Data flows from the top down:
//!
//! 1.  **Public API (`reader`, `iter`)**: The user-facing interface.
//!     -   Exposes `MdictReader` for dictionary lookups.
//!     -   Provides iterators for keys and records.
//!
//! 2.  **Format (`format`)**: High-level file format parsing.
//!     -   `header`: Parses the main dictionary header.
//!     -   `index`: Handles version-specific index block structures (`v1v2`, `v3`).
//!     -   `content`: Parses the actual content of a data block (keys or records).
//!
//! 3.  **Codec (`codec`)**: Pure, low-level data transformation primitives.
//!     -   Handles decryption (`crypto`), decompression (`compression`), and text encoding.
//!     -   Has no knowledge of the MDict file structure.
//!
//! 4.  **Types (`types`)**: Foundational data structures, errors, and traits.
//!     -   Shared across all layers.
//!
//! ```text
//!   ┌──────────────────┐
//!   │      Reader      │
//!   └──────────────────┘
//!            │
//!   ┌──────────────────┐
//!   │      Format      │ (header, index, content)
//!   └──────────────────┘
//!            │
//!   ┌──────────────────┐
//!   │       Codec      │ (crypto, compression)
//!   └──────────────────┘
//! ```

// Foundational types
pub mod types;

// Low-level encoding/decoding primitives
mod codec;

// High-level, version-specific format parsing
pub mod format;

// High-level public API
pub mod iter;
pub mod reader;

// Internal utilities
mod utils;

// Public API exports
pub use reader::MdictReader;
pub use types::error::{MdictError, Result};
