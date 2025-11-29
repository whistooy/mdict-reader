//! File format parsing layer for MDict dictionary files.
//!
//! This module provides the mid-level parsing layer that bridges between
//! raw file I/O and the high-level [`MdictReader`](crate::mdict::reader::MdictReader).
//!
//! # Module Organization
//!
//! - [`header`]: Parses the XML header containing metadata and settings
//! - [`index`]: Parses key/record block indexes for all MDict versions
//! - [`content`]: Decodes and decompresses individual content blocks
//!
//! # Architecture
//!
//! ```text
//! File Structure:
//! ┌─────────────────┐
//! │  XML Header     │ ← header::parse()
//! ├─────────────────┤
//! │  Index Section  │ ← index::parse()
//! │  (version-      │
//! │   specific)     │
//! ├─────────────────┤
//! │  Content Blocks │ ← content::decode_block()
//! │  (compressed,   │
//! │   encrypted)    │
//! └─────────────────┘
//! ```

pub mod content;
pub mod header;
pub mod index;
