//! # mdict-reader
//!
//! A reader for MDict dictionary files (.mdx and .mdd).
//! Supports versions 1.x, 2.x and 3.x with encryption and various compression algorithms.
//!
//! ## Usage
//!
//! ### High-Level (Auto-Detection)
//!
//! For convenience, you can use the `Mdict` enum to automatically open a file
//! based on its extension and dispatch to the correct reader.
//!
//! ```no_run
//! use mdict_reader::Mdict;
//!
//! let mdict = Mdict::open("path/to/dictionary.mdx", None, None).unwrap();
//!
//! if let Mdict::Mdx(reader) = mdict {
//!     for result in reader.iter_keys() {
//!         // ...
//!     }
//! }
//! ```
//!
//! ### Low-Level (Specialized Readers)
//!
//! If you know the file type in advance, you can instantiate the specialized
//! `MdictReader` directly for a more direct and type-safe experience.
//!
//! ```no_run
//! use mdict_reader::{MdictReader, Mdx};
//!
//! // The type parameter `Mdx` specializes the reader for dictionary files.
//! let mdx_reader = MdictReader::<Mdx>::new("path/to/dictionary.mdx", None, None).unwrap();
//!
//! // The iterator now yields `Result<(String, String)>` directly.
//! for result in mdx_reader.iter_records() {
//!     let (key, definition) = result.unwrap();
//!     println!("Key: {}, Definition: {}", key, definition);
//! }
//! ```

pub mod mdict;

// Re-export the main types for convenience
pub use mdict::{
    // The core, specialized reader struct
    MdictReader,
    // The file type markers for specialization
    types::filetypes::{FileType, Mdd, Mdx},
    // The error types
    types::error::{MdictError, Result},
    // Models are essential for understanding the data
    types::models::{EncryptionFlags, KeyEntry, MdictHeader, RecordInfo},
};

use std::path::Path;

/// An enum that dispatches to the correct, specialized MDict reader.
///
/// This serves as a high-level convenience wrapper for opening files when
/// the type is not known at compile time.
pub enum Mdict {
    Mdx(MdictReader<Mdx>),
    Mdd(MdictReader<Mdd>),
}

impl Mdict {
    /// Opens an MDict file, automatically detecting its type from the file
    /// extension and returning the appropriate specialized reader.
    ///
    /// # Encoding Override Behavior
    /// - For **MDX files**: `user_encoding` overrides the header's declared encoding.
    /// - For **MDD files**: `user_encoding` is **ignored**; MDD always uses UTF-16LE per specification.
    ///
    /// For direct, type-safe access, use `MdictReader::<Mdx>::new()` or
    /// `MdictReader::<Mdd>::new()` instead.
    ///
    /// # Arguments
    /// * `path` - File path to the .mdx or .mdd file
    /// * `passcode` - Optional (`regcode_hex`, `user_email`) tuple for encrypted files
    /// * `user_encoding` - Optional encoding override (only effective for MDX files)
    pub fn open(
        path: impl AsRef<Path>,
        passcode: Option<(&str, &str)>,
        user_encoding: Option<&str>,
    ) -> Result<Self> {
        let path = path.as_ref();

        match path.extension().and_then(|s| s.to_str()) {
            Some(ext) if ext.eq_ignore_ascii_case("mdx") => {
                Ok(Mdict::Mdx(MdictReader::<Mdx>::new(path, passcode, user_encoding)?))
            }
            Some(ext) if ext.eq_ignore_ascii_case("mdd") => {
                Ok(Mdict::Mdd(MdictReader::<Mdd>::new(path, passcode, user_encoding)?))
            }
            _ => Err(MdictError::InvalidFormat(
                "File must have a .mdx or .mdd extension for auto-detection".to_string(),
            )),
        }
    }
}
