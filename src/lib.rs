//! # mdict-reader
//! 
//! A reader for MDict dictionary files (.mdx and ~.mdd~ formats).
//! Supports versions 1.x and 2.x with encryption and various compression algorithms.
//! 
//! **Note:** Support for `.mdd` resource files is planned but not yet implemented.
pub mod mdict;

// Re-export the main types for convenience
pub use mdict::{
    MdictReader,
    models::{
        MdictHeader, 
        EncryptionFlags, 
        KeyEntry, 
        KeyBlockInfo, 
        RecordBlockInfo
    },
};
