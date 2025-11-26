//! Specialization logic for MDict file types (.mdx vs .mdd).

use super::error::Result;
use encoding_rs::{Encoding, UTF_16LE};

/// A trait that defines the behavior of a specific MDict file type (MDX or MDD).
pub trait FileType {
    /// A short name used for debugging and logging.
    const DEBUG_NAME: &'static str;

    /// The type of record data contained in this file.
    /// - `String` for MDX files.
    /// - `Vec<u8>` for MDD files.
    type Record;

    /// The mandatory encoding for this file type, if any.
    ///
    /// - `None`: Use the encoding specified in the file header. (MDX behavior)
    /// - `Some(encoding)`: Always use this encoding instead of the header. (MDD behavior)
    const ENCODING_OVERRIDE: Option<&'static Encoding>;

    /// Processes raw record bytes into the final record type.
    fn process_record(bytes: &[u8], encoding: &'static Encoding) -> Result<Self::Record>;
}

/// Zero-cost marker struct for MDX files.
#[derive(Debug)]
pub struct Mdx;

impl FileType for Mdx {
    const DEBUG_NAME: &'static str = "MDX";
    type Record = String;
    const ENCODING_OVERRIDE: Option<&'static Encoding> = None;

    fn process_record(bytes: &[u8], encoding: &'static Encoding) -> Result<Self::Record> {
        // Decode using the provided encoding.
        let (text, _, _) = encoding.decode(bytes);

        // Strip null terminators
        let stripped = text.trim_end_matches('\0');

        Ok(stripped.to_owned())
    }
}

/// Zero-cost marker struct for MDD files.
#[derive(Debug)]
pub struct Mdd;

impl FileType for Mdd {
    const DEBUG_NAME: &'static str = "MDD";
    type Record = Vec<u8>;
    const ENCODING_OVERRIDE: Option<&'static Encoding> = Some(UTF_16LE);

    fn process_record(bytes: &[u8], _encoding: &'static Encoding) -> Result<Self::Record> {
        // MDD bytes are the final record.
        Ok(bytes.to_vec())
    }
}
