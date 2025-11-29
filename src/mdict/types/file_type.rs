//! Specialization logic for MDict file types (.mdx vs .mdd).

use super::error::Result;
use super::models::{RecordData, StyleSheet};
use encoding_rs::{Encoding, UTF_16LE};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Compiled regex for stylesheet substitution pattern matching.
///
/// Matches backtick-delimited style IDs like `1`, `42`, `255`.
static STYLE_PATTERN: OnceLock<Regex> = OnceLock::new();

/// Returns the cached stylesheet regex pattern.
fn style_regex() -> &'static Regex {
    STYLE_PATTERN.get_or_init(|| Regex::new(r"`(\d+)`").expect("Invalid stylesheet regex pattern"))
}

/// Applies stylesheet substitution to text content.
///
/// Replaces backtick-delimited style IDs (e.g., `1`, `42`) with their
/// corresponding opening and closing tags from the stylesheet map.
///
/// # Pattern Behavior
/// - Consecutive style tags are properly nested
/// - Previous closing tag is inserted before new opening tag
/// - Final closing tag is appended at the end
fn substitute_stylesheet(text: &str, stylesheet: &HashMap<u8, (String, String)>) -> String {
    let re = style_regex();
    let mut result = String::new();
    let mut last_pos = 0;
    let mut current_closing_tag = String::new();

    for cap in re.captures_iter(text) {
        let match_obj = cap.get(0).unwrap();

        // Append text before this match
        result.push_str(&text[last_pos..match_obj.start()]);

        // Parse style ID
        if let Ok(style_id) = cap[1].parse::<u8>() {
            if let Some((open_tag, close_tag)) = stylesheet.get(&style_id) {
                // Close previous style and open new one
                result.push_str(&current_closing_tag);
                result.push_str(open_tag);
                current_closing_tag = close_tag.clone();
            } else {
                // Style ID not found, just close previous style
                result.push_str(&current_closing_tag);
                current_closing_tag.clear();
            }
        }

        last_pos = match_obj.end();
    }

    // Append remaining text and final closing tag
    result.push_str(&text[last_pos..]);
    result.push_str(&current_closing_tag);

    result
}

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

    /// Processes raw record bytes into the final record type with transformations.
    ///
    /// This method handles:
    /// - Text decoding
    /// - Stylesheet substitution (MDX only)
    /// - Internal redirection detection
    fn process_record(
        bytes: &[u8],
        encoding: &'static Encoding,
        stylesheet: &StyleSheet,
    ) -> Result<RecordData<Self::Record>>;
}

/// Zero-cost marker struct for MDX files.
#[derive(Debug)]
pub struct Mdx;

impl FileType for Mdx {
    const DEBUG_NAME: &'static str = "MDX";
    type Record = String;
    const ENCODING_OVERRIDE: Option<&'static Encoding> = None;

    fn process_record(
        bytes: &[u8],
        encoding: &'static Encoding,
        stylesheet: &StyleSheet,
    ) -> Result<RecordData<Self::Record>> {
        // Decode using the provided encoding
        let (text, _, _) = encoding.decode(bytes);

        // Strip null terminators
        let mut content = text.trim_end_matches('\0').to_string();

        // Check for internal redirection (MDX uses UTF-8 encoding)
        // Pattern: @@@LINK=target_key
        if let Some(target) = content.strip_prefix("@@@LINK=") {
            let target_key = target.trim().to_string();
            return Ok(RecordData::Redirect(target_key));
        }

        // Apply stylesheet substitution if available (skip if empty)
        if !stylesheet.is_empty() {
            content = substitute_stylesheet(&content, stylesheet);
        }

        Ok(RecordData::Content(content))
    }
}

/// Zero-cost marker struct for MDD files.
#[derive(Debug)]
pub struct Mdd;

impl FileType for Mdd {
    const DEBUG_NAME: &'static str = "MDD";
    type Record = Vec<u8>;
    const ENCODING_OVERRIDE: Option<&'static Encoding> = Some(UTF_16LE);

    fn process_record(
        bytes: &[u8],
        encoding: &'static Encoding,
        _stylesheet: &StyleSheet,
    ) -> Result<RecordData<Self::Record>> {
        // Check for internal redirection in MDD files
        // The pattern "@@@LINK=" is encoded in the file's encoding (UTF-16LE for v1/v2, UTF-8 for v3)
        const REDIRECT_PREFIX: &[u8] = b"@@@LINK=";

        // For v1/v2 (UTF-16LE), the pattern is: [@, \0, @, \0, @, \0, L, \0, I, \0, N, \0, K, \0, =, \0]
        // For v3 (UTF-8), the pattern is: [@, @, @, L, I, N, K, =]

        let redirect_pattern: Vec<u8> = if encoding == UTF_16LE {
            // UTF-16LE encoding of "@@@LINK="
            REDIRECT_PREFIX.iter().flat_map(|&b| vec![b, 0u8]).collect()
        } else {
            // UTF-8 or other single-byte encodings
            REDIRECT_PREFIX.to_vec()
        };

        if bytes.starts_with(&redirect_pattern) {
            // Decode the target resource name
            let target_bytes = &bytes[redirect_pattern.len()..];
            let (target_text, _, _) = encoding.decode(target_bytes);
            let target_key = target_text.trim_end_matches('\0').trim().to_string();
            return Ok(RecordData::Redirect(target_key));
        }

        // No redirection, return raw bytes
        Ok(RecordData::Content(bytes.to_vec()))
    }
}
