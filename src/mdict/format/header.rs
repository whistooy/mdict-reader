//! MDict file header parsing and encryption key derivation.
//!
//! This module handles:
//! - Parsing the XML header from MDict files
//! - Validating header checksums
//! - Extracting metadata (title, encoding, encryption flags, etc.)
//! - Deriving master decryption keys from passcodes or UUIDs

use std::collections::HashMap;
use std::io::Read;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use encoding_rs::UTF_16LE;
use quick_xml::{events::Event, Reader};
use adler2::adler32_slice;
use hex;
use log::{debug, info, warn, trace};
use crate::mdict::codec::crypto;
use crate::mdict::types::{
    error::{MdictError, Result},
    models::{
        EncryptionFlags, MdictHeader, MdictMetadata, MdictVersion, MdictEncoding, MasterKey,
    },
};
use crate::mdict::utils;

/// Parses the MDict file header from the beginning of the file.
///
/// # Header Structure
/// ```text
/// [4 bytes] Header length (big-endian u32)
/// [N bytes] XML metadata (UTF-16LE for v1/v2, UTF-8 for v3)
/// [4 bytes] Adler32 checksum (little-endian u32)
/// ```
///
/// # Parameters
/// * `file` - Reader positioned at the start of an MDict file
/// * `passcode` - Optional `(regcode_hex, user_email)` for encrypted files
///
/// # Returns
/// A tuple of (version, encoding, encryption_flags, master_key, metadata)
pub fn parse<R: Read>(
    file: &mut R,
    passcode: Option<(&str, &str)>,
) -> Result<MdictHeader> {
    info!("Parsing MDict header");

    // Step 1: Read header length
    let header_len = file.read_u32::<BigEndian>()?;
    trace!("Header length: {} bytes", header_len);

    // Step 2: Read header content
    let mut header_bytes = vec![0u8; header_len as usize];
    file.read_exact(&mut header_bytes)?;

    // Step 3: Verify header integrity
    let checksum_expected = file.read_u32::<LittleEndian>()?;
    let checksum_actual = adler32_slice(header_bytes.as_slice());
    trace!("Header checksum: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
    if checksum_actual != checksum_expected {
        return Err(MdictError::ChecksumMismatch {
            expected: checksum_expected,
            actual: checksum_actual,
        });
    }

    // Step 4: Decode header based on version detection
    // - v1/v2: UTF-16LE with \x00\x00 terminator
    // - v3: UTF-8 without double-null terminator
    let decoded_header = if header_bytes.ends_with(&[0, 0]) {
        debug!("Header ends with \\x00\\x00, decoding as UTF-16LE (likely v1/v2)");
        // Remove the 2-byte null terminator before decoding
        let trimmed_bytes = &header_bytes[..header_bytes.len() - 2];
        let (s, _, _) = UTF_16LE.decode(trimmed_bytes);
        s.into_owned()
    } else {
        debug!("Header does not end with \\x00\\x00, decoding as UTF-8 (likely v3)");
        // V3 uses UTF-8; from_utf8_lossy handles any encoding issues gracefully
        String::from_utf8_lossy(&header_bytes).into_owned()
    };

    // Step 5: Sanitize XML (remove control characters except whitespace)
    let sanitized_header: String = decoded_header
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();

    // Step 6: Parse XML to extract attributes
    let attrs = parse_xml_attributes(&sanitized_header)?;

    // Step 7: Build header structure from attributes
    let (version, encoding, encryption_flags, metadata) = build_header_from_attributes(&attrs)?;
    
    // Step 8: Validate encoding/version consistency
    if version == MdictVersion::V3 && !header_bytes.ends_with(&[0, 0]) {
        debug!(
            "Consistency check passed: Version is {} (>= 3.0) and header was parsed as UTF-8.",
            metadata.engine_version
        );
    } else if version != MdictVersion::V3 && header_bytes.ends_with(&[0, 0]) {
        debug!(
            "Consistency check passed: Version is {} (< 3.0) and header was parsed as UTF-16LE.",
            metadata.engine_version
        );
    } else {
        warn!(
            "Potential header encoding mismatch! Guessed encoding based on terminator ('{}'), but parsed version is: {}. The file may not be parsed correctly.",
            if header_bytes.ends_with(&[0, 0]) { "ends with 0x0000" } else { "no 0x0000 suffix" },
            metadata.engine_version
        );
    }

    // Step 9: Derive master decryption key
    let master_key = try_derive_master_key(
        passcode,
        metadata.uuid.as_ref(),
        version,
    )?;

    info!(
        "Header parsed successfully: version={}, title='{}', encoding={}, encrypted=(blocks={}, index={})",
        metadata.engine_version,
        metadata.title,
        encoding.name(),
        encryption_flags.encrypt_record_blocks,
        encryption_flags.encrypt_key_index
    );

    Ok(MdictHeader {
        version,
        encoding,
        encryption_flags,
        master_key,
        metadata,
    })
}

/// Extracts all attributes from the root XML element.
///
/// The MDict header is a single XML element with all metadata as attributes.
fn parse_xml_attributes(xml: &str) -> Result<HashMap<String, String>> {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                return e.attributes()
                    .map(|attr_result| {
                        let attr = attr_result.map_err(|e| MdictError::InvalidFormat(format!("Failed to parse XML attribute: {}", e)))?;
                        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                        let value = attr.unescape_value()
                            .map_err(|e| MdictError::InvalidFormat(format!("Failed to decode XML value: {}", e)))?
                            .into_owned();
                        Ok((key, value))
                    })
                    .collect();
            }
            Ok(Event::Eof) => return Err(MdictError::InvalidFormat("No root element found in header XML".to_string())),
            Err(e) => return Err(MdictError::InvalidFormat(format!("Failed to read header XML: {}", e))),
            _ => {}
        }
        buf.clear();
    }
}

/// Constructs header components from parsed XML attributes.
///
/// Applies defaults for missing optional fields and validates required fields.
fn build_header_from_attributes(attrs: &HashMap<String, String>) -> Result<(MdictVersion, MdictEncoding, EncryptionFlags, MdictMetadata)> {
    // Extract and parse version number
    let version_str = attrs
        .get("GeneratedByEngineVersion")
        .map(String::as_str)
        .unwrap_or("1.0");
    let version_f32: f32 = version_str.parse().map_err(|e| {
        MdictError::InvalidFormat(format!(
            "Could not parse 'GeneratedByEngineVersion': {}",
            e
        ))
    })?;

    // Convert to version enum for type-safe handling
    let version_enum = MdictVersion::try_from(version_f32)?;
    debug!("MDict version: {} (parsed as {:?})", version_str, version_enum);

    // Extract text encoding (defaults to UTF-8)
    let encoding = attrs
        .get("Encoding")
        .map(|s| utils::parse_encoding(s.as_str()))
        .unwrap_or(encoding_rs::UTF_8);
    debug!("Text encoding: {}", encoding.name());

    // Parse encryption bitmask
    let encryption_flags = attrs
        .get("Encrypted")
        .and_then(|s| s.parse::<u8>().ok())
        .map(|flag_val| {
            debug!("Encryption flags: {:#04x}", flag_val);
            EncryptionFlags {
                encrypt_record_blocks: (flag_val & 0x01) != 0,
                encrypt_key_index: (flag_val & 0x02) != 0,
            }
        })
        .unwrap_or_default();

    // Extract user-visible metadata
    let title = attrs
        .get("Title")
        .cloned()
        .unwrap_or_else(|| "Untitled Dictionary".to_string());
    let description = attrs.get("Description").cloned();
    let stylesheet = attrs.get("StyleSheet").cloned();
    let uuid = attrs.get("UUID").map(|s| s.as_bytes().to_vec());

    let metadata = MdictMetadata {
        title,
        engine_version: version_str.to_string(),
        description,
        stylesheet_raw: stylesheet,
        uuid,
    };

    Ok((version_enum, encoding, encryption_flags, metadata))
}

/// Attempts to derive a master decryption key from available credentials.
///
/// # Priority Order
/// 1. Explicit passcode (regcode + email) if provided
/// 2. UUID-based key for MDict v3.0 files
/// 3. `None` if no credentials available
///
/// # Parameters
/// * `passcode` - Optional `(regcode_hex, user_email)` tuple
/// * `uuid` - Optional UUID from v3.0 file header
/// * `version` - MDict version enum
fn try_derive_master_key(
    passcode: Option<(&str, &str)>,
    uuid: Option<&Vec<u8>>,
    version: MdictVersion,
) -> Result<MasterKey> {
    // Priority 1: Use explicit passcode if provided
    if let Some((reg_code_hex, user_email)) = passcode {
        info!("Deriving master decryption key from provided passcode");
        let reg_code = hex::decode(reg_code_hex)
            .map_err(|e| MdictError::DecryptionError(format!("Invalid regcode hex: {}", e)))?;

        if reg_code.len() != 16 {
            return Err(MdictError::DecryptionError(
                "Registration code must be exactly 16 bytes (32 hex chars)".to_string()
            ));
        }

        let master_key = crypto::derive_master_key(&reg_code, user_email.as_bytes())?;
        debug!("Master key derived successfully");
        return Ok(Some(master_key));
    }

    // Priority 2: Derive from UUID for v3.0 files
    if version == MdictVersion::V3
        && let Some(uuid_bytes) = uuid
    {
        info!("Deriving master key from UUID (v3.0)");
        let master_key = crypto::derive_key_from_uuid(uuid_bytes)?;
        debug!("Master key derived from UUID");
        return Ok(Some(master_key));
    }

    // No credentials available
    Ok(None)
}
