//! MDict header parsing and master key derivation

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16LE};
use quick_xml::{events::Event, Reader};
use adler32::adler32;
use hex;
use log::{debug, info, trace};
use super::models::{MdictHeader, MdictVersion, EncryptionFlags};
use super::crypto;
use super::error::{Result, MdictError};

/// Parse the MDict file header.
/// 
/// Header structure:
/// - 4 bytes: Header length (big-endian)
/// - N bytes: UTF-16LE XML content
/// - 4 bytes: Adler32 checksum (little-endian)
/// 
/// If the file is encrypted and a passcode is configured, derives the master key.
pub fn parse(file: &mut File, passcode: Option<(&str, &str)>) -> Result<MdictHeader> {
    info!("Parsing MDict header");

    // Read header length
    let header_len = file.read_u32::<BigEndian>()?;
    trace!("Header length: {} bytes", header_len);

    // Read header content
    let mut header_bytes = vec![0u8; header_len as usize];
    file.read_exact(&mut header_bytes)?;

    // Verify checksum
    let checksum_expected = file.read_u32::<LittleEndian>()?;
    let checksum_actual = adler32(header_bytes.as_slice())?;
    trace!("Header checksum: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
    if checksum_actual != checksum_expected {
        return Err(MdictError::ChecksumMismatch {
            expected: checksum_expected,
            actual: checksum_actual,
        });
    }

    // Decode UTF-16LE to string
    let (decoded_header, _, _) = UTF_16LE.decode(&header_bytes);

    // Sanitize XML (remove control characters except whitespace)
    let sanitized_header: String = decoded_header
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();

    // Parse XML attributes
    let attrs = parse_xml_attributes(&sanitized_header)?;

    // Build header struct
    let mut header = build_header_from_attributes(&attrs)?;

    // Derive master key if passcode provided
    header.master_key = try_derive_master_key(passcode)?;

    info!(
        "Header parsed successfully: version={}, title='{}', encoding={}, encrypted=(blocks={}, index={})",
        header.engine_version,
        header.title,
        header.encoding.name(),
        header.encryption_flags.encrypt_record_blocks,
        header.encryption_flags.encrypt_key_index
    );

    Ok(header)
}

/// Parse XML string to extract attributes as HashMap.
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

/// Build MdictHeader from XML attributes.
fn build_header_from_attributes(attrs: &HashMap<String, String>) -> Result<MdictHeader> {
    // Parse version
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

    // Convert to behavioral enum for parsing logic
    let version_enum = MdictVersion::try_from(version_f32)?;
    debug!("MDict version: {} (parsed as {:?})", version_str, version_enum);

    // Parse encoding (normalize GBK/GB2312 to GB18030)
    let encoding = attrs
        .get("Encoding")
        .map(|s| if s == "GBK" || s == "GB2312" { "GB18030" } else { s.as_str() })
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    debug!("Text encoding: {}", encoding.name());

    // Parse encryption flags
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

    // Extract metadata
    let title = attrs
        .get("Title")
        .cloned()
        .unwrap_or_else(|| "Untitled Dictionary".to_string());
    let description = attrs.get("Description").cloned();
    let stylesheet = attrs.get("StyleSheet").cloned();

    Ok(MdictHeader {
        version: version_enum,
        engine_version: version_str.to_string(),
        encryption_flags,
        encoding,
        title,
        description,
        stylesheet,
        master_key: None, // Will be set separately
    })
}

/// Derive master key if passcode is provided.
/// 
/// In production, passcode should come from user input or config.
/// Format: (registration_code_hex, email)
fn try_derive_master_key(
    passcode: Option<(&str, &str)>,
) -> Result<Option<[u8; 16]>> {
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

    // No passcode provided, no key to derive.
    Ok(None)
}
