//! MDict header parsing and master key derivation

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use encoding_rs::UTF_16LE;
use quick_xml::{events::Event, Reader};
use adler2::adler32_slice;
use hex;
use log::{debug, info, warn, trace};
use super::models::{MdictHeader, MdictVersion, EncryptionFlags, BlockType};
use super::{utils, crypto};
use super::error::{Result, MdictError};

/// Parse the MDict file header.
/// 
/// Header structure:
/// - 4 bytes: Header length (big-endian)
/// - N bytes: XML content (UTF-16LE for v1/v2, UTF-8 for v3)
/// - 4 bytes: Adler32 checksum (little-endian)
/// 
/// If the file is encrypted and a passcode is configured, derives the master key.
pub fn parse<R: Read>(
    file: &mut R,
    passcode: Option<(&str, &str)>,
) -> Result<MdictHeader> {
    info!("Parsing MDict header");

    // Read header length
    let header_len = file.read_u32::<BigEndian>()?;
    trace!("Header length: {} bytes", header_len);

    // Read header content
    let mut header_bytes = vec![0u8; header_len as usize];
    file.read_exact(&mut header_bytes)?;

    // Verify checksum
    let checksum_expected = file.read_u32::<LittleEndian>()?;
    let checksum_actual = adler32_slice(header_bytes.as_slice());
    trace!("Header checksum: expected={:#010x}, actual={:#010x}", checksum_expected, checksum_actual);
    if checksum_actual != checksum_expected {
        return Err(MdictError::ChecksumMismatch {
            expected: checksum_expected,
            actual: checksum_actual,
        });
    }

    // Decode header based on encoding detection
    // v1/v2: UTF-16LE (ends with \x00\x00)
    // v3:    UTF-8 (ends with \x00)
    let decoded_header = if header_bytes.ends_with(&[0, 0]) {
        debug!("Header ends with \\x00\\x00, decoding as UTF-16LE (likely v1/v2)");
        // The spec implies the terminator should be removed before decoding.
        let trimmed_bytes = &header_bytes[..header_bytes.len() - 2];
        let (s, _, _) = UTF_16LE.decode(trimmed_bytes);
        s.into_owned()
    } else {
        debug!("Header does not end with \\x00\\x00, decoding as UTF-8 (likely v3)");
        // V3 headers are not null-terminated in the same way.
        // We use from_utf8_lossy to be safe, though it should be valid UTF-8.
        String::from_utf8_lossy(&header_bytes).into_owned()
    };

    // Sanitize XML (remove control characters except whitespace)
    let sanitized_header: String = decoded_header
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();

    // Parse XML attributes
    let attrs = parse_xml_attributes(&sanitized_header)?;

    // Build header struct
    let mut header = build_header_from_attributes(&attrs)?;
    
    // Final check: If the XML parsing succeeded but gave us a version that
    // contradicts our encoding guess, something is very wrong.
    if header.version == MdictVersion::V3 && !header_bytes.ends_with(&[0, 0]) {
        debug!(
            "Consistency check passed: Version is {} (>= 3.0) and header was parsed as UTF-8.",
            header.engine_version
        );
    } else if header.version != MdictVersion::V3 && header_bytes.ends_with(&[0, 0]) {
        debug!(
            "Consistency check passed: Version is {} (< 3.0) and header was parsed as UTF-16LE.",
            header.engine_version
        );
    } else {
        warn!(
            "Potential header encoding mismatch! Guessed encoding based on terminator ('{}'), but parsed version is: {}. The file may not be parsed correctly.",
            if header_bytes.ends_with(&[0, 0]) { "ends with 0x0000" } else { "no 0x0000 suffix" },
            header.engine_version
        );
    }

    // Derive master key if passcode provided or UUID for v3
    header.master_key = try_derive_master_key(
        passcode,
        header.uuid.as_ref(),
        header.version,
    )?;

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

    // Parse encoding from header
    let encoding = attrs
        .get("Encoding")
        .map(|s| utils::parse_encoding(s.as_str()))
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
    let uuid = attrs.get("UUID").map(|s| s.as_bytes().to_vec());

    Ok(MdictHeader {
        version: version_enum,
        engine_version: version_str.to_string(),
        encryption_flags,
        encoding,
        title,
        description,
        stylesheet,
        master_key: None, // Will be set separately
        uuid,
    })
}

/// Derive master key if passcode is provided.
/// 
/// In production, passcode should come from user input or config.
/// Format: (registration_code_hex, email)
fn try_derive_master_key(
    passcode: Option<(&str, &str)>,
    uuid: Option<&Vec<u8>>,
    version: MdictVersion,
) -> Result<Option<[u8; 16]>> {
    // Priority 1: Explicit passcode
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

    // Priority 2: UUID-based key (v3.0+ only)
    if version == MdictVersion::V3
        && let Some(uuid_bytes) = uuid {
            info!("Deriving master key from UUID (v3.0)");
            let master_key = crypto::derive_key_from_uuid(uuid_bytes)?;
            debug!("Master key derived from UUID");
            return Ok(Some(master_key));
        }

    // No passcode or UUID provided, no key to derive.
    Ok(None)
}

/// Scan the file to locate v3.0 block offsets.
/// Returns (key_data_offset, key_index_offset, record_data_offset, record_index_offset).
/// Returns an error if any of the four required blocks are missing.
pub fn scan_v3_block_offsets<R: Read + Seek>(
    file: &mut R,
    start_offset: u64,
) -> Result<(u64, u64, u64, u64)> {
    info!("Scanning v3.0 file structure for block offsets");

    file.seek(SeekFrom::Start(start_offset))?;

    let mut offsets = [
        (BlockType::KeyData, None),
        (BlockType::KeyIndex, None),
        (BlockType::RecordData, None),
        (BlockType::RecordIndex, None),
    ];

    while let Ok(block_type_raw) = file.read_u32::<BigEndian>() {
        let block_type = BlockType::try_from(block_type_raw)?;
        let block_size = file.read_u64::<BigEndian>()?;
        let block_data_offset = file.stream_position()?;

        trace!(
            "Found block: type={:?}, size={} bytes, offset={}",
            block_type, block_size, block_data_offset
        );

        // Find the corresponding offset in our array and set it
        if let Some(offset) = offsets.iter_mut().find(|(t, _)| *t == block_type) {
            offset.1 = Some(block_data_offset);
        } else {
            // This case should not be reached with our BlockType enum, but good for safety
            warn!("Ignoring unknown block type: {:#010x}", block_type_raw);
        }

        // Skip to the next block header
        file.seek(SeekFrom::Current(block_size as i64))?;
    }

    // Unpack the results, checking for missing blocks
    let get_offset = |block_type: BlockType| {
        offsets
            .iter()
            .find(|(t, _)| *t == block_type)
            .and_then(|(_, o)| *o)
            .ok_or_else(|| MdictError::InvalidFormat(format!("Missing {:?} block in v3.0 file", block_type)))
    };

    let key_data_offset = get_offset(BlockType::KeyData)?;
    let key_index_offset = get_offset(BlockType::KeyIndex)?;
    let record_data_offset = get_offset(BlockType::RecordData)?;
    let record_index_offset = get_offset(BlockType::RecordIndex)?;

    info!(
        "V3.0 block scan complete: key_data={}, key_index={}, record_data={}, record_index={}",
        key_data_offset, key_index_offset, record_data_offset, record_index_offset
    );

    Ok((key_data_offset, key_index_offset, record_data_offset, record_index_offset))
}
