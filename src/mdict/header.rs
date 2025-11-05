//! MDict header parsing and master key derivation

use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16LE};
use quick_xml::{events::Event, Reader};
use adler32::adler32;
use hex;
use super::models::{MdictHeader, EncryptionFlags};
use super::crypto;

/// Parse the MDict file header.
/// 
/// Header structure:
/// - 4 bytes: Header length (big-endian)
/// - N bytes: UTF-16LE XML content
/// - 4 bytes: Adler32 checksum (little-endian)
/// 
/// If the file is encrypted and a passcode is configured, derives the master key.
pub fn parse(file: &mut File) -> Result<MdictHeader, Box<dyn Error>> {
    println!("=== Parsing Header ===");

    // Read header length
    let header_len = file.read_u32::<BigEndian>()?;
    
    // Read header content
    let mut header_bytes = vec![0u8; header_len as usize];
    file.read_exact(&mut header_bytes)?;
    
    // Verify checksum
    let checksum_expected = file.read_u32::<LittleEndian>()?;
    let checksum_actual = adler32(&header_bytes[..])?;
    if checksum_actual != checksum_expected {
        return Err(format!(
            "Header checksum mismatch: expected 0x{:08X}, got 0x{:08X}",
            checksum_expected, checksum_actual
        ).into());
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
    
    // Derive master key if needed
    header.master_key = derive_master_key_if_needed(&header)?;
    
    println!("Header parsed: version={}, title={}, encrypted={:?}", 
        header.version, header.title, header.encryption_flags);
    
    Ok(header)
}

/// Parse XML string to extract attributes as HashMap.
fn parse_xml_attributes(xml: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                return e.attributes()
                    .map(|attr_result| {
                        let attr = attr_result?;
                        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                        let value = attr.unescape_value()?.into_owned();
                        Ok((key, value))
                    })
                    .collect();
            }
            Ok(Event::Eof) => return Err("No root element found in header XML".into()),
            Err(e) => return Err(e.into()),
            _ => {}
        }
        buf.clear();
    }
}

/// Build MdictHeader from XML attributes.
fn build_header_from_attributes(attrs: &HashMap<String, String>) -> Result<MdictHeader, Box<dyn Error>> {
    // Parse version
    let version_str = attrs
        .get("GeneratedByEngineVersion")
        .map(String::as_str)
        .unwrap_or("1.0");
    let version: f32 = version_str.parse()?;
    
    // Check version support
    if version >= 3.0 {
        return Err(format!(
            "Unsupported MDict version {}. Only v1.x and v2.x are supported.",
            version
        ).into());
    }
    
    // Version determines number width (v1=4 bytes, v2=8 bytes)
    let number_width = if version >= 2.0 { 8 } else { 4 };
    
    // Parse encoding (normalize GBK/GB2312 to GB18030)
    let encoding = attrs
        .get("Encoding")
        .map(|s| if s == "GBK" || s == "GB2312" { "GB18030" } else { s.as_str() })
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    
    // Parse encryption flags
    let encryption_flags = attrs
        .get("Encrypted")
        .and_then(|s| s.parse::<u8>().ok())
        .map(|flag_val| EncryptionFlags {
            encrypt_record_blocks: (flag_val & 0x01) != 0,
            encrypt_key_index: (flag_val & 0x02) != 0,
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
        version,
        encryption_flags,
        encoding,
        number_width,
        title,
        description,
        stylesheet,
        master_key: None, // Will be set separately
    })
}

/// Derive master key if file is encrypted and passcode is provided.
/// 
/// In production, passcode should come from user input or config.
/// Format: (registration_code_hex, email)
fn derive_master_key_if_needed(header: &MdictHeader) -> Result<Option<[u8; 16]>, Box<dyn Error>> {
    // TODO: In production, load from config or prompt user
    let passcode: Option<(&str, &str)> = None;
    // Example: Some(("0123456789ABCDEF0123456789ABCDEF", "user@example.com"))
    
    if let Some((reg_code_hex, user_email)) = passcode {
        if header.encryption_flags.encrypt_record_blocks {
            println!("Deriving master key from passcode...");
            let reg_code = hex::decode(reg_code_hex)?;
            let master_key = crypto::derive_master_key(&reg_code, user_email.as_bytes())?;
            return Ok(Some(master_key));
        }
    }
    
    Ok(None)
}
