// --- Standard Library Imports ---
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Result as IoResult, Error as IoError, ErrorKind as IoErrorKind};
// --- External Crate Imports ---
use adler32::adler32;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16LE, UTF_16BE};
use flate2::read::ZlibDecoder;
use lzokay::decompress::decompress as lzokay_decompress;
use quick_xml::{events::Event, Error as XmlError, Reader};
use ripemd::{Digest, Ripemd128};

// --- Data Structures ---

/// Defines the known MDict encryption schemes.
#[derive(Debug)]
pub enum EncryptionType {
    /// No encryption.
    None,
    /// Record blocks are encrypted (`Encrypted` = "1" or "Yes").
    RecordBlock,
    /// The key index is encrypted (`Encrypted` = "2").
    KeyIndex,
}

/// Structured metadata parsed from the MDict header XML.
#[derive(Debug)]
pub struct MdictHeader {
    // --- Fields for parsing ---
    pub version: f32,
    pub encryption_type: EncryptionType,
    pub encoding: &'static Encoding,
    pub number_width: usize,

    // --- Fields for dictionary info & behavior ---
    pub title: String,
    pub description: Option<String>,
    pub stylesheet: Option<String>,
}


/// Metadata for the key index and key blocks section.
#[derive(Debug)]
pub struct KeyBlockInfo {
    pub num_key_blocks: u64,
    pub num_entries: u64,
    pub key_index_decomp_len: Option<u64>, // None for v1.x
    pub key_index_comp_len: u64,
    pub key_blocks_len: u64,
}

/// Represents the metadata for a single, complete key block.
#[derive(Debug)]
pub struct KeyBlock {
    pub compressed_size: u64,
    pub decompressed_size: u64,
}

/// Represents a final, extracted headword and its corresponding record ID.
#[derive(Debug)]
pub struct Headword {
    pub id: u64,
    pub text: String,
}

// --- Implementation & Helpers ---

impl MdictHeader {
    /// Creates an `MdictHeader` by interpreting raw XML attributes.
    pub fn from_attributes(attrs: &HashMap<String, String>) -> Self {
        // --- Fields for parsing ---
        // v2.0+ uses 8-byte numbers; earlier versions use 4-byte.
        let version = attrs
            .get("GeneratedByEngineVersion")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1.0);
        let number_width = if version >= 2.0 { 8 } else { 4 };

        // Normalize non-standard encoding labels (e.g., "GBK") for the `encoding_rs` crate.
        let encoding = attrs
            .get("Encoding")
            .map(|s| if s == "GBK" || s == "GB2312" { "GB18030" } else { s })
            .and_then(|label| Encoding::for_label(label.as_bytes()))
            .unwrap_or(encoding_rs::UTF_8);

        // Map the "Encrypted" attribute string to its corresponding enum variant.
        let encryption_type = match attrs.get("Encrypted").map(String::as_str) {
            Some("Yes") | Some("1") => EncryptionType::RecordBlock,
            Some("2") => EncryptionType::KeyIndex,
            _ => EncryptionType::None,
        };

        // --- Fields for dictionary info & behavior ---
        let title = attrs
            .get("Title")
            .map(String::from)
            .unwrap_or_else(|| "Untitled Dictionary".to_string());
        
        let description = attrs.get("Description").map(String::from);
        
        let stylesheet = attrs.get("StyleSheet").map(String::from);
        MdictHeader {
            version,
            encryption_type,
            encoding,
            number_width,
            title,
            description,
            stylesheet,
        }
    }
}

/// Reads a 4- or 8-byte big-endian number based on the MDict version.
fn read_number(reader: &mut impl Read, number_width: usize) -> IoResult<u64> {
    match number_width {
        8 => reader.read_u64::<BigEndian>(),
        4 => reader.read_u32::<BigEndian>().map(u64::from),
        2 => reader.read_u16::<BigEndian>().map(u64::from),
        1 => reader.read_u8().map(u64::from),
        _ => Err(IoError::from(IoErrorKind::InvalidInput)),
    }
}

/// Implements the v2 key index key derivation algorithm using RIPEMD128.
fn derive_key_for_v2_index(key_index_block: &[u8]) -> [u8; 16] {
    let mut hasher = Ripemd128::new();
    // Per the spec, the hash input is the 4-byte block checksum...
    hasher.update(&key_index_block[4..8]);
    // ...and a 4-byte magic constant (0x3695).
    hasher.update(&0x3695u32.to_le_bytes());
    hasher.finalize().into()
}

/// Decrypts data using the custom XOR obfuscation algorithm from the MDict format.
fn fast_decrypt(data: &mut [u8], key: &[u8]) {
    // The algorithm's initial state starts with a magic byte (0x36).
    let mut prev = 0x36u8;
    for (i, byte) in data.iter_mut().enumerate() {
        let current = *byte;
        // This is a 4-bit nibble swap, a required step in the algorithm.
        let rotated = current.rotate_left(4);
        *byte = rotated ^ prev ^ (i as u8) ^ key[i % key.len()];
        // The next iteration's state depends on the *original*, pre-decryption byte.
        prev = current;
    }
}

/// Reads a single key text from the reader based on version and encoding.
fn read_key_text(
    reader: &mut &[u8],
    mdict_header: &MdictHeader,
) -> Result<(), Box<dyn Error>> {
    // 1. Read the length of the text in "units" (bytes for UTF-8, u16s for UTF-16).
    let text_size = if mdict_header.version >= 2.0 {
        read_number(reader, 2)?
    } else {
        read_number(reader, 1)?
    };

    // 2. Determine the length of the null terminator in "units".
    // V2 dictionaries have a 1-unit terminator, V1 has none.
    let text_term = if mdict_header.version < 2.0 { 0 } else { 1 };
    
    // 3. Determine the width of a single "unit" in bytes.
    let unit_width = if mdict_header.encoding == UTF_16LE || mdict_header.encoding == UTF_16BE {
        2
    } else {
        1
    };

    // 4. Calculate the total number of bytes to read from the file.
    let total_units = text_size + text_term;
    let total_bytes = total_units as usize * unit_width;

    *reader = &reader[total_bytes..];
    Ok(())
}


/// Performs decompression on a raw payload using the specified algorithm.
fn perform_decompression(
    payload: &[u8],
    compression_type: u32,
    decompressed_size: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let decompressed_bytes = match compression_type {
        2 => { // zlib
            let mut decompressed = Vec::with_capacity(decompressed_size as usize);
            let mut decoder = ZlibDecoder::new(payload);
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        },
        1 => { // lzo
            let mut decompressed = vec![0; decompressed_size as usize];
            let size = lzokay_decompress(payload, &mut decompressed)?;
            assert_eq!(size as u64, decompressed_size, "LZO decompressed size mismatch.");
            decompressed
        },
        0 => { // No compression
            payload.to_vec()
        }
        _ => panic!("Unsupported compression type: {}", compression_type),
    };

    // Final check to ensure the output size is exactly what was expected.
    assert_eq!(decompressed_bytes.len() as u64, decompressed_size);
    Ok(decompressed_bytes)
}

/// Reads a null-terminated string from a byte slice, decodes it, and advances the slice.
fn read_null_terminated_string (
    reader: &mut &[u8],
    mdict_header: &MdictHeader,
) -> Result<String, Box<dyn Error>> {
    let terminator_width;
    let end_pos;

    if mdict_header.encoding == UTF_16LE || mdict_header.encoding == UTF_16BE {
        // For UTF-16, the terminator is two null bytes.
        terminator_width = 2;
        end_pos = reader
            .windows(2)
            .position(|window| window == [0, 0])
            .ok_or("Unterminated UTF-16 string found in key block.")?;
    } else {
        // For other encodings (UTF-8, GB18030), the terminator is a single null byte.
        terminator_width = 1;
        end_pos = reader
            .iter()
            .position(|&byte| byte == 0)
            .ok_or("Unterminated string found in key block.")?;
    }

    // Decode the text slice before the terminator.
    let text_bytes = &reader[..end_pos];
    let (text, _, _) = mdict_header.encoding.decode(text_bytes);

    // Advance the reader past the text and its terminator.
    *reader = &reader[end_pos + terminator_width..];

    Ok(text.into_owned())
}



fn main() -> Result<(), Box<dyn Error>> {
    let mut file = File::open("data/test_dict.mdx")?;

    // MDX format: 4-byte big-endian integer for header length.
    let header_length = file.read_u32::<BigEndian>()?;
    println!("Reading header length: OK. ({} bytes)", header_length);

    let mut header_content_bytes = vec![0; header_length as usize];
    file.read_exact(&mut header_content_bytes)?;
    println!("Reading header content: OK.");

    // MDX format: 4-byte little-endian Adler32 checksum of the header.
    let checksum_from_file = file.read_u32::<LittleEndian>()?;
    println!("Reading header checksum: OK.");

    let calculated_checksum = adler32(&header_content_bytes[..])?;
    assert_eq!(
        calculated_checksum,
        checksum_from_file,
        "Header checksum mismatch!"
    );
    println!("Verifying header checksum: OK.");

    // MDX headers are encoded in UTF-16LE.
    let (decoded_header, _, _) = UTF_16LE.decode(&header_content_bytes);
    println!("Decoding header text (UTF-16LE): OK.");

    // MDX headers can contain control characters that break XML parsers. We filter
    // them out, preserving only valid whitespace, to ensure well-formed XML.
    let sanitized_header_text: String = decoded_header
        .as_ref()
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();
    println!("Sanitizing header XML: OK.");

    let mut reader = Reader::from_str(&sanitized_header_text);
    println!("Creating XML reader: OK.");

    let mut buf = Vec::new();
    let header_attrs_result: Result<HashMap<String, String>, XmlError> = loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                println!(
                    "Finding root tag: OK. (<{}>)",
                    String::from_utf8_lossy(e.name().as_ref())
                );

                // By mapping over the attributes and collecting into a Result, we ensure
                // that the entire operation fails if any single attribute is malformed. [1, 2, 3]
                let attrs_result = e
                    .attributes()
                    .map(|attr_result| {
                        let attr = attr_result?;

                        // Use from_utf8_lossy for robustness; some MDX attribute keys have bad encodings.
                        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();

                        // Unescape XML entities (e.g., &amp;) and take ownership of the
                        // value to store it in the HashMap.
                        let value = attr.unescape_value()?.into_owned();

                        Ok((key, value))
                    })
                    .collect();

                break attrs_result;
            }
            Ok(Event::Eof) => panic!("Reached end of XML without finding a root element."),
            Err(e) => break Err(e),
            _ => (),
        }
    };
    buf.clear();

    // The parsing operation returns a Result, which we handle once here.
    let header_attrs = header_attrs_result?;
    println!(
        "Parsing header attributes: OK. (Found {} attributes)",
        header_attrs.len()
    );
    // println!("{:#?}", header_attrs);
    let mdict_header = MdictHeader::from_attributes(&header_attrs);
    println!("Constructing MdictHeader: OK.");
    println!("{:#?}", mdict_header);

    println!("Reading key block info...");

    // The header for key block metadata varies in size by version.
    // v2.0+ uses 5 u64s (5 * 8 = 40 bytes).
    // v1.x uses 4 u32s (4 * 4 = 16 bytes).
    let key_block_info_size = if mdict_header.version >= 2.0 { 40 } else { 16 };
    let mut key_block_info_bytes = vec![0; key_block_info_size];
    file.read_exact(&mut key_block_info_bytes)?;
    println!("Reading key block info bytes: OK.");

    // v2.0+ includes a checksum for this header, which we must verify.
    if mdict_header.version >= 2.0 {
        let checksum_from_file = file.read_u32::<BigEndian>()?;
        println!("Reading key block info checksum (v2): OK.");

        let calculated_checksum = adler32(&key_block_info_bytes[..])?;

        assert_eq!(
            calculated_checksum,
            checksum_from_file,
            "Key block info checksum mismatch!"
        );
        println!("Verifying key block info checksum: OK.");
    }

    // Parse the metadata from the header bytes.
    let mut reader = &key_block_info_bytes[..];
    let key_block_info = KeyBlockInfo {
        num_key_blocks: read_number(&mut reader, mdict_header.number_width)?,
        num_entries: read_number(&mut reader, mdict_header.number_width)?,
        // Conditionally parse this field only if we are on v2.0+.
        key_index_decomp_len: if mdict_header.version >= 2.0 {
            Some(read_number(&mut reader, mdict_header.number_width)?)
        } else {
            None
        },
        key_index_comp_len: read_number(&mut reader, mdict_header.number_width)?,
        key_blocks_len: read_number(&mut reader, mdict_header.number_width)?,
    };

    println!("Constructing KeyBlockInfo: OK.");
    println!("{:#?}", key_block_info);

    println!("Reading key index...");
    let mut key_index_comp_bytes = vec![0; key_block_info.key_index_comp_len as usize];
    file.read_exact(&mut key_index_comp_bytes)?;
    println!("Reading compressed key index: OK.");

    let key_index_decomp_bytes: Vec<u8>;

    // The presence of `key_index_decomp_len` distinguishes v2.0+ formats from v1.x.
    if let Some(decomp_len) = key_block_info.key_index_decomp_len {
        // -- START of V2 KEY INDEX LOGIC --
        println!("Processing v2 key index...");

        let payload: &[u8];
        let mut decrypted_payload: Vec<u8>; // Must live long enough

        // Check for KeyIndex encryption (`Encrypted="2"`).
        if let EncryptionType::KeyIndex = mdict_header.encryption_type {
            println!("Key index is encrypted. Decrypting...");
            // Derive the key using the RIPEMD128 algorithm specified for this block.
            let key = derive_key_for_v2_index(&key_index_comp_bytes);
            // Decrypt the payload portion (from byte 8) of the block.
            decrypted_payload = key_index_comp_bytes[8..].to_vec();
            fast_decrypt(&mut decrypted_payload, &key);
            payload = &decrypted_payload;
        } else {
            // If not encrypted, the payload for decompression is the original block past the header.
            payload = &key_index_comp_bytes[8..];
        }

        // The first 4 bytes of the block define the compression type, in little-endian.
        let compression_type = LittleEndian::read_u32(&key_index_comp_bytes[0..4]);
        key_index_decomp_bytes = perform_decompression(
            payload, // This is the (possibly decrypted) payload
            compression_type,
            decomp_len,
        )?;

        // The checksum in the v2 header is calculated on the DECOMPRESSED data.
        let checksum_from_header = BigEndian::read_u32(&key_index_comp_bytes[4..8]);
        let calculated_checksum = adler32(&key_index_decomp_bytes[..])?;
        assert_eq!(
            calculated_checksum, checksum_from_header,
            "V2 Key Index checksum mismatch after decompression!"
        );
        println!("Verifying v2 key index checksum: OK.");
    } else {
        // --- V1.x KEY INDEX LOGIC ---
        // Per the spec, the v1.x key index block is raw binary data with no compression.
        println!("Processing v1 key index (no compression): OK.");
        key_index_decomp_bytes = key_index_comp_bytes;
    }

    println!(
        "Key index processed. Final size: {} bytes.",
        key_index_decomp_bytes.len()
    );

    println!("Parsing key index metadata...");
    let mut key_block_infos: Vec<KeyBlock> = Vec::new();
    let mut reader = &key_index_decomp_bytes[..];
    let mut calculated_num_entries = 0;
    while !reader.is_empty() { // Using is_empty() is a common pattern for slices
        let num_entries = read_number(&mut reader, mdict_header.number_width)?;
        calculated_num_entries += num_entries;

        read_key_text(&mut reader, &mdict_header)?;
        read_key_text(&mut reader, &mdict_header)?;
        // println!("  Keys: '{}' -> '{}'", _first_key, _last_key);

        let compressed_size = read_number(&mut reader, mdict_header.number_width)?;
        let decompressed_size = read_number(&mut reader, mdict_header.number_width)?;

        key_block_infos.push(KeyBlock {
            compressed_size,
            decompressed_size,
        });
    }

    println!(
        "Finished parsing key index. Found {} key blocks.",
        key_block_infos.len()
    );
    // println!("{:#?}", key_block_infos);
    assert_eq!(
        calculated_num_entries,
        key_block_info.num_entries,
        "Mismatch between calculated entries and header's total entry count!"
    );
    println!(
        "Total entries calculated from index: {}",
        calculated_num_entries
    );

    println!("--- Starting Key Block Processing ---");
    let mut all_headwords: Vec<Headword> = Vec::new();

    for key_block_info in key_block_infos.iter() {
        // Read the entire compressed block for this entry.
        let mut compressed_bytes = vec![0; key_block_info.compressed_size as usize];
        file.read_exact(&mut compressed_bytes)?;

        // The first 8 bytes of each block are a header.
        // Bytes 0-3: Compression Type
        // Bytes 4-7: Adler32 Checksum
        let compression_type = LittleEndian::read_u32(&compressed_bytes[0..4]);
        let checksum_from_header = BigEndian::read_u32(&compressed_bytes[4..8]);
        let payload = &compressed_bytes[8..];
        
        // Decompress the payload first.
        let decompressed_bytes = perform_decompression(
            payload,
            compression_type,
            key_block_info.decompressed_size,
        )?;

        // For v1 and v2 dictionaries, the checksum is calculated on the DECOMPRESSED data.
        // This was the source of the panic.
        let calculated_checksum = adler32(&decompressed_bytes[..])?;
        assert_eq!(
            calculated_checksum, checksum_from_header,
            "Key block checksum mismatch after decompression!"
        );

        // --- Parse the decompressed bytes into Headwords ---
        let mut block_reader = &decompressed_bytes[..];
        while !block_reader.is_empty() {
            let record_id = read_number(&mut block_reader, mdict_header.number_width)?;
            let text = read_null_terminated_string(&mut block_reader, &mdict_header)?;
            
            all_headwords.push(Headword {
                id: record_id,
                text,
            });
        }
    }

    println!(
        "Finished processing all key blocks. Total headwords found: {}",
        all_headwords.len()
    );

    // Final sanity check
    assert_eq!(key_block_info.num_entries, all_headwords.len() as u64);
    println!("Verified that the number of parsed headwords matches the total entry count.");

    Ok(())
}