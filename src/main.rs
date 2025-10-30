// --- Standard Library Imports ---
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
// --- External Crate Imports ---
use adler32::adler32;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16LE, UTF_16BE};
use flate2::read::ZlibDecoder;
use lzokay::decompress::decompress as lzokay_decompress;
use quick_xml::{events::Event, Reader};
use ripemd::{Digest, Ripemd128};

// --- Data Structures ---

/// Represents the MDict encryption bitfield.
#[derive(Debug, Default)]
pub struct EncryptionFlags {
    /// Corresponds to the 0x01 bitflag.
    pub encrypt_record_blocks: bool,
    /// Corresponds to the 0x02 bitflag.
    pub encrypt_key_index: bool,
}

/// Structured metadata parsed from the MDict header XML.
#[derive(Debug)]
pub struct MdictHeader {
    pub version: f32,
    pub encryption_flags: EncryptionFlags,
    pub encoding: &'static Encoding,
    pub number_width: usize,
    pub title: String,
    pub description: Option<String>,
    pub stylesheet: Option<String>,
}

/// Metadata for the key index and key blocks section.
#[derive(Debug)]
pub struct KeyBlockInfo {
    pub num_key_blocks: u64,
    pub num_entries: u64,
    pub key_index_decomp_len: Option<u64>,
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
    /// Fails if the MDict version is 3.0 or higher, as it is unsupported.
    pub fn from_attributes(attrs: &HashMap<String, String>) -> Result<Self, Box<dyn Error>> {
        let version_str = attrs.get("GeneratedByEngineVersion").map(String::as_str).unwrap_or("1.0");
        let version = version_str.parse::<f32>()?;

        // MDX Format: Version 3.0+ uses entirely different block structures and
        // checksum algorithms (xxhash) that are not yet supported.
        if version >= 3.0 {
            return Err(format!("Unsupported MDict version {} found. Only v1.x and v2.x are supported.", version).into());
        }

        let number_width = if version >= 2.0 { 8 } else { 4 };

        // MDX Format: Normalize non-standard encoding labels (e.g., "GBK") for compatibility.
        let encoding = attrs
            .get("Encoding")
            .map(|s| if s == "GBK" || s == "GB2312" { "GB18030" } else { s })
            .and_then(|label| Encoding::for_label(label.as_bytes()))
            .unwrap_or(encoding_rs::UTF_8);

        let encryption_flags = attrs.get("Encrypted")
            .and_then(|s| s.parse::<u8>().ok())
            .map(|flag_val| EncryptionFlags {
                encrypt_record_blocks: (flag_val & 0x01) != 0,
                encrypt_key_index: (flag_val & 0x02) != 0,
            })
            .unwrap_or_default(); 

        let title = attrs.get("Title").cloned().unwrap_or_else(|| "Untitled Dictionary".to_string());
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
        })
    }
}

/// Reads a number (4 or 8 bytes, big-endian) based on the MDict version.
fn read_number(reader: &mut impl Read, number_width: usize) -> Result<u64, Box<dyn Error>> {
    Ok(match number_width {
        8 => reader.read_u64::<BigEndian>()?,
        4 => reader.read_u32::<BigEndian>().map(u64::from)?,
        _ => return Err("Unsupported number width for read_number.".into()),
    })
}

/// Reads a number with a smaller width (1 or 2 bytes) for text length prefixes.
fn read_small_number(reader: &mut impl Read, number_width: usize) -> Result<u64, Box<dyn Error>> {
    Ok(match number_width {
        2 => reader.read_u16::<BigEndian>().map(u64::from)?,
        1 => reader.read_u8().map(u64::from)?,
        _ => return Err("Unsupported number width for read_small_number.".into()),
    })
}

/// Implements the v2 key index key derivation algorithm using RIPEMD128.
fn derive_key_for_v2_index(key_index_block: &[u8]) -> [u8; 16] {
    let mut hasher = Ripemd128::new();
    // MDX Format (v2): The decryption key for the key index is a hash of the
    // block's checksum (bytes 4-8) and a fixed magic number.
    hasher.update(&key_index_block[4..8]);
    hasher.update(&0x3695u32.to_le_bytes());
    hasher.finalize().into()
}

/// Decrypts data using the custom XOR obfuscation algorithm from the MDict format.
fn fast_decrypt(data: &mut [u8], key: &[u8]) {
    let mut prev = 0x36u8;
    for (i, byte) in data.iter_mut().enumerate() {
        let current = *byte;
        // MDX Algorithm: Each byte is rotated, then XORed with the previous *original*
        // byte, its index, and a byte from the key.
        let rotated = current.rotate_left(4);
        *byte = rotated ^ prev ^ (i as u8) ^ key[i % key.len()];
        prev = current;
    }
}

/// Skips over a length-prefixed key text in a slice reader.
fn parse_key_text(reader: &mut &[u8], mdict_header: &MdictHeader) -> Result<(), Box<dyn Error>> {
    // MDX Format: The length of the key text is stored in "units". For UTF-8, 1 unit = 1 byte.
    // For UTF-16, 1 unit = 1 character (2 bytes).
    let text_len_in_units = if mdict_header.version >= 2.0 {
        read_small_number(reader, 2)?
    } else {
        read_small_number(reader, 1)?
    };

    // MDX Format (v2): A 1-unit terminator follows the text (1 byte for UTF-8, 2 for UTF-16).
    // MDX Format (v1): No terminator is used.
    let terminator_len_in_units = if mdict_header.version < 2.0 { 0 } else { 1 };
    
    // The width of a single "unit" in bytes depends on the encoding.
    let unit_width_in_bytes = if mdict_header.encoding == UTF_16LE || mdict_header.encoding == UTF_16BE { 2 } else { 1 };

    // Calculate the total number of bytes to skip over.
    let total_bytes_to_skip = (text_len_in_units + terminator_len_in_units) as usize * unit_width_in_bytes;

    if reader.len() < total_bytes_to_skip {
        return Err("Incomplete key text found while parsing key index.".into());
    }

    // Advance the reader by the calculated number of bytes.
    *reader = &reader[total_bytes_to_skip..];
    Ok(())
}


/// Performs decompression on a raw payload using the specified algorithm.
fn perform_decompression(
    payload: &[u8],
    compression_type: u32,
    decompressed_size: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let decompressed_bytes = match compression_type {
        // MDX Compression: Type 2 is zlib.
        2 => {
            let mut decompressed = Vec::with_capacity(decompressed_size as usize);
            let mut decoder = ZlibDecoder::new(payload);
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        },
        // MDX Compression: Type 1 is LZO.
        1 => {
            let mut decompressed = vec![0; decompressed_size as usize];
            lzokay_decompress(payload, &mut decompressed)?;
            decompressed
        },
        // MDX Compression: Type 0 is no compression.
        0 => payload.to_vec(),
        _ => return Err(format!("Unsupported compression type: {}", compression_type).into()),
    };

    // This assertion is critical for confirming the integrity of the decompressed data.
    assert_eq!(decompressed_bytes.len() as u64, decompressed_size, "Decompressed size mismatch.");
    Ok(decompressed_bytes)
}

/// Reads a null-terminated string from a byte slice, decodes it, and advances the slice.
fn read_null_terminated_string(
    reader: &mut &[u8],
    encoding: &'static Encoding,
) -> Result<String, Box<dyn Error>> {
    let (terminator_width, end_pos) = if encoding == UTF_16LE || encoding == UTF_16BE {
        // UTF-16 uses a 2-byte null terminator.
        let width = 2;
        let pos = reader.windows(width).position(|w| w == [0, 0])
            .ok_or("Unterminated UTF-16 string in key block.")?;
        (width, pos)
    } else {
        // UTF-8 and other single-byte encodings use a 1-byte null terminator.
        let width = 1;
        let pos = reader.iter().position(|&b| b == 0)
            .ok_or("Unterminated string in key block.")?;
        (width, pos)
    };

    let text_bytes = &reader[..end_pos];
    let (text, _, _) = encoding.decode(text_bytes);

    // Advance the reader past the decoded text and its terminator.
    *reader = &reader[end_pos + terminator_width..];

    Ok(text.into_owned())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut file = File::open("data/test_dict.mdx")?;

    // --- 1. HEADER ---
    println!("Processing Header Block: START.");
    // MDX Format: 4-byte big-endian integer specifying header length.
    let header_len = file.read_u32::<BigEndian>()?;
    let mut header_bytes = vec![0; header_len as usize];
    file.read_exact(&mut header_bytes)?;
    
    // MDX Format: 4-byte little-endian Adler32 checksum of the (unencoded) header bytes.
    let checksum_from_file = file.read_u32::<LittleEndian>()?;
    let calculated_checksum = adler32(&header_bytes[..])?;
    assert_eq!(calculated_checksum, checksum_from_file, "Header checksum mismatch!");
    
    // MDX Format: The header text itself is always UTF-16LE.
    let (decoded_header, _, _) = UTF_16LE.decode(&header_bytes);
    
    // Some MDX files contain invalid control characters in the XML; we filter them.
    let sanitized_header: String = decoded_header.chars().filter(|c| !c.is_control() || c.is_whitespace()).collect();
    
    let mut xml_reader = Reader::from_str(&sanitized_header);
    let mut buf = Vec::new();
    let header_attrs = loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let attrs = e.attributes()
                    .map(|attr_result| {
                        let attr = attr_result?;
                        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                        let value = attr.unescape_value()?.into_owned();
                        Ok((key, value))
                    })
                    .collect::<Result<HashMap<String, String>, Box<dyn Error>>>()?;
                break attrs;
            }
            Ok(Event::Eof) => return Err("End of XML reached without finding a root element.".into()),
            Err(e) => return Err(e.into()),
            _ => (),
        }
    };
    
    let mdict_header = MdictHeader::from_attributes(&header_attrs)?;
    println!("Processing Header Block: OK.");
    println!("{:#?}", mdict_header);

    // --- 2. KEY BLOCK INFO ---
    println!("Processing Key Block Info: START.");
    // MDX Format: The size of this info block depends on the version.
    // v2.0+ uses 5 u64s (40 bytes); v1.x uses 4 u32s (16 bytes).
    let num_bytes = if mdict_header.version >= 2.0 { 40 } else { 16 };
    let mut key_block_info_bytes = vec![0; num_bytes];
    file.read_exact(&mut key_block_info_bytes)?;

    // MDX Format (v2.0+): This info block is followed by its own 4-byte Adler32 checksum.
    if mdict_header.version >= 2.0 {
        let checksum = file.read_u32::<BigEndian>()?;
        assert_eq!(adler32(&key_block_info_bytes[..])?, checksum, "Key block info checksum mismatch!");
    }

    let mut reader = &key_block_info_bytes[..];
    let key_block_info = KeyBlockInfo {
        num_key_blocks: read_number(&mut reader, mdict_header.number_width)?,
        num_entries: read_number(&mut reader, mdict_header.number_width)?,
        // MDX Format (v2.0+): Includes the decompressed length of the key index.
        key_index_decomp_len: if mdict_header.version >= 2.0 { Some(read_number(&mut reader, mdict_header.number_width)?) } else { None },
        key_index_comp_len: read_number(&mut reader, mdict_header.number_width)?,
        key_blocks_len: read_number(&mut reader, mdict_header.number_width)?,
    };
    println!("Processing Key Block Info: OK.");
    println!("{:#?}", key_block_info);

    // --- 3. KEY INDEX ---
    println!("Processing Key Index: START.");
    let mut key_index_comp_bytes = vec![0; key_block_info.key_index_comp_len as usize];
    file.read_exact(&mut key_index_comp_bytes)?;

    let key_index_decomp_bytes = if let Some(decomp_len) = key_block_info.key_index_decomp_len {
        // --- V2.X KEY INDEX LOGIC ---
        // MDX Format (v2): Block header is [4-byte compression type][4-byte checksum].
        let mut decrypted_payload: Vec<u8>; // Must live long enough for the borrow below.

        let payload_to_decompress = if mdict_header.encryption_flags.encrypt_key_index {
            let key = derive_key_for_v2_index(&key_index_comp_bytes);
            decrypted_payload = key_index_comp_bytes[8..].to_vec();
            fast_decrypt(&mut decrypted_payload, &key);
            &decrypted_payload
        } else {
            &key_index_comp_bytes[8..]
        };

        let compression_type = LittleEndian::read_u32(&key_index_comp_bytes[0..4]);
        let decompressed_bytes = perform_decompression(payload_to_decompress, compression_type, decomp_len)?;

        // MDX Format (v2): Checksum is calculated on the DECOMPRESSED data.
        let checksum_from_header = BigEndian::read_u32(&key_index_comp_bytes[4..8]);
        assert_eq!(adler32(&decompressed_bytes[..])?, checksum_from_header, "V2 Key Index checksum mismatch!");
        decompressed_bytes
    } else {
        // --- V1.X KEY INDEX LOGIC ---
        // MDX Format (v1): The key index is raw, with no compression or header.
        key_index_comp_bytes
    };
    println!("Processing Key Index: OK.");
    
    // --- 4. PARSE KEY INDEX METADATA ---
    println!("Parsing Key Index Metadata: START.");
    let mut key_blocks: Vec<KeyBlock> = Vec::new();
    let mut reader = &key_index_decomp_bytes[..];
    let mut calculated_num_entries = 0;
    
    while !reader.is_empty() {
        // MDX Format: Each entry in the key index describes one key block.
        let num_entries_in_block = read_number(&mut reader, mdict_header.number_width)?;
        calculated_num_entries += num_entries_in_block;

        // MDX Format: The first and last keys are stored as length-prefixed strings.
        // We parse them to advance the reader but discard the content.
        parse_key_text(&mut reader, &mdict_header)?; // First key
        parse_key_text(&mut reader, &mdict_header)?; // Last key
        
        // MDX Format: The entry concludes with the compressed and decompressed sizes of the key block.
        let compressed_size = read_number(&mut reader, mdict_header.number_width)?;
        let decompressed_size = read_number(&mut reader, mdict_header.number_width)?;

        key_blocks.push(KeyBlock { compressed_size, decompressed_size });
    }
    
    assert_eq!(calculated_num_entries, key_block_info.num_entries, "Mismatch in total entry count!");
    println!("Parsing Key Index Metadata: OK. (Found {} key blocks)", key_blocks.len());

    // --- 5. PARSE KEY BLOCKS ---
    println!("Processing Key Blocks: START.");
    let mut all_headwords: Vec<Headword> = Vec::new();

    for key_block_meta in key_blocks.iter() {
        let mut compressed_bytes = vec![0; key_block_meta.compressed_size as usize];
        file.read_exact(&mut compressed_bytes)?;

        // MDX Format (v1/v2): Block header is [4-byte compression type][4-byte checksum].
        let compression_type = LittleEndian::read_u32(&compressed_bytes[0..4]);
        let checksum_from_header = BigEndian::read_u32(&compressed_bytes[4..8]);
        
        let decompressed_bytes = perform_decompression(
            &compressed_bytes[8..],
            compression_type,
            key_block_meta.decompressed_size,
        )?;

        // MDX Format (v1/v2): Checksum is verified against the DECOMPRESSED data.
        let calculated_checksum = adler32(&decompressed_bytes[..])?;
        assert_eq!(calculated_checksum, checksum_from_header, "Key block checksum mismatch!");

        let mut block_reader = &decompressed_bytes[..];
        while !block_reader.is_empty() {
            // MDX Format: Each headword entry is [record_id][null_terminated_text].
            let id = read_number(&mut block_reader, mdict_header.number_width)?;
            let text = read_null_terminated_string(&mut block_reader, mdict_header.encoding)?;
            all_headwords.push(Headword { id, text });
        }
    }
    
    assert_eq!(key_block_info.num_entries, all_headwords.len() as u64, "Final headword count does not match expected total!");
    println!("Processing Key Blocks: OK. (Total headwords: {})", all_headwords.len());

    Ok(())
}