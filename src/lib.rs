// --- Standard Library Imports ---
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Cursor};

// --- External Crate Imports ---
use adler32::adler32;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16LE, UTF_16BE};
use flate2::read::ZlibDecoder;
use hex;
use lzokay::decompress::decompress as lzokay_decompress;
use quick_xml::{events::Event, Reader};
use ripemd::{Digest, Ripemd128};
use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    Salsa8,
};

// --- Data Structures ---

/// Represents the MDict encryption bitfield.
#[derive(Debug, Default)]
pub struct EncryptionFlags {
    // Corresponds to the 0x01 bitflag.
    pub encrypt_record_blocks: bool,
    // Corresponds to the 0x02 bitflag.
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

/// Metadata for the entire record block section.
#[derive(Debug)]
pub struct RecordBlockInfo {
    pub num_record_blocks: u64,
    pub num_entries: u64,
    pub record_index_len: u64,
    pub record_blocks_len: u64,
}

/// Metadata for a single record block.
#[derive(Debug)]
pub struct RecordBlock {
    pub compressed_size: u64,
    pub decompressed_size: u64,
}

/// The main struct for interacting with an MDict dictionary.
pub struct MdictParser {
    pub header: MdictHeader,
    pub key_block_info: KeyBlockInfo,
    pub key_blocks: Vec<KeyBlock>,
    pub record_block_info: RecordBlockInfo,
    pub record_blocks: Vec<RecordBlock>,
    pub all_headwords: Vec<Headword>,
    // Records are left raw for now for demonstration purposes.
    pub all_records_decompressed: Vec<u8>,
}


// --- Implementation & Helpers ---

impl MdictHeader {
    // Creates an `MdictHeader` by interpreting raw XML attributes.
    // Fails if the MDict version is 3.0 or higher, as it is unsupported.
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


impl MdictParser {
    // --- Low-level Decoding Helpers ---
    
    // Reads a number (4 or 8 bytes, big-endian) based on the MDict version.
    fn read_number(reader: &mut impl Read, number_width: usize) -> Result<u64, Box<dyn Error>> {
        Ok(match number_width {
            8 => reader.read_u64::<BigEndian>()?,
            4 => reader.read_u32::<BigEndian>().map(u64::from)?,
            _ => return Err("Unsupported number width for Self::read_number.".into()),
        })
    }

    // Reads a number with a smaller width (1 or 2 bytes) for text length prefixes.
    fn read_small_number(reader: &mut impl Read, number_width: usize) -> Result<u64, Box<dyn Error>> {
        Ok(match number_width {
            2 => reader.read_u16::<BigEndian>().map(u64::from)?,
            1 => reader.read_u8().map(u64::from)?,
            _ => return Err("Unsupported number width for Self::read_small_number.".into()),
        })
    }

    // Derives the master encryption key from a user-provided passcode.
    fn derive_master_key(reg_code: &[u8], user_id: &[u8]) -> Result<[u8; 16], Box<dyn Error>> {
        // MDX Algorithm: The user ID is hashed with Ripemd128 to form a 16-byte key.
        let mut hasher = Ripemd128::new();
        hasher.update(user_id);
        let user_id_digest: [u8; 16] = hasher.finalize().into();

        // MDX Algorithm (Salsa20): Salsa20 requires a 32-byte key. The 16-byte Ripemd128
        // digest is duplicated to create the required 32-byte key.
        let mut salsa_key = [0u8; 32];
        salsa_key[..16].copy_from_slice(&user_id_digest);
        salsa_key[16..].copy_from_slice(&user_id_digest);

        // MDX Algorithm: The registration code is decrypted with Salsa20/8 to yield the final master key.
        let mut key = reg_code.to_vec();
        let mut cipher = Salsa8::new((&salsa_key).into(), &([0u8; 8]).into());
        cipher.apply_keystream(&mut key);

        let final_key: [u8; 16] = key.try_into()
            .map_err(|_| "Derived key was not 16 bytes long.")?;
        Ok(final_key)
    }

    // Decrypts data using the Salsa20/8 stream cipher.
    fn salsa_decrypt(data: &mut [u8], key16: &[u8; 16]) {
        // MDX Algorithm (Salsa20): The 16-byte key is duplicated to form the 32-byte key required by the cipher.
        let mut salsa_key = [0u8; 32];
        salsa_key[..16].copy_from_slice(key16);
        salsa_key[16..].copy_from_slice(key16);

        let mut cipher = Salsa8::new((&salsa_key).into(), &([0u8; 8]).into());
        cipher.apply_keystream(data);
    }

    // Implements the v2 key index key derivation algorithm using RIPEMD128.
    fn derive_key_for_v2_index(key_index_block: &[u8]) -> [u8; 16] {
        let mut hasher = Ripemd128::new();
        // MDX Format (v2): The decryption key for the key index is a hash of the
        // block's checksum (bytes 4-8) and a fixed magic number.
        hasher.update(&key_index_block[4..8]);
        hasher.update(&0x3695u32.to_le_bytes());
        hasher.finalize().into()
    }

    // Decrypts data using the custom XOR obfuscation algorithm from the MDict format.
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

    // Skips over a length-prefixed key text in a slice reader.
    fn parse_key_text(reader: &mut &[u8], mdict_header: &MdictHeader) -> Result<(), Box<dyn Error>> {
        // MDX Format: The length of the key text is stored in "units". For UTF-8, 1 unit = 1 byte.
        // For UTF-16, 1 unit = 1 character (2 bytes).
        let text_len_in_units = if mdict_header.version >= 2.0 {
            Self::read_small_number(reader, 2)?
        } else {
            Self::read_small_number(reader, 1)?
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

    // Performs decryption on a raw payload using the specified algorithm.
    fn perform_decryption(
        payload: &[u8],
        encryption_type: u8,
        key16: &[u8; 16],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(match encryption_type {
            // MDX Encryption: Type 0 is no encryption.
            0 => payload.to_vec(),
            // MDX Encryption: Type 1 is FastDecrypt (XOR).
            1 => {
                let mut decrypted = payload.to_vec();
                Self::fast_decrypt(&mut decrypted, key16);
                decrypted
            },
            // MDX Encryption: Type 2 is Salsa20/8.
            2 => {
                let mut decrypted = payload.to_vec();
                Self::salsa_decrypt(&mut decrypted, key16);
                decrypted
            },
            _ => return Err(format!("Unsupported block encryption type: {}", encryption_type).into()),
        })
    }

    // Performs decompression on a raw payload using the specified algorithm.
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

    // A universal decoder for both key and record blocks, orchestrating decryption and decompression.
    fn decode_block(
        compressed_block: &[u8],
        decompressed_size: u64,
        master_key: Option<&[u8; 16]>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // MDX Format: First 4 bytes define compression and encryption type.
        let info = LittleEndian::read_u32(&compressed_block[0..4]);
        let compression_type = (info & 0xF) as u8;
        let encryption_type = ((info >> 4) & 0xF) as u8;

        // MDX Format: Next 4 bytes are the Adler32 checksum.
        let checksum_from_header = BigEndian::read_u32(&compressed_block[4..8]);
        let payload = &compressed_block[8..];

        // MDX Format: The decryption key is either the provided master key, or a key
        // derived from the block's checksum if no master key is available.
        let decryption_key_16: [u8; 16] = match master_key {
            Some(key) => *key,
            None => {
                let mut hasher = Ripemd128::new();
                hasher.update(&compressed_block[4..8]);
                hasher.finalize().into()
            }
        };

        // First, decrypt the payload.
        let decrypted_payload = Self::perform_decryption(payload, encryption_type, &decryption_key_16)?;

        // Second, decompress the (now decrypted) payload.
        let decompressed_bytes = Self::perform_decompression(&decrypted_payload, compression_type as u32, decompressed_size)?;

        // Finally, the checksum is verified against the fully decompressed data.
        let calculated_checksum = adler32(&decompressed_bytes[..])?;
        assert_eq!(calculated_checksum, checksum_from_header, "Block checksum mismatch!");
        
        Ok(decompressed_bytes)
    }

    // Reads a null-terminated string from a byte slice, decodes it, and advances the slice.
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
    
    // --- Internal Parsing Steps ---

    fn parse_header(file: &mut File) -> Result<MdictHeader, Box<dyn Error>> {
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
                    break e.attributes()
                        .map(|attr_result| {
                            let attr = attr_result?;
                            let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                            let value = attr.unescape_value()?.into_owned();
                            Ok((key, value))
                        })
                        .collect::<Result<HashMap<String, String>, Box<dyn Error>>>()?;
                }
                Ok(Event::Eof) => return Err("End of XML reached without finding a root element.".into()),
                Err(e) => return Err(e.into()),
                _ => (),
            }
        };

        let mdict_header = MdictHeader::from_attributes(&header_attrs)?;
        println!("Processing Header Block: OK.");
        println!("{:#?}", mdict_header);
        Ok(mdict_header)
    }

    fn derive_optional_master_key(header: &MdictHeader) -> Result<Option<[u8; 16]>, Box<dyn Error>> {
        // MDX Format: For encrypted dictionaries, a passcode (registration code and user ID) is required.
        // In a real application, this would be provided by the user.
        let passcode: Option<(&str, &str)> = None; // Some(("0123456789ABCDEF0123456789ABCDEF", "example@example.com"))
        
        // If a passcode is provided and the dictionary is encrypted, derive the master key.
        if let Some((reg_code_hex, user_id_str)) = passcode {
            if header.encryption_flags.encrypt_record_blocks {
                println!("Deriving master key from passcode...");
                let reg_code = hex::decode(reg_code_hex)?;
                return Ok(Some(Self::derive_master_key(&reg_code, user_id_str.as_bytes())?));
            }
        }
        Ok(None)
    }

    fn parse_key_block_info(file: &mut File, header: &MdictHeader, master_key: Option<&[u8; 16]>) -> Result<KeyBlockInfo, Box<dyn Error>> {
        println!("Processing Key Block Info: START.");
        // MDX Format: The size of this info block depends on the version.
        // v2.0+ uses 5 u64s (40 bytes); v1.x uses 4 u32s (16 bytes).
        let num_bytes = if header.version >= 2.0 { 40 } else { 16 };
        let mut key_block_info_bytes = vec![0; num_bytes];
        file.read_exact(&mut key_block_info_bytes)?;

        // MDX Format (Encrypted): The entire key block info section is encrypted with Salsa20
        // if a master key is present. It must be decrypted before parsing.
        if let Some(ref key) = master_key {
            println!("Decrypting Key Block Info with Salsa20...");
            Self::salsa_decrypt(&mut key_block_info_bytes, key);
        }

        // MDX Format (v2.0+): This info block is followed by its own 4-byte Adler32 checksum.
        if header.version >= 2.0 {
            let checksum = file.read_u32::<BigEndian>()?;
            assert_eq!(adler32(&key_block_info_bytes[..])?, checksum, "Key block info checksum mismatch!");
        }

        let mut reader = &key_block_info_bytes[..];
        let key_block_info = KeyBlockInfo {
            num_key_blocks: Self::read_number(&mut reader, header.number_width)?,
            num_entries: Self::read_number(&mut reader, header.number_width)?,
            // MDX Format (v2.0+): Includes the decompressed length of the key index.
            key_index_decomp_len: if header.version >= 2.0 { Some(Self::read_number(&mut reader, header.number_width)?) } else { None },
            key_index_comp_len: Self::read_number(&mut reader, header.number_width)?,
            key_blocks_len: Self::read_number(&mut reader, header.number_width)?,
        };
        println!("Processing Key Block Info: OK.");
        println!("{:#?}", key_block_info);
        Ok(key_block_info)
    }

    fn parse_key_index(file: &mut File, key_block_info: &KeyBlockInfo, header: &MdictHeader) -> Result<Vec<u8>, Box<dyn Error>> {
        println!("Processing Key Index: START.");
        let mut key_index_comp_bytes = vec![0; key_block_info.key_index_comp_len as usize];
        file.read_exact(&mut key_index_comp_bytes)?;

        let key_index_decomp_bytes = if let Some(decomp_len) = key_block_info.key_index_decomp_len {
            // --- V2.X KEY INDEX LOGIC ---
            // MDX Format (v2): Block header is [4-byte compression type][4-byte checksum].
            let mut decrypted_payload: Vec<u8>; // Must live long enough for the borrow below.

            let payload_to_decompress = if header.encryption_flags.encrypt_key_index {
                let key = Self::derive_key_for_v2_index(&key_index_comp_bytes);
                decrypted_payload = key_index_comp_bytes[8..].to_vec();
                Self::fast_decrypt(&mut decrypted_payload, &key);
                &decrypted_payload
            } else {
                &key_index_comp_bytes[8..]
            };

            let compression_type = LittleEndian::read_u32(&key_index_comp_bytes[0..4]);
            let decompressed_bytes = Self::perform_decompression(payload_to_decompress, compression_type, decomp_len)?;

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
        Ok(key_index_decomp_bytes)
    }

    fn parse_key_index_metadata(decomp_bytes: &[u8], header: &MdictHeader, key_block_info: &KeyBlockInfo) -> Result<Vec<KeyBlock>, Box<dyn Error>> {
        println!("Parsing Key Index Metadata: START.");
        let mut key_blocks: Vec<KeyBlock> = Vec::new();
        let mut reader = decomp_bytes;
        let mut calculated_num_entries = 0;

        while !reader.is_empty() {
            // MDX Format: Each entry in the key index describes one key block.
            let num_entries_in_block = Self::read_number(&mut reader, header.number_width)?;
            calculated_num_entries += num_entries_in_block;

            // MDX Format: The first and last keys are stored as length-prefixed strings.
            // We parse them to advance the reader but discard the content.
            Self::parse_key_text(&mut reader, header)?; // First key
            Self::parse_key_text(&mut reader, header)?; // Last key

            // MDX Format: The entry concludes with the compressed and decompressed sizes of the key block.
            let compressed_size = Self::read_number(&mut reader, header.number_width)?;
            let decompressed_size = Self::read_number(&mut reader, header.number_width)?;

            key_blocks.push(KeyBlock { compressed_size, decompressed_size });
        }

        assert_eq!(calculated_num_entries, key_block_info.num_entries, "Mismatch in total entry count!");
        println!("Parsing Key Index Metadata: OK. (Found {} key blocks)", key_blocks.len());
        Ok(key_blocks)
    }

    fn parse_key_blocks(file: &mut File, key_block_info: &KeyBlockInfo, key_blocks: &[KeyBlock], header: &MdictHeader, master_key: Option<&[u8; 16]>) -> Result<Vec<Headword>, Box<dyn Error>> {
        println!("Processing Key Blocks: START.");
        let mut all_headwords: Vec<Headword> = Vec::new();

        // The entire collection of key blocks is read into memory at once.
        let mut key_blocks_data = vec![0; key_block_info.key_blocks_len as usize];
        file.read_exact(&mut key_blocks_data)?;
        let mut key_blocks_cursor = Cursor::new(key_blocks_data);

        for key_block_meta in key_blocks.iter() {
            let mut compressed_bytes = vec![0; key_block_meta.compressed_size as usize];
            key_blocks_cursor.read_exact(&mut compressed_bytes)?;

            // The universal block decoder handles any encryption on the key blocks.
            let decompressed_bytes = Self::decode_block(
                &compressed_bytes,
                key_block_meta.decompressed_size,
                master_key,
            )?;

            let mut block_reader = &decompressed_bytes[..];
            while !block_reader.is_empty() {
                // MDX Format: Each headword entry is [record_id][null_terminated_text].
                let id = Self::read_number(&mut block_reader, header.number_width)?;
                let text = Self::read_null_terminated_string(&mut block_reader, header.encoding)?;
                all_headwords.push(Headword { id, text });
            }
        }

        assert_eq!(key_block_info.num_entries, all_headwords.len() as u64, "Final headword count does not match expected total!");
        println!("Processing Key Blocks: OK. (Total headwords: {})", all_headwords.len());
        Ok(all_headwords)
    }

    fn parse_record_block_info(file: &mut File, header: &MdictHeader, key_block_info: &KeyBlockInfo) -> Result<RecordBlockInfo, Box<dyn Error>> {
        println!("Processing Record Block Info: START.");
        // MDX Format: This info block is read directly from the file stream. Its structure
        // mirrors the key block info and is not checksummed.
        let record_block_info = RecordBlockInfo {
            num_record_blocks: Self::read_number(file, header.number_width)?,
            num_entries: Self::read_number(file, header.number_width)?,
            record_index_len: Self::read_number(file, header.number_width)?,
            record_blocks_len: Self::read_number(file, header.number_width)?,
        };

        // Sanity check: the number of entries should be consistent across the file.
        assert_eq!(record_block_info.num_entries, key_block_info.num_entries, "Record and key entry counts do not match!");
        println!("Processing Record Block Info: OK.");
        println!("{:#?}", record_block_info);
        Ok(record_block_info)
    }

    fn parse_record_block_index(file: &mut File, record_info: &RecordBlockInfo, header: &MdictHeader) -> Result<Vec<RecordBlock>, Box<dyn Error>> {
        println!("Parsing Record Block Index: START.");
        // MDX Format: This is a simple list of metadata for each record block.
        // Unlike the key index, it's not compressed and contains no headword text.
        let mut record_block_index_bytes = vec![0; record_info.record_index_len as usize];
        file.read_exact(&mut record_block_index_bytes)?;

        let mut reader = &record_block_index_bytes[..];
        let mut record_blocks: Vec<RecordBlock> = Vec::new();
        while !reader.is_empty() {
            // MDX Format: Each entry defines the size of one record block.
            let compressed_size = Self::read_number(&mut reader, header.number_width)?;
            let decompressed_size = Self::read_number(&mut reader, header.number_width)?;
            record_blocks.push(RecordBlock { compressed_size, decompressed_size });
        }

        assert_eq!(record_blocks.len() as u64, record_info.num_record_blocks, "Mismatch in record block count!");
        println!("Parsing Record Block Index: OK. (Found {} record blocks)", record_blocks.len());
        Ok(record_blocks)
    }

    fn decompress_record_blocks(file: &mut File, record_blocks: &[RecordBlock], master_key: Option<&[u8; 16]>) -> Result<Vec<u8>, Box<dyn Error>> {
        println!("Processing Record Blocks: START.");
        let total_decomp_size: usize = record_blocks.iter().map(|b| b.decompressed_size as usize).sum();
        let mut all_records_decompressed = Vec::with_capacity(total_decomp_size);

        for record_block_meta in record_blocks.iter() {
            let mut compressed_bytes = vec![0; record_block_meta.compressed_size as usize];
            file.read_exact(&mut compressed_bytes)?;

            // The universal block decoder handles any encryption on the record blocks.
            let decompressed_bytes = Self::decode_block(
                &compressed_bytes,
                record_block_meta.decompressed_size,
                master_key,
            )?;

            all_records_decompressed.extend_from_slice(&decompressed_bytes);
        }

        assert_eq!(all_records_decompressed.len(), total_decomp_size, "Final decompressed size does not match expected size!");
        println!("Processing Record Blocks: OK. (Total decompressed size: {} bytes)", all_records_decompressed.len());
        Ok(all_records_decompressed)
    }

    // Creates a new MdictParser and parses the entire file.
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        let mut file = File::open(path)?;
        // --- 1. HEADER ---
        let mdict_header = Self::parse_header(&mut file)?;
        // --- 1.5. MASTER KEY DERIVATION ---
        let master_key = Self::derive_optional_master_key(&mdict_header)?;
        // --- 2. KEY BLOCK INFO ---
        let key_block_info = Self::parse_key_block_info(&mut file, &mdict_header, master_key.as_ref())?;
        // --- 3. KEY INDEX ---
        let key_index_decomp_bytes = Self::parse_key_index(&mut file, &key_block_info, &mdict_header)?;
        // --- 4. PARSE KEY INDEX METADATA ---
        let key_blocks = Self::parse_key_index_metadata(&key_index_decomp_bytes, &mdict_header, &key_block_info)?;
        // --- 5. PARSE KEY BLOCKS ---
        let all_headwords = Self::parse_key_blocks(&mut file, &key_block_info, &key_blocks, &mdict_header, master_key.as_ref())?;
        // --- 6. READ RECORD BLOCK INFO ---
        let record_block_info = Self::parse_record_block_info(&mut file, &mdict_header, &key_block_info)?;
        // --- 7. PARSE RECORD BLOCK INDEX ---
        let record_blocks = Self::parse_record_block_index(&mut file, &record_block_info, &mdict_header)?;
        // --- 8. DECOMPRESS ALL RECORD BLOCKS ---
        let all_records_decompressed = Self::decompress_record_blocks(&mut file, &record_blocks, master_key.as_ref())?;
        // --- Return the fully parsed struct ---
        Ok(Self {
            header: mdict_header,
            key_block_info,
            key_blocks,
            record_block_info,
            record_blocks,
            all_headwords,
            all_records_decompressed,
        })
    }
}