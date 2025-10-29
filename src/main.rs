use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use adler32::adler32;
use encoding_rs::UTF_16LE;
use quick_xml::events::Event;
use quick_xml::Error as XmlError;
use quick_xml::Reader;

fn main() {
    let mut file = File::open("data/test_dict.mdx").expect("Failed to open file");

    // MDX format: 4-byte big-endian integer for header length.
    let mut header_length_bytes = [0; 4];
    file.read_exact(&mut header_length_bytes)
        .expect("Failed to read header length");
    let header_length = u32::from_be_bytes(header_length_bytes);
    println!("Reading header length: OK. ({} bytes)", header_length);

    let mut header_content_bytes = vec![0; header_length as usize];
    file.read_exact(&mut header_content_bytes)
        .expect("Failed to read header content");
    println!("Reading header content: OK.");

    // MDX format: 4-byte little-endian Adler32 checksum of the header.
    let mut checksum_bytes_from_file = [0; 4];
    file.read_exact(&mut checksum_bytes_from_file)
        .expect("Failed to read header checksum");
    let checksum_from_file = u32::from_le_bytes(checksum_bytes_from_file);
    println!("Reading header checksum: OK.");

    let calculated_checksum = adler32(&header_content_bytes[..]).expect("Failed to calculate checksum");
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

    // The parsing operation returns a Result, which we handle once here.
    let header_attrs = header_attrs_result.expect("Failed to parse XML attributes");

    println!(
        "Parsing header attributes: OK. (Found {} attributes)",
        header_attrs.len()
    );
    println!("{:#?}", header_attrs);

    buf.clear();
}
