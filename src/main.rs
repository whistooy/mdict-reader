use std::fs::File;
use std::io::Read;
use adler32::adler32;

fn main() {
    let mut file = File::open("data/test_dict.mdx").expect("Failed to open file");

    // The first 4 bytes of an MDX file specify the length of the header text.
    // This length is a 32-bit unsigned integer in big-endian byte order.
    let mut header_length_bytes = [0; 4];
    file.read_exact(&mut header_length_bytes).expect("Failed to read header length (4 bytes)");
    let header_length = u32::from_be_bytes(header_length_bytes);
    println!("Header length: {} bytes", header_length);

    // Read the header content itself, which is typically XML data.
    let mut header_content_bytes = vec![0; header_length as usize];
    file.read_exact(&mut header_content_bytes).expect("Failed to read header content");
    println!("Header content: read {} bytes", header_content_bytes.len());

    // The next 4 bytes are the Adler32 checksum of the header content.
    // This checksum is a 32-bit unsigned integer in little-endian byte order.
    let mut checksum_bytes_from_file = [0; 4];
    file.read_exact(&mut checksum_bytes_from_file).expect("Failed to read header checksum (4 bytes)");
    let checksum_from_file = u32::from_le_bytes(checksum_bytes_from_file);
    println!("Header checksum from file: {}", checksum_from_file);

    // Calculate the checksum of the header content we just read to verify its integrity.
    let calculated_checksum = adler32(&header_content_bytes[..]).expect("Failed to calculate checksum");
    println!("Header checksum calculated: {}", calculated_checksum);

    // The checksum from the file must match our calculated checksum.
    assert_eq!(
        calculated_checksum,
        checksum_from_file,
        "Header checksum mismatch!"
    );
    println!("Header checksum verification: OK.");
}
