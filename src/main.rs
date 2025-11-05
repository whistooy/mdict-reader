use mdict_reader::MdictParser;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- Testing the mdict-parser library ---");
    let parser = MdictParser::new("data/test_dict.mdx")?;
    println!("\n--- Parser Initialized Successfully ---");
    println!("Dictionary Title: {}", parser.header.title);
    println!("Found {} total entries.", parser.key_block_info.num_entries);
    println!("First headword: '{}'", parser.all_headwords.first().map_or("N/A", |h| &h.text));
    Ok(())
}
