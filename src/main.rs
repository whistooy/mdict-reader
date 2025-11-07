use mdict_reader::MdictReader;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-mdx-file>", args[0]);
        std::process::exit(1);
    }
    
    let mdx_path = &args[1];
    
    println!("Reading MDict file: {}", mdx_path);
    println!("{}", "=".repeat(60));
    
    match MdictReader::new(mdx_path) {
        Ok(reader) => {
            println!("\n{}", "=".repeat(60));
            println!("SUCCESS! Reading completed.");
            println!("{}", "=".repeat(60));
            
            println!("\nDictionary Information:");
            println!("  Title: {}", reader.header.title);
            println!("  Version: {}", reader.header.engine_version);
            println!("  Encoding: {}", reader.header.encoding.name());
            println!("  Encrypted: {:?}", reader.header.encryption_flags);
            
            if let Some(desc) = &reader.header.description {
                println!("  Description: {}", desc);
            }
            
            println!("\nStatistics:");
            println!("  Total key entries: {}", reader.all_keys.len());
            println!("  Key blocks: {}", reader.key_blocks.len());
            println!("  Record blocks: {}", reader.record_blocks.len());
            println!("  Total record data: {} bytes", reader.all_records_decompressed.len());
            
            println!("\nSample Key Entries (first 10):");
            for (i, key_entry) in reader.all_keys.iter().take(10).enumerate() {
                println!("  {}. [{}] {}", i + 1, key_entry.id, key_entry.text);
            }
            
            if reader.all_keys.len() > 10 {
                println!("  ... and {} more", reader.all_keys.len() - 10);
            }
        }
        Err(e) => {
            eprintln!("\nERROR: Failed to read MDict file");
            eprintln!("  {}", e);
            std::process::exit(1);
        }
    }
}
