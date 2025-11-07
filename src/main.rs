use mdict_reader::MdictReader;
use std::env;

fn main() {
    // Initialize logger (simple stderr logger)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-mdx-file> [--passcode <REG_CODE>,<EMAIL>]", args[0]);
        std::process::exit(1);
    }

    let mdx_path = &args[1];
    let mut passcode: Option<(&str, &str)> = None;
    let mut passcode_storage: Option<(String, String)> = None;
    
    // Parse --passcode argument
    if let Some(passcode_idx) = args.iter().position(|arg| arg == "--passcode") {
        if let Some(passcode_str) = args.get(passcode_idx + 1) {
            if let Some((reg_code, email)) = passcode_str.split_once(',') {
                // Store the parsed parts because we need to pass references with a stable lifetime
                passcode_storage = Some((reg_code.to_string(), email.to_string()));
            } else {
                eprintln!("ERROR: Invalid passcode format. Expected <REG_CODE_HEX>,<EMAIL>");
                std::process::exit(1);
            }
        } else {
            eprintln!("ERROR: --passcode flag requires an argument.");
            std::process::exit(1);
        }
    }
    
    if let Some((ref reg_code, ref email)) = passcode_storage {
        passcode = Some((reg_code, email));
    }

    println!("\n{}", "=".repeat(60));
    println!("MDict Reader");
    println!("{}", "=".repeat(60));
    println!("File: {}", mdx_path);
    if passcode.is_some() {
        println!("Passcode: provided");
    }
    println!("{}\n", "=".repeat(60));

    // Pass the optional passcode to the reader
    match MdictReader::new(mdx_path, passcode) {
        Ok(reader) => {
            println!("\n{}", "=".repeat(60));
            println!("✓ SUCCESS");
            println!("{}", "=".repeat(60));
        
            println!("\nDictionary Information:");
            println!("  Title:       {}", reader.header.title);
            println!("  Version:     {}", reader.header.engine_version);
            println!("  Encoding:    {}", reader.header.encoding.name());
            println!("  Encrypted:   blocks={}, index={}", 
                     reader.header.encryption_flags.encrypt_record_blocks,
                     reader.header.encryption_flags.encrypt_key_index);
        
            if let Some(desc) = &reader.header.description {
                println!("  Description: {}", desc);
            }
        
            println!("\nStatistics:");
            println!("  Key entries:    {}", reader.all_keys.len());
            println!("  Key blocks:     {}", reader.key_blocks.len());
            println!("  Record blocks:  {}", reader.record_blocks.len());
            println!("  Record data:    {} bytes", reader.all_records_decompressed.len());
        
            // Define how many sample entries to show
            let sample_count = 100;
            
            println!("\nSample Key Entries (first {}):", sample_count);
            for (i, key_entry) in reader.all_keys.iter().take(sample_count).enumerate() {
                println!("  {:2}. [id={}] {}", i + 1, key_entry.id, key_entry.text);
            }
        
            if reader.all_keys.len() > sample_count {
                println!("  ... and {} more entries", reader.all_keys.len() - sample_count);
            }
            
            println!();
        }
        Err(e) => {
            eprintln!("\n{}", "=".repeat(60));
            eprintln!("✗ ERROR");
            eprintln!("{}", "=".repeat(60));
            eprintln!("Failed to read MDict file: {}", e);
            eprintln!();
            std::process::exit(1);
        }
    }
}
