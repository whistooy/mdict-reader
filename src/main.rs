use mdict_reader::MdictReader;
use std::env;

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
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

    match MdictReader::new(mdx_path, passcode) {
        Ok(reader) => {
            println!("\n{}", "=".repeat(60));
            println!("✓ SUCCESS - Metadata loaded");
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
            println!("  Key entries:    {}", reader.key_block_info.num_entries);
            println!("  Key blocks:     {}", reader.key_block_info.num_key_blocks);
            println!("  Record blocks:  {}", reader.record_block_info.num_record_blocks);
        
            // Define how many sample entries to show
            let sample_count = 100;
            let total_entries = reader.key_block_info.num_entries;
            
            println!("\nSample Entries & Definitions (first {} of {}):", sample_count, total_entries);
            
            let definitions_iterator = reader.iter_keys()
                .with_record_info()
                .with_definitions();

            for (i, entry_result) in definitions_iterator.take(sample_count).enumerate() {
                match entry_result {
                    Ok((key, definition)) => {
                        println!("  {:2}. Key: {}", i + 1, key);
                        
                        // Truncate for clean display
                        let mut truncated_def = definition
                            .trim()
                            .replace('\n', " ")
                            .replace('\r', "");
                        let max_len = 1000;
                        if truncated_def.chars().count() > max_len {
                            truncated_def = truncated_def.chars().take(max_len).collect::<String>() + "...";
                        }

                        println!("     Def: {}", truncated_def);
                    }
                    Err(e) => {
                        eprintln!("  Error fetching entry {}: {}", i + 1, e);
                        break;
                    }
                }
            }
        
            if total_entries > sample_count as u64 {
                println!("  ... and {} more entries", total_entries - sample_count as u64);
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
