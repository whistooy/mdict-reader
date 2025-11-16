use mdict_reader::{Mdict, MdictReader, FileType};
use std::env;

/// Helper function to print common metadata from any MdictReader.
fn print_common_info<T: FileType>(reader: &MdictReader<T>) {
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
    println!("  Key entries:    {}", reader.num_entries());
    println!("  Key blocks:     {}", reader.num_key_blocks());
    println!("  Record blocks:  {}", reader.num_record_blocks());
}
/// Generic helper to print sample records, handling the iteration and sampling logic.
/// It takes a closure to define how to print the record-specific details.
fn print_samples<T: FileType>(
    reader: &MdictReader<T>,
    description: &str,
    print_record_details: impl Fn(&T::Record),
) {
    let desired_sample_count = 100;
    println!("\nSample Entries & {} (showing first up to {} entries):", description, desired_sample_count);
    let mut entries_processed = 0;
    // We collect the first `desired_sample_count` entries.
    // This is efficient because the iterator is lazy and will stop processing
    // key blocks once the limit is reached.
    let samples: Vec<_> = reader.iter_keys()
        .with_record_info()
        .with_records()
        .take(desired_sample_count)
        .collect();
    // Now, we print the collected samples.
    for (i, entry_result) in samples.into_iter().enumerate() {
        match entry_result {
            Ok((key, record)) => {
                println!("  {:2}. Key: {}", i + 1, key);
                print_record_details(&record);
            }
            Err(e) => eprintln!("  Error fetching entry {}: {}", i + 1, e),
        }
        entries_processed += 1;
    }
    
    let total_entries = reader.num_entries();
    println!("\nTotal entries in dictionary: {}", total_entries);
    if total_entries > entries_processed as u64 {
        let remaining = total_entries - entries_processed as u64;
        println!("  ({} samples shown above, {} more entries not shown)", entries_processed, remaining);
    }
}

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-mdx-or-mdd-file> [--passcode <REG_CODE>,<EMAIL>]", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];

    // Parse optional --passcode argument
    let mut passcode: Option<(&str, &str)> = None;
    let mut passcode_storage: Option<(String, String)> = None;
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

    // Parse optional --encoding argument (user override)
    let mut user_encoding: Option<&str> = None;
    if let Some(enc_idx) = args.iter().position(|arg| arg == "--encoding") {
        if let Some(enc_label) = args.get(enc_idx + 1) {
            user_encoding = Some(enc_label.as_str());
        } else {
            eprintln!("ERROR: --encoding flag requires an argument.");
            std::process::exit(1);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("MDict Reader");
    println!("{}", "=".repeat(60));
    println!("File: {}", file_path);
    if passcode.is_some() {
        println!("Passcode: provided");
    }
    println!("{}", "=".repeat(60));

    // Use the high-level Mdict::open for auto-detection
    match Mdict::open(file_path, passcode, user_encoding) {
        Ok(mdict) => {
            match mdict {
                Mdict::Mdx(reader) => {
                    println!("\nFile Type: MDX (Dictionary)");
                    print_common_info(&reader);
                    // Use the generic helper with a closure for MDX-specific printing
                    print_samples(&reader, "Definitions", |definition| {
                        let mut truncated_def = definition.trim().replace(['\n', '\r'], " ");
                        let max_len = 1000;
                        if truncated_def.chars().count() > max_len {
                            truncated_def = truncated_def.chars().take(max_len).collect::<String>() + "...";
                        }
                        println!("     Def: {}", truncated_def);
                    });
                }
                Mdict::Mdd(reader) => {
                    println!("\nFile Type: MDD (Resource Data)");
                    print_common_info(&reader);
                    // Use the generic helper with a closure for MDD-specific printing
                    print_samples(&reader, "Resource Sizes", |data| {
                        println!("     Resource Size: {} bytes", data.len());
                    });
                }
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
