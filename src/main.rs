use mdict_reader::{Mdict, MdictReader, FileType};
use std::env;
use std::cmp::min;


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
    println!("  Key entries:    {}", reader.key_block_info.num_entries);
    println!("  Key blocks:     {}", reader.key_block_info.num_key_blocks);
    println!("  Record blocks:  {}", reader.record_block_info.num_record_blocks);
}
/// Generic helper to print sample records, handling the iteration and sampling logic.
/// It takes a closure to define how to print the record-specific details.
fn print_samples<T: FileType>(
    reader: &MdictReader<T>,
    description: &str,
    print_record_details: impl Fn(&T::Record),
) {
    let desired_sample_count = 100;
    let total_entries = reader.key_block_info.num_entries;
    // Correctly calculate the number of samples to show.
    let sample_count = min(desired_sample_count, total_entries as usize);
    println!("\nSample Entries & {} (first {} of {}):", description, sample_count, total_entries);
    let records_iterator = reader.iter_keys()
        .with_record_info()
        .with_records();
    for (i, entry_result) in records_iterator.take(sample_count).enumerate() {
        match entry_result {
            Ok((key, record)) => {
                println!("  {:2}. Key: {}", i + 1, key);
                // Call the provided closure to print the specific details.
                print_record_details(&record);
            }
            Err(e) => eprintln!("  Error fetching entry {}: {}", i + 1, e),
        }
    }
    if total_entries > sample_count as u64 {
        println!("  ... and {} more entries", total_entries - sample_count as u64);
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
    println!("File: {}", file_path);
    if passcode.is_some() {
        println!("Passcode: provided");
    }
    println!("{}", "=".repeat(60));

    // Use the high-level Mdict::open for auto-detection
    match Mdict::open(file_path, passcode) {
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
