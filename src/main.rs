use std::fmt::Display;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::{Args, Parser, Subcommand, ValueEnum};
use mdict_reader::{FileType, Mdict, MdictError, MdictReader};

// --- Constants ---
/// The name of the subdirectory for MDD resources, used to keep outputs tidy.
const MDD_RESOURCES_SUBDIR: &str = "resources";

// --- CLI Argument Parsing Setup ---
/// A command-line tool to inspect and extract MDict (.mdx/.mdd) dictionary files.
#[derive(Parser, Debug)]
#[command(name = "mdict-tool", version, about, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Inspect header info and sample entries from a single .mdx or .mdd file.
    Info(InfoArgs),
    /// Extract content from dictionary files.
    Extract(ExtractArgs),
}

/// Arguments shared between the Info and Extract commands.
#[derive(Args, Debug)]
struct SharedArgs {
    /// Passcode for encrypted files (format: REGCODE_HEX,EMAIL).
    #[arg(long, global = true)]
    passcode: Option<String>,
    /// Override the text encoding for older (v1/v2) .mdx files. Ignored for v3 files.
    #[arg(long, global = true, value_name = "ENCODING")]
    encoding: Option<String>,
}

#[derive(Args, Debug)]
struct InfoArgs {
    /// Path to the .mdx or .mdd file to inspect.
    #[arg(required = true, value_name = "FILE")]
    file: PathBuf,
    #[command(flatten)]
    shared: SharedArgs,
}

#[derive(Args, Debug)]
#[command(about = "Extracts dictionary entries and resources.")]
struct ExtractArgs {
    /// Path to the .mdx or .mdd file to extract.
    #[arg(required = true, value_name = "FILE")]
    file: PathBuf,
    /// Extract the main .mdx and all companion .mdd files (e.g., file.mdd, file.1.mdd).
    #[arg(long, short)]
    all: bool,
    /// Specify the output format for .mdx text content.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Directory for all output files. If not set, files are created next to the source.
    #[arg(long, short, value_name = "DIR")]
    output: Option<PathBuf>,
    #[command(flatten)]
    shared: SharedArgs,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum Format {
    /// Simple text with a '</>' separator (default).
    Text,
    /// Machine-readable JSON Lines (one JSON object per line).
    Jsonl,
}

// --- Main Application Logic ---

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match cli.command {
        Command::Info(args) => run_info(&args.file, &args.shared),
        Command::Extract(args) => run_extract(args),
    }
}

/// Executes the 'info' command.
fn run_info(file: &Path, shared_args: &SharedArgs) {
    print_banner(file, shared_args.passcode.is_some());
    let mdict = open_mdict_or_exit(file, shared_args);

    match mdict {
        Mdict::Mdx(reader) => {
            println!("\nFile Type: MDX (Dictionary)");
            print_common_info(&reader);
            print_samples(&reader, "Definitions", |definition| {
                let mut truncated = definition.trim().replace(['\n', '\r'], " ");
                if truncated.chars().count() > 100 {
                    truncated = truncated.chars().take(100).collect::<String>() + "...";
                }
                println!("     Def: {}", truncated);
            });
        }
        Mdict::Mdd(reader) => {
            println!("\nFile Type: MDD (Resource Data)");
            print_common_info(&reader);
            print_samples(&reader, "Resource Sizes", |data| {
                println!("     Resource Size: {} bytes", data.len());
            });
        }
    }
    println!();
}


/// Executes the 'extract' command with a unified, clean logic flow.
fn run_extract(args: ExtractArgs) {
    #[derive(Debug)]
    enum Task { Mdx, Mdd }
    let mut tasks = Vec::new();

    // 1. Build a list of files to process. This is clear and stays the same.
    if args.all {
        if args.file.extension().and_then(|s| s.to_str()) != Some("mdx") {
            eprint_and_exit("The '--all' flag requires the main .mdx file as input.");
        }
        tasks.push((Task::Mdx, args.file.clone()));
        tasks.extend(find_companion_mdds(&args.file).into_iter().map(|p| (Task::Mdd, p)));
    } else {
        match args.file.extension().and_then(|s| s.to_str()) {
            Some("mdx") => tasks.push((Task::Mdx, args.file)),
            Some("mdd") => tasks.push((Task::Mdd, args.file)),
            _ => eprint_and_exit("Extract command requires an .mdx or .mdd file."),
        }
    }

    // 2. Create the top-level output directory if specified.
    if let Some(output_dir) = &args.output
        && fs::create_dir_all(output_dir).is_err() {
            eprint_and_exit(format!("Could not create output directory: {}", output_dir.display()));
        }
    
    // 3. Execute all tasks in a single, unified loop.
    for (task, path) in tasks {
        let mdict = open_mdict_or_exit(&path, &args.shared);
        match (task, mdict) {
            (Task::Mdx, Mdict::Mdx(reader)) => {
                if let Err(e) = extract_mdx_content(reader, &path, args.format, args.output.as_deref()) {
                    eprintln!("   ERROR: Failed to extract MDX content from {}: {}", path.display(), e);
                }
            }
            (Task::Mdd, Mdict::Mdd(reader)) => {
                // This is the clean, consolidated logic for determining the MDD target directory.
                let base_output_path = args.output.as_deref()
                    .unwrap_or_else(|| path.parent().unwrap_or_else(|| Path::new(".")));

                // Use a subdirectory if doing a full extraction (`--all`) OR if saving next to
                // the source file (to avoid cluttering the source directory).
                let use_subdir = args.all || args.output.is_none();
                
                let target_dir = if use_subdir {
                    base_output_path.join(MDD_RESOURCES_SUBDIR)
                } else {
                    base_output_path.to_path_buf()
                };
                
                if let Err(e) = extract_mdd_resources(reader, &path, &target_dir) {
                    eprintln!("   ERROR: Failed to extract MDD resources from {}: {}", path.display(), e);
                }
            }
            _ => eprintln!("   WARN: Skipped mismatched file type for task: {}", path.display()),
        }
    }
}

/// Extracts content from an MDX reader.
fn extract_mdx_content(reader: MdictReader<mdict_reader::Mdx>, path: &Path, format: Format, output_dir: Option<&Path>) -> Result<(), MdictError> {
    println!("\n-> Extracting MDX content from {}...", path.display());
    
    let output_base = get_output_base_path(path, output_dir);
    let out_path = output_base.with_extension(match format {
        Format::Text => "txt",
        Format::Jsonl => "jsonl",
    });

    let mut out = create_writer(&out_path)?;
    let mut first_entry = true;
    for result in reader.iter_records() {
        let (key, def) = match result {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("   WARN: Skipping entry due to error: {}", e);
                continue;
            }
        };

        if !first_entry {
            write!(out, "\r\n")?; // Write separator before subsequent entries
        }
        first_entry = false;

        match format {
            Format::Text => {
                let trimmed_def = def.trim_end();
                write!(out, "{}\r\n{}\r\n</>", key, trimmed_def)?;
            },
            Format::Jsonl => {
                let json_string = serde_json::to_string(&serde_json::json!({ "key": key, "record": def }))
                    .map_err(|e| MdictError::InvalidFormat(format!("JSON serialization failed: {}", e)))?;
                write!(out, "{}", json_string)?;
            },
        };
    }
    out.flush()?; // Ensure all buffered data is written

    println!("   SUCCESS: Entries written to {}", out_path.display());

    if let Some(stylesheet) = &reader.header.stylesheet {
        let style_path = output_base.with_file_name(format!("{}_style.css", output_base.file_stem().unwrap_or_default().to_string_lossy()));
        if fs::write(&style_path, stylesheet).is_err() {
            eprintln!("   WARN: Could not write stylesheet to {}", style_path.display());
        } else {
            println!("   SUCCESS: Stylesheet written to {}", style_path.display());
        }
    }
    Ok(())
}

/// Extracts resources from an MDD reader into a specific target directory.
fn extract_mdd_resources(reader: MdictReader<mdict_reader::Mdd>, path: &Path, target_dir: &Path) -> Result<(), MdictError> {
    println!("\n-> Extracting MDD resources from {}...", path.display());
    
    fs::create_dir_all(target_dir)?;

    let mut success_count = 0;
    for result in reader.iter_records() {
        let (key, data) = match result {
            Ok(pair) => pair,
            Err(e) => { eprintln!("   WARN: Skipping resource due to error: {}", e); continue; }
        };
        let rel_path = key.replace('\\', std::path::MAIN_SEPARATOR_STR);
        let out_path = target_dir.join(rel_path.strip_prefix(std::path::MAIN_SEPARATOR).unwrap_or(&rel_path));
        
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if fs::write(&out_path, &data).is_ok() {
            success_count += 1;
        } else {
            eprintln!("   WARN: Could not write resource to {}", out_path.display());
        }
    }
    println!(
        "   SUCCESS: Extracted {} / {} resources to {}",
        success_count,
        reader.num_entries(),
        target_dir.display()
    );
    Ok(())
}

// --- General Helper Functions ---
fn open_mdict_or_exit(file: &Path, args: &SharedArgs) -> Mdict {
    let passcode_ref = args.passcode.as_deref()
        .map(|s| s.split_once(',')
            .unwrap_or_else(|| eprint_and_exit("Invalid passcode format. Expected 'REGCODE_HEX,EMAIL'.")));
    match Mdict::open(file, passcode_ref, args.encoding.as_deref()) {
        Ok(mdict) => mdict,
        Err(e) => eprint_and_exit(format!("Failed to open '{}': {}", file.display(), e)),
    }
}

fn find_companion_mdds(mdx_file: &Path) -> Vec<PathBuf> {
    let mut companions = Vec::new();
    let base_name = mdx_file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let dir = mdx_file.parent().unwrap_or_else(|| Path::new("."));
    let mut i = 0;
    loop {
        let suffix = if i == 0 { String::new() } else { format!(".{}", i) };
        let mdd_path = dir.join(format!("{base_name}{suffix}.mdd"));
        if mdd_path.exists() {
            companions.push(mdd_path);
            i += 1;
        } else {
            break;
        }
    }
    companions
}

fn get_output_base_path(source_path: &Path, output_dir: Option<&Path>) -> PathBuf {
    let file_stem = source_path.file_stem().unwrap_or_default();
    match output_dir {
        Some(dir) => dir.join(file_stem),
        None => {
            let mut p = source_path.to_path_buf();
            p.set_extension("");
            p
        }
    }
}

fn print_common_info<T: FileType>(reader: &MdictReader<T>) {
    println!("\n{:=<60}", "");
    println!("✓ SUCCESS - Metadata loaded");
    println!("{:=<60}", "");
    println!("\nDictionary Information:");
    println!("  Title:       {}", reader.header.title);
    println!("  Version:     {}", reader.header.engine_version);
    println!("  Encoding:    {}", reader.header.encoding.name());
    println!("  Encrypted:   blocks={}, index={}", reader.header.encryption_flags.encrypt_record_blocks, reader.header.encryption_flags.encrypt_key_index);
    if let Some(desc) = &reader.header.description {
        println!("  Description: {}", desc);
    }
    println!("\nStatistics:");
    println!("  Key entries:    {}", reader.num_entries());
    println!("  Key blocks:     {}", reader.num_key_blocks());
    println!("  Record blocks:  {}", reader.num_record_blocks());
}

fn print_samples<T: FileType>(reader: &MdictReader<T>, description: &str, print_record_details: impl Fn(&T::Record)) {
    let desired_sample_count = 10;
    println!("\nSample Entries & {} (showing first up to {}):", description, desired_sample_count);
    for (i, entry_result) in reader.iter_records().take(desired_sample_count).enumerate() {
        match entry_result {
            Ok((key, record)) => {
                println!("  {:2}. Key: {}", i + 1, key);
                print_record_details(&record);
            }
            Err(e) => eprintln!("  Error fetching entry {}: {}", i + 1, e),
        }
    }
    println!("\nTotal entries in dictionary: {}", reader.num_entries());
}

fn print_banner(file: &Path, has_passcode: bool) {
    println!("\n{:=<60}\nMDict Tool\n{:=<60}", "", "");
    println!("File: {}", file.display());
    if has_passcode { println!("Passcode: provided"); }
}

fn eprint_and_exit<T: Display>(msg: T) -> ! {
    eprintln!("\n{:=<60}\n✗ ERROR\n{:=<60}", "", "");
    eprintln!("{}", msg);
    eprintln!();
    process::exit(1);
}

fn create_writer(path: &Path) -> Result<BufWriter<File>, MdictError> {
    File::create(path)
        .map(BufWriter::new)
        .map_err(MdictError::Io)
}
