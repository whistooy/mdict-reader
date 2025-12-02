# mdict-reader

[![CI](https://github.com/whistooy/mdict-reader/workflows/CI/badge.svg)](https://github.com/whistooy/mdict-reader/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)

A Rust library and command-line tool for reading MDict (`.mdx` and `.mdd`) dictionary files.

The project can:

* open MDX (dictionary) and MDD (resource) files
* parse headers and metadata
* iterate over keys and records
* extract text entries and binary resources via a CLI

It aims to support MDict format versions 1.x, 2.x and 3.x.

***

## Project Status

This is an early-stage project. The core functionality works for the author’s test dictionaries, but:

* the public API may change
* there may be formats or edge cases that are not handled yet

Feedback, bug reports and small test dictionaries are welcome.

***

## Command-Line Tool

The `mdict-reader` binary lets you inspect and extract MDict data from the command line.

### Building and Installing

```Shell
git clone https://github.com/whistooy/mdict-reader.git
cd mdict-reader
cargo install --path .
```

After this, the `mdict-reader` binary should be available in your `$PATH`.

### Basic Usage

The CLI has two main subcommands: `info` and `extract`.

#### Inspect a file (`info`)

Shows metadata and a few sample entries from a `.mdx` or `.mdd` file.

```Shell
mdict-reader info /path/to/dictionary.mdx
mdict-reader info /path/to/resources.mdd
```

Optional flags:

* `--passcode REGCODE_HEX,EMAIL` – passcode for encrypted files
* `--encoding ENCODING` – override text encoding for older (v1/v2) MDX files
* `--substitute-stylesheet` – expand stylesheet markers into tags when reading MDX files (off by default)

#### Extract dictionary content (`extract`)

Extract entries from an MDX file to a text or JSONL file:

```Shell
# Text format (default): "key", definition, "</>" separator between entries
mdict-reader extract /path/to/dictionary.mdx

# JSON Lines format (one JSON object per line)
mdict-reader extract /path/to/dictionary.mdx --format jsonl
```

The output file is written next to the source by default. You can choose a different directory:

```Shell
mdict-reader extract /path/to/dictionary.mdx --output ./out
```

#### Extract resources from MDD

Extract binary resources (images, audio, etc.) from an MDD file:

```Shell
mdict-reader extract /path/to/resources.mdd
```

Resources are written under a `resources/` subdirectory next to the source file, or under `--output` if provided.

#### Extract MDX and all companion MDDs

Many dictionaries ship as one MDX plus several MDD files named like:

* `dict.mdd`
* `dict.1.mdd`
* `dict.2.mdd`
* …

You can extract everything in one go:

```Shell
mdict-reader extract /path/to/dict.mdx --all --output ./dict-extracted
```

This will:

* write the MDX entries to `./dict-extracted/dict.txt` (or `.jsonl`)
* extract all related MDD files into `./dict-extracted/resources/`

***

## Library Usage

You can also use `mdict-reader` as a library in your own Rust code.

Until it is published on crates.io, you can depend on it via Git:

```TOML
[dependencies]
mdict-reader = { git = "https://github.com/whistooy/mdict-reader.git", branch = "main" }
```

### High-level API (`Mdict`)

If you don’t know in advance whether a file is MDX or MDD, you can use the `Mdict` enum:

```Rust
use mdict_reader::{Mdict, RecordData};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mdict = Mdict::open("path/to/file.mdx", None, None, false)?;

    match mdict {
        Mdict::Mdx(reader) => {
            for result in reader.iter_records().take(5) {
                let (key, record) = result?;
                match record {
                    RecordData::Content(text) => println!("{}: {}", key, text),
                    RecordData::Redirect(target) => println!("{} -> {}", key, target),
                }
            }
        }
        Mdict::Mdd(reader) => {
            for result in reader.iter_records().take(5) {
                let (key, record) = result?;
                if let RecordData::Content(bytes) = record {
                    println!("{}: {} bytes", key, bytes.len());
                }
            }
        }
    }

    Ok(())
}
```

### Direct reader (`MdictReader<T>`)

If you know the file type, you can use `MdictReader<T>` directly with the `Mdx` or `Mdd` marker types.

#### MDX example

```Rust
use mdict_reader::{MdictReader, Mdx, RecordData};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = MdictReader::<Mdx>::new("path/to/dict.mdx", None, None, false)?;

    println!("Title: {}", reader.metadata().title);
    println!("Entries: {}", reader.num_entries());

    for result in reader.iter_records().take(3) {
        let (key, record) = result?;
        match record {
            RecordData::Content(text) => println!("{}: {}", key, text),
            RecordData::Redirect(target) => println!("{} -> {}", key, target),
        }
    }

    Ok(())
}
```

Pass `true` as the last argument if you want stylesheet markers expanded into tags; the default `false` preserves raw backtick markers.

#### MDD example

```Rust
use mdict_reader::{MdictReader, Mdd, RecordData};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = MdictReader::<Mdd>::new("path/to/resources.mdd", None, None, false)?;

    for result in reader.iter_records().take(3) {
        let (key, record) = result?;
        if let RecordData::Content(data) = record {
            println!("{}: {} bytes", key, data.len());
        }
    }

    Ok(())
}
```

***

## License

This project is licensed under the MIT License. See the [`LICENSE`](LICENSE) file for details.

***

## Acknowledgements

This crate is an independent implementation of the MDict (`.mdx`/`.mdd`) file format in Rust. The author relied on existing community documentation of the format while developing the code.

In particular, the following resources were used as technical references:

- [`zhansliu/writemdict`](https://github.com/zhansliu/writemdict), especially
  [`fileformat.md`](https://github.com/zhansliu/writemdict/blob/master/fileformat.md),
  which describes the file layout and many low-level details such as header fields,
  block structure, compression, and encryption.

- [`xwang/mdict-analysis`](https://bitbucket.org/xwang/mdict-analysis/), in particular
  its [`README.rst`](https://bitbucket.org/xwang/mdict-analysis/src/master/README.rst)
  with diagrams of the file structure and the
  [`readmdict.py`](https://bitbucket.org/xwang/mdict-analysis/src/master/readmdict.py)
  example program.

These projects were used as format references only; this crate does not include code from them.  
Many thanks to the maintainers of these projects for making their work publicly available.
