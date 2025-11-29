use log::{debug, info, trace};
use std::fs::File;
use std::io::{Read, Seek};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::format;
use super::format::content;
use super::iter::{KeysIterator, RecordIterator};
use super::types::error::{MdictError, Result};
use super::types::filetypes::FileType;
use super::types::models::{
    BlockMeta, EncryptionFlags, MasterKey, MdictEncoding, MdictHeader, MdictMetadata, MdictVersion,
    RecordData, StyleSheet, parse_stylesheet,
};

/// The main reader for MDict dictionary files.
///
/// This type-parameterized reader handles both MDX (dictionary definitions)
/// and MDD (resource data) files across all MDict format versions (1.x, 2.x, 3.x).
///
/// # Type Parameter
/// * `T` - File type marker: [`Mdx`] for dictionaries, [`Mdd`] for resources
///
/// # Thread Safety
/// The internal file handle is wrapped in `Arc<Mutex<File>>`, making the reader
/// `Send` and `Sync` for concurrent access from multiple threads.
#[derive(Debug)]
pub struct MdictReader<T: FileType> {
    file: Arc<Mutex<File>>,

    // Parsing-critical fields (stored directly for zero-lock access)
    version: MdictVersion,
    encoding: MdictEncoding,
    encryption_flags: EncryptionFlags,
    master_key: MasterKey,
    parsed_stylesheet: StyleSheet,

    // Display metadata
    metadata: MdictMetadata,

    key_blocks: Vec<BlockMeta>,
    record_blocks: Vec<BlockMeta>,
    pub total_record_decomp_size: u64,

    /// Total number of entries in the dictionary (cached from index parsing).
    num_entries: u64,
    _file_type: PhantomData<T>,
}

impl<T: FileType> MdictReader<T> {
    /// Opens and parses an MDict file from the given path.
    ///
    /// # Text Encoding Priority
    /// Encoding is determined in this order (highest to lowest):
    /// 1. **Version 3.0**: Always uses UTF-8 regardless of file type or user settings
    /// 2. **MDD files**: Always use UTF-16LE per format specification
    /// 3. **MDX v1/v2**: `user_encoding` parameter if provided
    /// 4. **Fallback**: Encoding declared in the file's XML header
    ///
    /// # Arguments
    /// * `path` - Path to the MDict file (.mdx or .mdd)
    /// * `passcode` - Optional decryption credentials as `(regcode_hex, user_email)`
    /// * `user_encoding` - Optional encoding override (only applies to MDX v1/v2 files)
    ///
    /// # Errors
    /// Returns [`MdictError`] if:
    /// - File cannot be opened or read
    /// - File format is invalid or corrupted
    /// - Version is unsupported (4.0+)
    /// - Checksum verification fails
    /// - File is encrypted but no valid passcode provided
    pub fn new(
        path: impl AsRef<Path>,
        passcode: Option<(&str, &str)>,
        user_encoding: Option<&str>,
    ) -> Result<Self> {
        let path = path.as_ref();
        info!("Opening {} file: {}", T::DEBUG_NAME, path.display());
        let mut file = File::open(path)?;

        // Step 1: Parse file header and extract metadata
        debug!("Parsing file header");
        let MdictHeader {
            version,
            mut encoding,
            encryption_flags,
            master_key,
            metadata,
        } = format::header::parse(&mut file, passcode)?;

        // Step 2: Apply version-specific encoding rules
        let original_encoding = encoding;
        let final_encoding = if version == MdictVersion::V3 {
            // V3.0 always uses UTF-8 regardless of header or user settings
            encoding_rs::UTF_8
        } else {
            // For v1/v2, apply encoding override priority:
            // 1. File type override (MDD → UTF-16LE)
            // 2. User-provided encoding parameter
            // 3. Encoding from file header
            T::ENCODING_OVERRIDE
                .or_else(|| user_encoding.map(super::utils::parse_encoding))
                .unwrap_or(encoding)
        };

        // Log encoding changes for clarity
        if original_encoding != final_encoding {
            debug!(
                "Encoding override applied: header='{}' → final='{}' (reason: {})",
                original_encoding.name(),
                final_encoding.name(),
                if version == MdictVersion::V3 {
                    "V3.0 specification"
                } else if T::ENCODING_OVERRIDE.is_some() {
                    "MDD file type requires UTF-16LE"
                } else {
                    "user parameter"
                }
            );
        }
        encoding = final_encoding;

        // Step 3: Parse index blocks (version-specific)
        debug!("Parsing block indexes");
        let (key_blocks, record_blocks, total_record_decomp_size, num_entries) =
            format::index::parse(&mut file, version, encoding, encryption_flags, master_key)?;

        info!(
            "{} file loaded: {} entries, {} key blocks, {} record blocks",
            T::DEBUG_NAME,
            num_entries,
            key_blocks.len(),
            record_blocks.len()
        );

        // Parse stylesheet immediately if present (returns empty HashMap if none)
        let parsed_stylesheet = metadata
            .stylesheet_raw
            .as_ref()
            .map(|s| parse_stylesheet(s))
            .unwrap_or_default();

        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            version,
            encoding,
            encryption_flags,
            master_key,
            parsed_stylesheet,
            metadata,
            key_blocks,
            record_blocks,
            total_record_decomp_size,
            num_entries,
            _file_type: PhantomData,
        })
    }

    /// Returns the total number of key blocks in the file.
    pub fn num_key_blocks(&self) -> usize {
        self.key_blocks.len()
    }

    /// Returns the total number of record blocks in the file.
    pub fn num_record_blocks(&self) -> usize {
        self.record_blocks.len()
    }

    /// Returns the total number of dictionary entries.
    ///
    /// This is O(1) as the count is cached during index parsing.
    pub fn num_entries(&self) -> u64 {
        self.num_entries
    }

    /// Returns a reference to the display metadata.
    ///
    /// Provides access to user-visible information such as title, description, and engine version.
    pub fn metadata(&self) -> &MdictMetadata {
        &self.metadata
    }

    /// Returns the MDict version.
    pub fn version(&self) -> MdictVersion {
        self.version
    }

    /// Returns the text encoding used in this file.
    pub fn encoding(&self) -> MdictEncoding {
        self.encoding
    }

    /// Returns the encryption flags indicating which parts of the file are encrypted.
    pub fn encryption_flags(&self) -> EncryptionFlags {
        self.encryption_flags
    }

    /// Returns an iterator over `(key, start, end)` tuples.
    ///
    /// This iterator decodes key blocks and resolves each entry to its byte range
    /// in the decompressed record stream. The returned tuples contain:
    /// - `key`: The dictionary key (word/term)
    /// - `start`: Starting byte offset in the virtual decompressed stream
    /// - `end`: Ending byte offset (exclusive)
    ///
    /// The byte ranges are self-contained and remain valid even after re-sorting,
    /// making this ideal for building custom search indexes.
    ///
    /// # Use Cases
    /// - Building sortable search indexes
    /// - Extracting specific entries by key
    /// - Custom caching strategies
    ///
    /// Chain with [`.with_records()`](KeysIterator::with_records) to access definitions.
    pub fn iter_keys(&self) -> KeysIterator<'_, T> {
        KeysIterator::new(self)
    }

    /// Returns an iterator over all `(key, record_data)` pairs.
    ///
    /// This is equivalent to `reader.iter_keys().with_records()`.
    ///
    /// The iterator handles all decoding steps:
    /// 1. Decodes key blocks to get search keys
    /// 2. Resolves record locations via block metadata
    /// 3. Decodes and extracts record data (including redirect detection)
    ///
    /// # Redirect Handling
    /// This method returns [`RecordData<T::Record>`] which can be:
    /// - `RecordData::Content(data)` - Actual record content
    /// - `RecordData::Redirect(target_key)` - Internal redirect to another entry
    ///
    /// Users are responsible for resolving redirects if desired.
    ///
    /// # Yield Type
    /// - **MDX files**: `Result<(String, RecordData<String>)>` - key and definition or redirect
    /// - **MDD files**: `Result<(String, RecordData<Vec<u8>>)>` - key and resource data or redirect
    ///
    /// # Example
    /// ```no_run
    /// # use mdict_reader::{MdictReader, Mdx, RecordData};
    /// # let reader = MdictReader::<Mdx>::new("dict.mdx", None, None).unwrap();
    /// for result in reader.iter_records() {
    ///     let (key, record_data) = result.unwrap();
    ///     match record_data {
    ///         RecordData::Content(text) => println!("{}: {}", key, text),
    ///         RecordData::Redirect(target) => println!("{} → {}", key, target),
    ///     }
    /// }
    /// ```
    pub fn iter_records(&self) -> RecordIterator<'_, T> {
        self.iter_keys().with_records()
    }

    /// Locates and reads a single record by its byte range.
    ///
    /// Uses binary search on record blocks to efficiently find the containing block,
    /// then extracts and decodes the record data.
    ///
    /// # Parameters
    /// * `start` - Starting byte offset in the virtual decompressed stream
    /// * `end` - Ending byte offset (exclusive)
    ///
    /// # Return Type
    /// Returns a [`RecordData`] enum which can be:
    /// - `RecordData::Content(T::Record)` - Actual record content
    /// - `RecordData::Redirect(String)` - Internal redirect to another key
    ///
    /// # Performance Note
    /// This method performs file I/O for each call. For sequential access,
    /// prefer using [`iter_records()`](Self::iter_records) which caches blocks.
    ///
    /// # Example
    /// ```no_run
    /// # use mdict_reader::{MdictReader, Mdx, RecordData};
    /// # let reader = MdictReader::<Mdx>::new("dict.mdx", None, None).unwrap();
    /// match reader.read_record(0, 100).unwrap() {
    ///     RecordData::Content(text) => println!("Content: {}", text),
    ///     RecordData::Redirect(target) => println!("Redirects to: {}", target),
    /// }
    /// ```
    pub fn read_record(&self, start: u64, end: u64) -> Result<RecordData<T::Record>> {
        trace!("Reading record: range=[{}..{}]", start, end);

        let block_meta = self.find_block_by_offset(start)?;

        let block_start = start - block_meta.decompressed_offset;
        let block_end = end - block_meta.decompressed_offset;

        let mut buffer = Vec::new();
        self.read_and_decode_block_into(&mut buffer, *block_meta)?;

        self.parse_record(&buffer, block_start, block_end)
    }

    /// Finds the record block containing the given offset.
    ///
    /// This is a helper method for advanced users who need block-level information
    /// for custom caching or processing strategies.
    ///
    /// # Parameters
    /// * `offset` - Byte offset in the virtual decompressed stream
    ///
    /// # Returns
    /// A reference to the [`BlockMeta`] containing the offset, which includes:
    /// - `decompressed_offset`: Where this block starts in the virtual stream
    /// - `decompressed_size`: Size of the decompressed block
    /// - `compressed_size`: Size of the compressed block in the file
    /// - `file_offset`: Where the compressed block is located in the file (unique identifier)
    ///
    /// # Example
    /// ```no_run
    /// # use mdict_reader::{MdictReader, Mdx};
    /// # let reader = MdictReader::<Mdx>::new("dict.mdx", None, None).unwrap();
    /// // Find which block contains offset 1000
    /// let block_meta = reader.find_block_by_offset(1000).unwrap();
    /// println!("Block at file offset: {}", block_meta.file_offset);
    /// ```
    pub fn find_block_by_offset(&self, offset: u64) -> Result<&BlockMeta> {
        if self.record_blocks.is_empty() {
            return Err(MdictError::InvalidFormat(
                "No record blocks available".to_string(),
            ));
        }

        let block_index = self
            .record_blocks
            .partition_point(|block| block.decompressed_offset <= offset)
            .saturating_sub(1);

        let block_meta = self.record_blocks.get(block_index).ok_or_else(|| {
            MdictError::InvalidFormat(format!("Offset {} is out of bounds", offset))
        })?;

        // Validate offset is within block bounds
        if offset >= block_meta.decompressed_offset + block_meta.decompressed_size {
            return Err(MdictError::InvalidFormat(format!(
                "Offset {} exceeds block bounds",
                offset
            )));
        }

        Ok(block_meta)
    }

    /// Extracts a record from an already-decompressed block.
    ///
    /// This is a zero-copy operation on in-memory data, used internally by
    /// [`RecordIterator`] to avoid redundant block decompression.
    ///
    /// # Parameters
    /// * `block_bytes` - Decompressed block data
    /// * `start` - Start position of the record within the block
    /// * `end` - End position of the record within the block (exclusive)
    pub fn parse_record(
        &self,
        block_bytes: &[u8],
        start: u64,
        end: u64,
    ) -> Result<RecordData<T::Record>> {
        content::parse_record::<T>(
            block_bytes,
            start,
            end,
            self.encoding,
            &self.parsed_stylesheet,
        )
    }

    /// Reads, decrypts, and decompresses a block from the file.
    ///
    /// This is a public method to enable custom caching strategies. Advanced users
    /// can call [`find_block_by_offset()`](Self::find_block_by_offset) to get the
    /// [`BlockMeta`], then use this method to read and decode the block.
    ///
    /// # Parameters
    /// * `block_meta` - Block metadata containing file offset and sizes
    ///
    /// # Returns
    /// The fully decompressed block data ready for record extraction.
    pub fn read_and_decode_block_into(
        &self,
        output: &mut Vec<u8>,
        block_meta: BlockMeta,
    ) -> Result<()> {
        trace!(
            "Reading block: offset={}, compressed={} bytes, decompressed={} bytes",
            block_meta.file_offset, block_meta.compressed_size, block_meta.decompressed_size
        );

        let mut file = self.file.lock().map_err(|_| MdictError::LockPoisoned)?;
        file.seek(std::io::SeekFrom::Start(block_meta.file_offset))?;
        let mut raw_block = vec![0u8; block_meta.compressed_size as usize];
        file.read_exact(&mut raw_block)?;

        content::decode_block_into(
            output,
            &mut raw_block,
            block_meta.decompressed_size,
            self.master_key,
            self.version,
        )
    }

    pub(crate) fn key_blocks(&self) -> &[BlockMeta] {
        &self.key_blocks
    }

    pub(crate) fn record_blocks(&self) -> &[BlockMeta] {
        &self.record_blocks
    }
}
