use encoding_rs::GB18030;
use mdict_reader::{Mdd, MdictReader, Mdx, RecordData};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

type MdxFixture = (&'static str, &'static str, &'static [(&'static str, usize)]);

const MDX_FIXTURES: &[MdxFixture] = &[
    ("utf8-2.0.mdx", "utf8_keys_varied.txt", &[("duplicate", 2)]),
    ("utf8-3.0.mdx", "utf8_keys_varied.txt", &[("duplicate", 2)]),
    ("gbk-2.0.mdx", "gbk_keys_varied.txt", &[("重复-key", 2)]),
    (
        "utf16-2.0.mdx",
        "utf16_keys_varied.txt",
        &[("duplicate", 2)],
    ),
];

const MDD_FIXTURES: &[&str] = &[
    "utf8-2.0.mdd",
    "utf8-3.0.mdd",
    "gbk-2.0.mdd",
    "utf16-2.0.mdd",
];

enum Expect<'a> {
    Content(&'a str),
    Redirect(&'a str),
}

const EXPECTED_RECORDS: &[(&str, &[(&str, Expect)])] = &[
    (
        "utf8-2.0.mdx",
        &[
            ("alpha", Expect::Content("Lowercase.")),
            ("redirect->alpha", Expect::Redirect("alpha")),
            (
                "style-demo",
                Expect::Content("<b>bold span</b><i><em>inline</em></i>(("),
            ),
            ("café", Expect::Content("Accented key.")),
            ("ümlaut", Expect::Content("Umlaut key.")),
            ("Árbol", Expect::Content("Combining-acute")),
            ("Chinese-key", Expect::Content("English counterpart")),
            ("中文-key", Expect::Content("Chinese + dash")),
        ],
    ),
    (
        "utf8-3.0.mdx",
        &[
            ("alpha", Expect::Content("Lowercase.")),
            ("redirect->alpha", Expect::Redirect("alpha")),
            ("café", Expect::Content("Accented key.")),
            ("ümlaut", Expect::Content("Umlaut key.")),
            ("Árbol", Expect::Content("Combining-acute")),
            ("Chinese-key", Expect::Content("English counterpart")),
            ("中文-key", Expect::Content("Chinese + dash")),
        ],
    ),
    (
        "utf16-2.0.mdx",
        &[
            ("alpha", Expect::Content("Lowercase.")),
            ("redirect->alpha", Expect::Redirect("alpha")),
            (
                "style-demo",
                Expect::Content("<b>bold span</b><i><em>inline</em></i>("),
            ),
            ("café", Expect::Content("Accented key.")),
            ("ümlaut", Expect::Content("Umlaut key.")),
            ("Árbol", Expect::Content("Combining-acute")),
            ("Chinese-key", Expect::Content("English counterpart")),
            ("中文-key", Expect::Content("Chinese + dash")),
        ],
    ),
    (
        "gbk-2.0.mdx",
        &[
            ("啊a", Expect::Content("字+ASCII组合 (a)。")),
            ("跳转->测试", Expect::Redirect("测试-1")),
            ("阿-", Expect::Content("字+符号组合 (-)。")),
            (
                "LatinMix",
                Expect::Content("纯ASCII键，便于对比大小写处理。"),
            ),
        ],
    ),
];

fn fixture_path(parts: &[&str]) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for part in parts {
        p.push(part);
    }
    p
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "")
}

fn read_source_text(path: &Path) -> String {
    let data =
        fs::read(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    // BOM check for UTF-16LE
    if data.starts_with(&[0xFF, 0xFE]) {
        let decoded = String::from_utf16_lossy(
            &data[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        return decoded;
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.contains("gbk") {
        let (cow, _, had_errors) = GB18030.decode(&data);
        if had_errors {
            panic!("GBK decode error in {}", path.display());
        }
        return cow.to_string();
    }
    String::from_utf8(data)
        .unwrap_or_else(|e| panic!("utf-8 decode error in {}: {}", path.display(), e))
}

fn load_source_counts(path: &Path) -> HashMap<String, usize> {
    let raw = read_source_text(path);
    let mut counts = HashMap::new();
    let mut lines = raw.lines();
    while let Some(key) = lines.next() {
        for line in lines.by_ref() {
            if line.trim() == "</>" {
                break;
            }
            let _ = line;
        }
        counts
            .entry(key.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }
    counts
}

fn assert_mdx_fixture(mdx_name: &str, source_name: &str, duplicates: &[(&str, usize)]) {
    let mdx_path = fixture_path(&["tests", mdx_name]);
    let source_path = fixture_path(&["tests", "fixtures_src", source_name]);

    let expected_counts = load_source_counts(&source_path);
    let reader = MdictReader::<Mdx>::new(&mdx_path, None, None, true).expect("open mdx");

    let records: Vec<(String, RecordData<String>)> = reader
        .iter_records()
        .map(|r| r.expect("record ok"))
        .collect();
    assert_eq!(
        records.len() as u64,
        reader.num_entries(),
        "entry count mismatch for {}",
        mdx_name
    );
    assert!(
        reader.num_record_blocks() > 1,
        "expected multiple record blocks in {}",
        mdx_name
    );

    let mut actual_counts: HashMap<String, usize> = HashMap::new();
    for (k, _) in &records {
        actual_counts
            .entry(k.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }
    for (k, expected) in expected_counts {
        let actual = actual_counts
            .get(&k)
            .copied()
            .unwrap_or_else(|| panic!("missing key {} in {}", k, mdx_name));
        assert_eq!(expected, actual, "duplicate count mismatch for key {}", k);
    }
    for (k, expected) in duplicates {
        let actual = actual_counts.get(*k).copied().unwrap_or(0);
        assert_eq!(
            *expected, actual,
            "expected {} occurrences of {}",
            expected, k
        );
    }

    let keys: Vec<(String, u64)> = reader.iter_keys().map(|r| r.expect("key ok")).collect();
    for win in keys.windows(2) {
        assert!(win[0].1 < win[1].1, "non-monotonic offset in {}", mdx_name);
    }

    let sample = keys.len().min(8);
    for i in 0..sample {
        let (key, start) = &keys[i];
        let end = keys
            .get(i + 1)
            .map(|(_, off)| *off)
            .unwrap_or_else(|| reader.total_record_decomp_size);

        let direct = reader
            .read_record(*start, end)
            .unwrap_or_else(|e| panic!("read_record failed for {}: {}", key, e));
        let iter_pair = &records[i];
        assert_eq!(&iter_pair.0, key, "key mismatch at index {}", i);
        match (&direct, &iter_pair.1) {
            (RecordData::Content(a), RecordData::Content(b)) => {
                assert_eq!(
                    normalize(a),
                    normalize(b),
                    "content mismatch at key {}",
                    key
                );
            }
            (RecordData::Redirect(a), RecordData::Redirect(b)) => {
                assert_eq!(a, b, "redirect mismatch at key {}", key);
            }
            _ => panic!("variant mismatch at key {} in {}", key, mdx_name),
        }

        let block = *reader
            .find_block_by_offset(*start)
            .expect("block for offset");
        let mut buf = Vec::new();
        reader
            .read_and_decode_block_into(&mut buf, block)
            .expect("decode block");
        assert_eq!(
            buf.len() as u64,
            block.decompressed_size,
            "decoded block size mismatch in {} (offset {}, decompressed {}, compressed {})",
            mdx_name,
            block.decompressed_offset,
            block.decompressed_size,
            block.compressed_size
        );
    }

    if let Some((_, expected)) = EXPECTED_RECORDS.iter().find(|(name, _)| *name == mdx_name) {
        let mut map: HashMap<String, RecordData<String>> = HashMap::new();
        for (k, v) in records.iter() {
            map.insert(k.clone(), v.clone());
        }
        for (key, expect) in *expected {
            let got = map
                .get(*key)
                .unwrap_or_else(|| panic!("missing expected key {} in {}", key, mdx_name));
            match (expect, got) {
                (Expect::Content(snippet), RecordData::Content(body)) => {
                    assert!(
                        body.contains(snippet),
                        "expected content snippet {:?} for key {} in {}, got {:?}",
                        snippet,
                        key,
                        mdx_name,
                        body
                    );
                    assert!(
                        !body.contains('`'),
                        "unexpected backtick in substituted content for key {} in {}: {:?}",
                        key,
                        mdx_name,
                        body
                    );
                }
                (Expect::Redirect(target), RecordData::Redirect(actual)) => {
                    assert_eq!(
                        target, actual,
                        "redirect target mismatch for key {} in {}",
                        key, mdx_name
                    );
                }
                _ => panic!("unexpected record variant for key {} in {}", key, mdx_name),
            }
        }
    }
}

fn load_expected_resources() -> HashMap<String, Vec<u8>> {
    let base = fixture_path(&["tests", "fixtures_src", "resources"]);
    let mut map = HashMap::new();
    for entry in fs::read_dir(&base).expect("read resources dir") {
        let entry = entry.expect("dir entry");
        if entry.file_type().expect("file type").is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            let data = fs::read(entry.path()).expect("read resource file");
            map.insert(name, data);
        }
    }
    map
}

fn assert_mdd_fixture(mdd_name: &str) {
    let mdd_path = fixture_path(&["tests", mdd_name]);
    let expected = load_expected_resources();
    let reader = MdictReader::<Mdd>::new(&mdd_path, None, None, true).expect("open mdd");

    assert!(
        reader.num_record_blocks() > 1,
        "expected multiple record blocks in {}",
        mdd_name
    );

    let mut actual: HashMap<String, Vec<u8>> = HashMap::new();
    for result in reader.iter_records() {
        let (key, record) = result.expect("record ok");
        match record {
            RecordData::Content(bytes) => {
                let normalized = key.trim_start_matches(['\\', '/']).to_string();
                actual.insert(normalized, bytes);
            }
            RecordData::Redirect(target) => {
                panic!("unexpected redirect {} -> {} in {}", key, target, mdd_name)
            }
        }
    }

    assert_eq!(
        expected.len(),
        actual.len(),
        "resource count mismatch in {}",
        mdd_name
    );
    for (name, bytes) in expected {
        let act = actual
            .get(&name)
            .unwrap_or_else(|| panic!("missing resource {} in {}", name, mdd_name));
        assert_eq!(
            bytes, *act,
            "resource bytes differ for {} in {}",
            name, mdd_name
        );
    }
}

#[test]
fn mdx_fixtures_match_sources() {
    for (mdx, source, duplicates) in MDX_FIXTURES {
        assert_mdx_fixture(mdx, source, duplicates);
    }
}

#[test]
fn mdx_stylesheet_substitution_can_be_disabled() {
    let mdx_path = fixture_path(&["tests", "utf8-2.0.mdx"]);
    let reader =
        MdictReader::<Mdx>::new(&mdx_path, None, None, false).expect("open mdx without styles");

    let style_record = reader
        .iter_records()
        .find_map(|res| match res {
            Ok((key, record)) if key == "style-demo" => Some(record),
            Ok(_) => None,
            Err(e) => panic!("record error: {}", e),
        })
        .expect("style-demo entry");

    let content = match style_record {
        RecordData::Content(body) => body,
        RecordData::Redirect(target) => {
            panic!("style-demo unexpectedly redirected to {}", target)
        }
    };

    assert!(
        content.contains('`'),
        "expected raw stylesheet markers when substitution is disabled"
    );
    assert!(
        !content.contains("<b>"),
        "stylesheet substitution should be skipped when disabled"
    );
}

#[test]
fn mdd_fixtures_match_resources() {
    for mdd in MDD_FIXTURES {
        assert_mdd_fixture(mdd);
    }
}
