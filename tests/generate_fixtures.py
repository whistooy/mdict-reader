#!/usr/bin/env python3
"""
Generate MDX source files that stress key sorting across encodings.

Outputs go to fixtures_src/:
- utf8_keys_varied.txt  (UTF-8)
- gbk_keys_varied.txt   (GBK/GB2312-safe)
- utf16_keys_varied.txt (UTF-16LE with BOM)
"""

from pathlib import Path
import struct
import wave

base = Path("fixtures_src")
base.mkdir(parents=True, exist_ok=True)

# Long padding to force multi-blocks when building MDX (intentionally large).
LOREM = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 16 + "\n") * 400

# UTF-8: rich key set with punctuation, case variants, accents, combining marks, and mixed scripts.
utf8_keys = [
    ("!bang", "Leading punctuation."),
    ("#hash", "Hash in key."),
    ("-dash", "Leading dash key."),
    ("=equals", "Equals in key."),
    ("?question", "Question in key."),
    ("@at", "At-sign key."),
    ("[bracket", "Opening bracket."),
    ("]bracket", "Closing bracket."),
    ("{brace", "Opening brace."),
    ("}brace", "Closing brace."),
    ("00number", "Leading digits."),
    ("0zero-alpha", "Digit + dash."),
    ("Alpha", "Title case."),
    ("alpha", "Lowercase."),
    ("ALPHA", "Uppercase."),
    ("Alpha-1", "Dash, Title."),
    ("alpha-1", "Dash, lower."),
    ("ALPHA-1", "Dash, upper."),
    ("Alpha_1", "Underscore variant."),
    ("Alpha 1", "Space variant."),
    ("Árbol", "Precomposed Á; check case-fold behavior."),
    ("A\u0301rbol", "Combining-acute Á; compare to Árbol."),
    ("á", "Lowercase accented."),
    ("Á", "Uppercase accented."),
    ("à", "Grave."),
    ("çedille", "Cedilla."),
    ("ümlaut", "Umlaut key."),
    ("café", "Accented key."),
    ("camelCase", "Mixed case key."),
    ("snake_case", "Underscore key."),
    ("kebab-case", "Dash-only key."),
    ("mixed/forward", "Forward slash key."),
    ("mixed\\back", "Backslash key."),
    ("plus+key", "Plus key."),
    ("dots...key", "Ellipsis key."),
    ("tilde~key", "Tilde key."),
    ("question?key", "Question in key."),
    ("exclaim!key", "Exclamation key."),
    ("at@key", "At-in-body key."),
    ("hash#key", "Hash-in-body key."),
    ("Chinese-key", "English counterpart of 中文-key."),
    ("中文-key", "Chinese + dash key."),
    ("duplicate", "First duplicate definition."),
    ("duplicate", "Second duplicate definition."),
    ("redirect->alpha", "@@@LINK=alpha"),
    ("style-demo", "`1`bold span`2`<em>inline</em>`3`(demo)"),
    ("padding", LOREM),
]

# GBK/GB2312-safe keys; focus on multibyte handling and ASCII/Chinese mixes.
gbk_keys = [
    ("!符号", "标点起始键。"),
    ("#号", "井号键。"),
    ("-横线", "短横线键。"),
    ("测试-1", "中文键带短横线，含标点。"),
    ("测试-EN", "English counterpart test-EN."),
    ("编码_case", "下划线键，混排 English/中文。"),
    ("encoding-case", "English counterpart of 编码_case."),
    ("例子:示例", "冒号键，含数字123。"),
    ("example:demo", "English counterpart of 例子:示例。"),
    # GBK multibyte edge cases (e.g., “啊” 0xB0A1; “阿” 0xB0A2)
    ("啊", "单字测试 GBK B0A1。"),
    ("啊a", "字+ASCII组合 (a)。"),
    ("啊b", "字+ASCII组合 (b)。"),
    ("啊-", "字+符号组合 (-)。"),
    ("阿", "单字测试 GBK B0A2。"),
    ("阿a", "字+ASCII组合。"),
    ("阿b", "字+ASCII组合。"),
    ("阿-", "字+符号组合 (-)。"),
    # Duplicates
    ("重复-key", "第一次重复。"),
    ("重复-key", "第二次重复。"),
    # Case/dash mix
    ("大小写-Aa", "大小写+dash。"),
    ("符号?问", "问号键，混排标点。"),
    ("波浪~键", "波浪线键。"),
    # Accented characters cannot appear in GBK keys; include ASCII/Chinese mixes only.
    ("LatinMix", "纯ASCII键，便于对比大小写处理。"),
    ("跳转->测试", "@@@LINK=测试-1"),
    # Padding to help force multi-blocks when encoded in GBK (ASCII text is safe).
    ("填充", LOREM),
]

# UTF-16LE with BOM; reuse the UTF-8 key set to compare sort behavior across encodings.
utf16_keys = utf8_keys


def write_entries(path: Path, entries, encoding: str, add_bom: bool = False) -> None:
    lines = []
    for key, val in entries:
        lines.append(key)
        lines.append(val)
        lines.append("</>")
    data = "\r\n".join(lines)
    if add_bom:
        path.write_bytes(b"\xff\xfe" + data.encode(encoding))
    else:
        path.write_bytes(data.encode(encoding))


write_entries(base / "utf8_keys_varied.txt", utf8_keys, "utf-8")
write_entries(base / "gbk_keys_varied.txt", gbk_keys, "gbk")
write_entries(base / "utf16_keys_varied.txt", utf16_keys, "utf-16le", add_bom=True)

print("Wrote sources to", base.resolve())

# Generate resource files for MDD testing (flat structure).
resources_base = base / "resources"
resources_base.mkdir(parents=True, exist_ok=True)

# 1x1 PNG
dot_png = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000"
    "000d49444154085b63f8b254f83f0006e902ace4fdb2920000000049454e44ae426082"
)
(resources_base / "Dot.PNG").write_bytes(dot_png)

# Short beep WAV
with wave.open(str(resources_base / "beep.wav"), "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(8000)
    frames = [int(20000 * (i / 80)) for i in range(80)]
    w.writeframes(b"".join(struct.pack("<h", f) for f in frames))

# Text resource
(resources_base / "file.txt").write_text("Flat resource path\n", encoding="utf-8")

# Larger binaries to force multiple MDD record blocks.
(resources_base / "large.bin").write_bytes(b"0123456789ABCDEF\n" * 2048)  # ~34 KB
(resources_base / "huge.bin").write_bytes(b"0123456789ABCDEF\n" * 8000)   # ~136 KB

# Simple stylesheet source (triplets: id, open tag, close tag).
stylesheet = "\n".join([
    "1",
    "<b>",
    "</b>",
    "2",
    "<i>",
    "</i>",
    "3",
    "(",
    ")",
])
(base / "stylesheet.txt").write_text(stylesheet, encoding="utf-8")
(base / "utf16_stylesheet.txt").write_bytes(b"\xff\xfe" + stylesheet.encode("utf-16le"))

print("Wrote resources to", resources_base.resolve())
print("Wrote stylesheet to", (base / "stylesheet.txt").resolve())
