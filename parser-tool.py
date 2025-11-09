import os
import re
import gzip
import binascii
from pathlib import Path
import string

FIELD_NAME = "serializedProgramCompressedBytes"

HEX_PATTERN = re.compile(
    b"serializedProgramCompressedBytes:\\s*([0-9A-Fa-f\\s\\r\\n\\.]+)",
    flags=re.MULTILINE
)

def clean_hex_string(s: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", s)

def safe_unhexlify(hexstr: str) -> bytes:
    if len(hexstr) == 0:
        return b""
    if len(hexstr) % 2 == 1:
        print("    [!] Odd-length hex detected; dropping last nibble to make even.")
        hexstr = hexstr[:-1]
    return binascii.unhexlify(hexstr)

def filter_printable(b: bytes) -> str:
    printable = set(bytes(string.printable, "ascii"))
    return "".join(chr(c) if c in printable else "" for c in b)

def process_asset_file(path: Path, output_dir: Path):
    with path.open("rb") as fh:
        content = fh.read()

    matches = HEX_PATTERN.findall(content)
    if not matches:
        print(f"No '{FIELD_NAME}' found in: {path}")
        return

    for i, match in enumerate(matches):
        print(f"Found candidate in {path.name} (match #{i}) -- cleaning...")
        hex_str = match.decode("ascii", errors="ignore")
        hex_data = clean_hex_string(hex_str)
        print(f"  cleaned hex length: {len(hex_data)} characters")

        try:
            compressed_bytes = safe_unhexlify(hex_data)
        except Exception as e:
            print(f"  [!] Failed to unhexlify: {e}")
            continue

        compressed_path = output_dir / f"{path.stem}_{i}.compressed.bin"
        compressed_path.write_bytes(compressed_bytes)
        print(f"  wrote compressed bytes -> {compressed_path.name}")

        try:
            decompressed_bytes = gzip.decompress(compressed_bytes)
        except Exception as e:
            print(f"  [!] gzip decompression failed: {e}")
            decompressed_bytes = None

        if decompressed_bytes:
            out_bin = output_dir / f"{path.stem}_{i}.bin"
            out_bin.write_bytes(decompressed_bytes)

            filtered_text = filter_printable(decompressed_bytes)
            out_txt = output_dir / f"{path.stem}_{i}.txt"
            out_txt.write_text(filtered_text, encoding="utf-8")
            print(f"  wrote filtered text -> {out_txt.name}")

def main():
    input_dir = input("Enter the input (MonoBehaviour) directory path: ").strip('"').strip()
    output_dir = input("Enter the output (Extracted) directory path: ").strip('"').strip()

    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.exists():
        print(f"[!] Input directory does not exist: {input_path}")
        return

    os.makedirs(output_path, exist_ok=True)

    print("Scanning for .asset files...")
    for root, _, files in os.walk(input_path):
        for fname in files:
            if not fname.endswith(".asset"):
                continue
            path = Path(root) / fname
            print(f"\nProcessing {path}...")
            try:
                process_asset_file(path, output_path)
            except Exception as e:
                print(f"  [!] Error processing {path}: {e}")

    print("\nDone. Check the output folder:", output_path.resolve())

if __name__ == "__main__":
    main()
