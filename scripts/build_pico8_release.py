#!/usr/bin/env python3
"""Extract PICO-8 cold data and build one GWRG manifest plus bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "gwrg.json"
UPSTREAM_REPO = "Macs75/pico8_gnw_distro"
CORE_VERSION = 3
RAM_EMU_REGION = 0
COLD_OFFSET = 0x7200
COLD_BYTES = 107512
BASELINE_REF = "v.2.0.0"


def extract_cold(core: bytes) -> bytes:
    if len(core) < 8 or core[:4] != b"CORE":
        raise SystemExit("upstream file is not a CORE container")
    version, metadata_size = struct.unpack_from("<HH", core, 4)
    if version != CORE_VERSION:
        raise SystemExit(f"expected CORE v{CORE_VERSION}, found v{version}")
    payload_offset = 8 + metadata_size
    metadata = core[8:payload_offset]
    if payload_offset > len(core) or len(metadata) < 16:
        raise SystemExit("CORE header is truncated")
    count = struct.unpack_from("<I", metadata, 12)[0]
    if len(metadata) < 16 + count * 12:
        raise SystemExit("CORE segment table is truncated")

    cursor = payload_offset
    ram_emu = None
    for index in range(count):
        region, code_bytes, _bss_bytes = struct.unpack_from("<III", metadata, 16 + index * 12)
        end = cursor + code_bytes
        if end > len(core):
            raise SystemExit(f"CORE segment {index} extends beyond file")
        if region == RAM_EMU_REGION:
            if ram_emu is not None:
                raise SystemExit("CORE has multiple RAM_EMU segments")
            ram_emu = core[cursor:end]
        cursor = end
    if cursor != len(core) or ram_emu is None:
        raise SystemExit("CORE payload is incomplete or has no RAM_EMU segment")
    if COLD_OFFSET + COLD_BYTES > len(ram_emu):
        raise SystemExit("configured cold-data range is outside RAM_EMU")
    return ram_emu[COLD_OFFSET:COLD_OFFSET + COLD_BYTES]


def file_record(path: Path, filename: str, **fields: object) -> dict:
    data = path.read_bytes()
    return {
        "filename": filename,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "url": filename,
        **fields,
    }


def write_bundle(manifest_path: Path, release_dir: Path, output: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    names = sorted(a["url"] for target in manifest["targets"] for a in target["artifacts"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in ["manifest.json", *names]:
            path = release_dir / name
            data = path.read_bytes()
            if name != "manifest.json":
                artifact = next(a for t in manifest["targets"] for a in t["artifacts"]
                                if a["url"] == name)
                if len(data) != artifact["bytes"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
                    raise SystemExit(f"{name}: manifest size/hash does not match payload")
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-bin", type=Path, required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--previous-cold-data", type=Path)
    args = parser.parse_args()

    declared = json.loads(CONFIG.read_text(encoding="utf-8"))
    cold_declaration = declared["artifacts"]["pico8.ro"]
    baseline_key = cold_declaration["lookupKey"]
    core = args.core_bin.read_bytes()
    cold = extract_cold(core)
    crc = zlib.crc32(cold) & 0xFFFFFFFF
    lookup_key = f"cold:pico8:{crc:08x}:{len(cold)}"

    if args.source_ref == BASELINE_REF and lookup_key != baseline_key:
        raise SystemExit(
            f"baseline cold lookup key mismatch: extracted {lookup_key}, configured {baseline_key}"
        )
    if args.previous_cold_data:
        previous = args.previous_cold_data.read_bytes()
        previous_crc = zlib.crc32(previous) & 0xFFFFFFFF
        previous_key = f"cold:pico8:{previous_crc:08x}:{len(previous)}"
        if lookup_key == previous_key:
            raise SystemExit(f"cold lookup key unchanged from previous release: {lookup_key}")
    elif args.source_ref != BASELINE_REF and lookup_key == baseline_key:
        raise SystemExit(
            f"cold lookup key is unchanged from baseline {BASELINE_REF}: {lookup_key}"
        )

    if len(core) < 16:
        raise SystemExit("CORE ABI header is truncated")
    abi_version, abi_min_size = struct.unpack_from("<II", core, 8)
    if abi_version != 2:
        raise SystemExit(f"expected firmware ABI 2, found {abi_version}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    core_path = args.out_dir / "pico8.bin"
    cold_path = args.out_dir / "pico8.ro"
    core_path.write_bytes(core)
    cold_path.write_bytes(cold)

    reloc_base = cold_declaration["relocBase"]
    if isinstance(reloc_base, str):
        reloc_base = int(reloc_base, 0)
    manifest = {
        "schemaVersion": 1,
        "project": "pico8",
        "title": "PICO-8",
        "source": {
            "repo": UPSTREAM_REPO,
            "commit": args.source_commit,
            "ref": args.source_ref,
        },
        "tools": [],
        "targets": [{
            "id": "gnw-retro-go",
            "platform": "game-and-watch",
            "label": "Game & Watch (Retro-Go)",
            "kind": "core",
            "requiresAbi": {"version": abi_version, "minSize": abi_min_size},
            "artifacts": [
                file_record(core_path, "pico8.bin"),
                file_record(cold_path, "pico8.ro", mapped=cold_declaration["mapped"],
                            relocBase=reloc_base, lookupKey=lookup_key),
            ],
            "systems": [{
                "id": "pico8",
                "longName": "PICO-8",
                "shortName": "PICO-8",
                "extensions": [".p8", ".p8.png"],
                "browse": "file",
                "compression": declared["systems"]["pico8"]["compression"],
            }],
        }],
    }
    manifest_path = args.out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    bundle = args.out_dir.parent / f"pico8-{args.source_ref.lower()}-bundle.zip"
    write_bundle(manifest_path, args.out_dir, bundle)
    print(f"cold: {len(cold)} bytes, CRC32 {crc:08x}, key {lookup_key}")
    print(f"manifest: {manifest_path}")
    print(f"bundle: {bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
