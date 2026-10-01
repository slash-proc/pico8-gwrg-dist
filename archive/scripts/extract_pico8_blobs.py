#!/usr/bin/env python3
"""Split the CORE v3 code segments and pair them with the live device dumps.

The packed `pico8.bin` contains RAM_EMU, ITCM, and RAM_UC segments. The raw
cold-data template is embedded at the end of RAM_EMU and is extracted
separately by `extract_pico8_cold_template.py`. The captured NOR blob here is
the device's already-relocated copy, not the raw template.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path


REGION_NAMES = {0: "ram-emu", 1: "itcm", 2: "ram-uc"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_core(core_path: Path):
    data = core_path.read_bytes()
    if len(data) < 8 or data[:4] != b"CORE":
        raise ValueError(f"{core_path} is not a CORE container")
    version, header_size = struct.unpack_from("<HH", data, 4)
    if version != 3:
        raise ValueError(f"expected CORE v3, found version {version}")

    payload_offset = 8 + header_size
    if payload_offset > len(data):
        raise ValueError(f"CORE header ends beyond end of {core_path}")
    meta = data[8:payload_offset]
    if len(meta) < 16:
        raise ValueError("CORE metadata is too short for its segment table")

    segment_count = struct.unpack_from("<I", meta, 12)[0]
    if not 1 <= segment_count <= 4:
        raise ValueError(f"invalid CORE segment count {segment_count}")
    if len(meta) < 16 + segment_count * 12:
        raise ValueError("CORE metadata does not contain the full segment table")

    segments = []
    cursor = payload_offset
    for index in range(segment_count):
        region, code_size, bss_size = struct.unpack_from(
            "<III", meta, 16 + 12 * index)
        end = cursor + code_size
        if end > len(data):
            raise ValueError(f"segment {index} extends past end of {core_path}")
        name = REGION_NAMES.get(region, f"region-{region}")
        segments.append({
            "index": index,
            "region": region,
            "name": name,
            "offset": cursor,
            "code_size": code_size,
            "bss_size": bss_size,
            "bytes": data[cursor:end],
        })
        cursor = end
    return data, version, header_size, payload_offset, cursor, segments


def save_blob(out_dir: Path, filename: str, data: bytes, **metadata) -> dict:
    path = out_dir / filename
    path.write_bytes(data)
    record = {
        "file": filename,
        "size": len(data),
        "sha256": sha256(data),
        **metadata,
    }
    print(f"{filename}: {len(data)} bytes sha256={record['sha256']}")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-bin", type=Path, default=Path("pico8.bin"))
    parser.add_argument("--device-dumps", type=Path,
                        default=Path("captures/pico8-device"))
    parser.add_argument("--out-dir", type=Path,
                        default=Path("captures/pico8-extracted"))
    args = parser.parse_args()

    data, version, header_size, payload_start, payload_end, segments = \
        extract_core(args.core_bin)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    records = []
    seen = set()
    for seg in segments:
        name = seg["name"]
        seen.add(seg["region"])
        filename = f"pico8-{name}-core.bin"
        records.append(save_blob(
            args.out_dir, filename, seg["bytes"],
            source="CORE container payload",
            segment_index=seg["index"],
            region=seg["region"],
            file_offset=f"0x{seg['offset']:x}",
            bss_size=seg["bss_size"],
        ))
        print(f"  BSS is not in the payload: {seg['bss_size']} bytes")

    missing = {0, 1, 2} - seen
    if missing:
        raise SystemExit(f"container is missing expected region(s): {sorted(missing)}")

    device_blobs = (
        ("itcm-loaded-segment.bin", "pico8-itcm-live.bin",
         "live ITCM memory, trimmed to CORE ITCM code_size"),
        ("cold-code-hint.bin", "pico8-ro-live-nor.bin",
         "live NOR snapshot at the log-reported cold-code address; "
         "not an original/unpatched .ro source"),
    )
    for source_name, output_name, description in device_blobs:
        source_path = args.device_dumps / source_name
        if not source_path.exists():
            print(f"device dump missing, skipped: {source_path}")
            continue
        blob = source_path.read_bytes()
        records.append(save_blob(
            args.out_dir, output_name, blob,
            source=description,
            captured_from=str(source_path),
        ))

    metadata = {
        "core_bin": str(args.core_bin),
        "container_version": version,
        "header_size": header_size,
        "payload_start": f"0x{payload_start:x}",
        "payload_end": f"0x{payload_end:x}",
        "trailing_bytes_after_segments": len(data) - payload_end,
        "ro_note": "The raw cold template is embedded at the tail of RAM_EMU; "
                   "use extract_pico8_cold_template.py. The paired "
                   "pico8-ro-live-nor.bin is the relocated device snapshot.",
        "blobs": records,
    }
    manifest_path = args.out_dir / "blobs.json"
    manifest_path.write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"metadata: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
