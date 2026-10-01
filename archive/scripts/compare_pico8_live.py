#!/usr/bin/env python3
"""Compare packed PICO-8 CORE segments with their live device snapshots."""

import argparse
import json
import struct
from pathlib import Path

from analyze_pico8_dump import parse_core, region_name


LIVE_FILES = {
    0: "ram-emu-loaded-code.bin",
    1: "itcm-loaded-segment.bin",
    2: "ram-uc-loaded-code.bin",
}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def compare(source: bytes, live: bytes, sentinel_base: int,
            live_base: int, cold_size: int):
    if len(source) != len(live):
        raise ValueError(f"source/live size mismatch: {len(source)} != {len(live)}")
    byte_diffs = [i for i, (a, b) in enumerate(zip(source, live)) if a != b]
    words = []
    relocations = []
    sentinel_end = sentinel_base + cold_size
    delta = (live_base - sentinel_base) & 0xFFFFFFFF
    for off in range(0, len(source) - 3, 4):
        before, after = u32(source, off), u32(live, off)
        if before == after:
            continue
        record = {"offset": f"0x{off:x}", "source": f"0x{before:08x}",
                  "live": f"0x{after:08x}"}
        words.append(record)
        plain = before & ~1
        if sentinel_base <= plain < sentinel_end and \
                after == ((before + delta) & 0xFFFFFFFF):
            relocations.append(record)
    return byte_diffs, words, relocations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, default=Path("pico8.bin"))
    parser.add_argument("--dump-dir", type=Path,
                        default=Path("captures/pico8-device"))
    parser.add_argument("--sentinel-base", type=lambda s: int(s, 0),
                        default=0xBEEF0000)
    parser.add_argument("--live-ro-base", type=lambda s: int(s, 0),
                        default=0x90100000)
    parser.add_argument("--cold-size", type=lambda s: int(s, 0),
                        default=107512)
    parser.add_argument("--report", type=Path,
                        default=Path("captures/pico8-device/segment-diff.json"))
    args = parser.parse_args()

    _, segments = parse_core(args.core)
    report = {
        "core": str(args.core),
        "sentinel_base": f"0x{args.sentinel_base:08x}",
        "live_ro_base": f"0x{args.live_ro_base:08x}",
        "cold_size": args.cold_size,
        "segments": [],
    }
    for segment in segments:
        region = segment["region"]
        filename = LIVE_FILES.get(region)
        if filename is None:
            continue
        live_path = args.dump_dir / filename
        if not live_path.exists() and region == 1:
            # The capture script stores a full ITCM window; use its segment
            # prefix if the analyzer's trimmed comparison file isn't present.
            live_path = args.dump_dir / "itcm-window.bin"
            live = live_path.read_bytes()[:segment["code_size"]]
        else:
            live = live_path.read_bytes()
        byte_diffs, words, relocations = compare(
            segment["code"], live, args.sentinel_base,
            args.live_ro_base, args.cold_size)
        entry = {
            "region": region_name(region),
            "source_file_offset": f"0x{segment['file_offset']:x}",
            "live_file": str(live_path),
            "code_size": segment["code_size"],
            "bss_size_not_compared": segment["bss_size"],
            "different_bytes": len(byte_diffs),
            "different_aligned_words": len(words),
            "cold_pointer_relocations_matching_delta": relocations,
            "different_aligned_words_detail": words,
        }
        report["segments"].append(entry)
        print(f"{entry['region']}: {entry['different_bytes']} differing bytes; "
              f"{len(words)} changed aligned words; "
              f"{len(relocations)} match the cold-pointer relocation")
        for word in words[:20]:
            tag = " relocation" if word in relocations else ""
            print(f"  +{word['offset']}: {word['source']} -> {word['live']}{tag}")
        if len(words) > 20:
            print(f"  ... {len(words) - 20} more changed aligned words; see report")

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
