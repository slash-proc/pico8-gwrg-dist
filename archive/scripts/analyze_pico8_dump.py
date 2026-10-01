#!/usr/bin/env python3
"""Compare the device ITCM snapshot with the packed core and infer relocation.

The script treats the local CORE container as a candidate source image, not
as authoritative truth about what is running. It derives the segment lengths
from that file, then looks for a consistent source-to-live address delta in
the ITCM words. If the candidate ITCM matches, the delta and the known live
cold-code base can reveal the linked sentinel base without assuming 0xBEEF0000.
"""

import argparse
import collections
import struct
from pathlib import Path


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_core(path: Path):
    data = path.read_bytes()
    if len(data) < 8 or data[:4] != b"CORE":
        raise ValueError(f"{path} does not start with a CORE container")
    container_version, header_size = struct.unpack_from("<HH", data, 4)
    if container_version != 3:
        raise ValueError(f"expected CORE header version 3, found {container_version}")
    meta_start = 8
    meta_end = meta_start + header_size
    if meta_end > len(data) or header_size < 64:
        raise ValueError(f"invalid CORE header length {header_size}")

    meta = data[meta_start:meta_end]
    count = u32(meta, 12)
    if not 1 <= count <= 4:
        raise ValueError(f"invalid segment count {count}")

    segments = []
    payload_offset = meta_end
    for idx in range(count):
        region, code_size, bss_size = struct.unpack_from("<III", meta, 16 + 12 * idx)
        end = payload_offset + code_size
        if end > len(data):
            raise ValueError(f"segment {idx} exceeds the packed binary")
        segments.append({
            "index": idx,
            "region": region,
            "code_size": code_size,
            "bss_size": bss_size,
            "file_offset": payload_offset,
            "code": data[payload_offset:end],
        })
        payload_offset = end
    return data, segments


def region_name(region: int) -> str:
    return {0: "RAM_EMU", 1: "ITCM", 2: "RAM_UC"}.get(region, f"region-{region}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, default=Path("pico8.bin"))
    parser.add_argument("--dump-dir", type=Path,
                        default=Path("captures/pico8-device"))
    parser.add_argument("--cold-base", type=lambda s: int(s, 0),
                        default=0x90100000,
                        help="live mapped base from the device log")
    parser.add_argument("--cold-size", type=lambda s: int(s, 0),
                        default=107512,
                        help="reported cold-code byte length")
    args = parser.parse_args()

    live_path = args.dump_dir / "itcm-window.bin"
    live = live_path.read_bytes()
    _, segments = parse_core(args.core)
    itcm_candidates = [seg for seg in segments if seg["region"] == 1]
    if len(itcm_candidates) != 1:
        raise SystemExit(f"expected one ITCM segment in {args.core}, "
                         f"found {len(itcm_candidates)}")
    itcm_seg = itcm_candidates[0]
    source = itcm_seg["code"]
    if len(live) < len(source):
        raise SystemExit(f"live ITCM snapshot has {len(live)} bytes; "
                         f"candidate segment needs {len(source)}")
    live_code = live[:len(source)]

    src_out = args.dump_dir / "itcm-core-segment.bin"
    live_out = args.dump_dir / "itcm-loaded-segment.bin"
    src_out.write_bytes(source)
    live_out.write_bytes(live_code)

    print(f"CORE v3 candidate: {args.core} ({args.core.stat().st_size} bytes)")
    for seg in segments:
        print(f"  seg[{seg['index']}] {region_name(seg['region'])}: "
              f"file +0x{seg['file_offset']:x}, code={seg['code_size']}, "
              f"bss={seg['bss_size']}")
    print(f"ITCM candidate length: {len(source)} bytes; "
          f"device prefix equal: {source == live_code}")
    print(f"wrote {src_out} and {live_out}")

    # Patched absolute pointers should differ by the same relocation delta.
    # Masking the Thumb bit is only used for matching references; reported
    # source/live values retain the original bit.
    deltas = collections.defaultdict(list)
    for off in range(0, len(source) - 3, 4):
        before = u32(source, off)
        after = u32(live_code, off)
        if before == after:
            continue
        if (before ^ after) & 1:
            continue
        delta = (after - before) & 0xFFFFFFFF
        deltas[delta].append((off, before, after))

    ranked = sorted(deltas.items(), key=lambda item: len(item[1]), reverse=True)
    if not ranked:
        print("No changed aligned 32-bit words found in the ITCM segment.")
        return 0

    print("Most common source-to-live deltas:")
    for delta, refs in ranked[:8]:
        inferred = (args.cold_base - delta) & 0xFFFFFFFF
        print(f"  delta=0x{delta:08x}, words={len(refs)}, "
              f"inferred linked base=0x{inferred:08x}")
        for off, before, after in refs[:8]:
            print(f"    ITCM+0x{off:04x}: 0x{before:08x} -> 0x{after:08x}")

    # If a candidate relocation base was recovered, count source pointers in
    # the implied range across the packed RAM/ITCM/RAM_UC payloads.
    delta, refs = ranked[0]
    inferred_base = (args.cold_base - delta) & 0xFFFFFFFF
    end = inferred_base + args.cold_size
    if end <= 0x100000000:
        print(f"References inside inferred range "
              f"[0x{inferred_base:08x}, 0x{end:08x}):")
        for seg in segments:
            matches = []
            code = seg["code"]
            for off in range(0, len(code) - 3, 4):
                value = u32(code, off)
                plain = value & ~1
                if inferred_base <= plain < end:
                    matches.append((off, value))
            print(f"  {region_name(seg['region'])}: {len(matches)}")
            for off, value in matches[:12]:
                print(f"    file+0x{seg['file_offset'] + off:x}: 0x{value:08x}")

        cold_path = args.dump_dir / "cold-code-hint.bin"
        if cold_path.exists():
            cold = cold_path.read_bytes()
            cold_matches = []
            cold_live_matches = []
            for off in range(0, len(cold) - 3, 4):
                value = u32(cold, off)
                if inferred_base <= (value & ~1) < end:
                    cold_matches.append((off, value))
                if args.cold_base <= (value & ~1) < args.cold_base + args.cold_size:
                    cold_live_matches.append((off, value))
            print(f"  captured cold blob: {len(cold_matches)} linked-base words, "
                  f"{len(cold_live_matches)} live-base words")
            for off, value in cold_matches[:8]:
                print(f"    cold+0x{off:04x}: 0x{value:08x}")
            for off, value in cold_live_matches[:8]:
                print(f"    cold+0x{off:04x}: 0x{value:08x} (live-base)")
    else:
        print("Inferred range wraps the 32-bit address space; skipping pointer counts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
