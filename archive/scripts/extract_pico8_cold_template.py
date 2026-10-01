#!/usr/bin/env python3
"""Extract PICO-8's raw cold-data template from its CORE v3 container.

The template occupies the final 0x1a3f8 bytes of the RAM_EMU payload in the
captured core. This emits the unpatched template and metadata for use as a
mapped FrogFS artifact. It does not apply address relocation.
"""

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path


RAM_EMU_REGION = 0
COLD_OFFSET = 0x7200
COLD_LENGTH = 0x1A3F8
EXPECTED_CRC32 = 0xB13AEAC5
RELOC_BASE = 0xBEEF0000


def extract_ram_emu(core: bytes) -> tuple[int, bytes]:
    if len(core) < 8 or core[:4] != b"CORE":
        raise ValueError("input is not a CORE container")
    version, header_size = struct.unpack_from("<HH", core, 4)
    if version != 3:
        raise ValueError(f"expected CORE v3; found v{version}")

    payload_offset = 8 + header_size
    if payload_offset > len(core):
        raise ValueError("CORE header extends beyond end of file")
    metadata = core[8:payload_offset]
    if len(metadata) < 16:
        raise ValueError("CORE metadata does not contain its segment table")
    count = struct.unpack_from("<I", metadata, 12)[0]
    if count < 1 or len(metadata) < 16 + count * 12:
        raise ValueError("invalid or truncated CORE segment table")

    cursor = payload_offset
    ram_emu = None
    for i in range(count):
        region, code_size, _bss_size = struct.unpack_from(
            "<III", metadata, 16 + i * 12)
        end = cursor + code_size
        if end > len(core):
            raise ValueError(f"CORE segment {i} extends beyond end of file")
        if region == RAM_EMU_REGION:
            ram_emu = (cursor, core[cursor:end])
        cursor = end

    if cursor != len(core):
        raise ValueError(f"unexpected {len(core) - cursor} trailing container bytes")
    if ram_emu is None:
        raise ValueError("CORE container has no RAM_EMU segment")
    file_offset, payload = ram_emu
    if len(payload) != 0x215F8:
        raise ValueError(f"unexpected RAM_EMU size: 0x{len(payload):x}")
    if COLD_OFFSET + COLD_LENGTH != len(payload):
        raise ValueError("cold template range does not end at RAM_EMU payload boundary")
    return file_offset, payload[COLD_OFFSET:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-bin", type=Path, default=Path("pico8.bin"))
    parser.add_argument("--out", type=Path,
                        default=Path("captures/pico8-extracted/pico8-cold-template.bin"))
    parser.add_argument("--metadata", type=Path,
                        default=Path("captures/pico8-extracted/pico8-cold-template.json"))
    args = parser.parse_args()

    core = args.core_bin.read_bytes()
    file_offset, cold = extract_ram_emu(core)
    crc = zlib.crc32(cold) & 0xFFFFFFFF
    if crc != EXPECTED_CRC32:
        raise SystemExit(f"cold template CRC mismatch: {crc:08x} != {EXPECTED_CRC32:08x}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(cold)
    report = {
        "source": str(args.core_bin),
        "segment": "RAM_EMU",
        "segment_file_offset": f"0x{file_offset:x}",
        "segment_offset": f"0x{COLD_OFFSET:x}",
        "file_offset": f"0x{file_offset + COLD_OFFSET:x}",
        "bytes": len(cold),
        "crc32": f"{crc:08x}",
        "sha256": hashlib.sha256(cold).hexdigest(),
        "cache_key": f"cold:pico8:{crc:08x}:{len(cold)}",
        "reloc_base_observed": f"0x{RELOC_BASE:08x}",
        "reloc_base_status": "observed in device trace; verify for this core build",
        "output": str(args.out),
    }
    args.metadata.write_text(json.dumps(report, indent=2) + "\n")
    print(f"wrote {args.out}: {len(cold)} bytes, crc32={crc:08x}")
    print(f"key: {report['cache_key']}")
    print(f"metadata: {args.metadata}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
