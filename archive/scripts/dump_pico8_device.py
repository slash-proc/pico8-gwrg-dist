#!/usr/bin/env python3
"""Read candidate PICO-8 code regions from the connected Game & Watch.

This uses gnwmanager's Python OpenOCDBackend directly. It does not start
gnwmanager on the device, reset it, write flash, or use the gnwmanager CLI.

The defaults are starting points from the supplied device log, not claims
about the current binary's format or sentinel value:

  * cold code: 0x90100000, 107512 bytes (the log's runtime report)
  * ITCM: the 64 KiB window at address zero (a raw window, not an isolated
    blob; trim it after inspecting the dump)

Run while the PICO-8 game is fully loaded. OpenOCDBackend.open() starts an
OpenOCD process and gnwmanager's implementation terminates existing OpenOCD
processes first, so do not run alongside another OpenOCD session.
"""

import argparse
import hashlib
import json
from pathlib import Path

from gnwmanager.ocdbackend.openocd_backend import OpenOCDError, OpenOCDBackend


DEFAULT_COLD_ADDRESS = 0x90100000
DEFAULT_COLD_SIZE = 107512
DEFAULT_ITCM_ADDRESS = 0x00000000
DEFAULT_ITCM_SIZE = 64 * 1024
DEFAULT_RAM_EMU_ADDRESS = 0x2404B000
DEFAULT_RAM_EMU_CODE_SIZE = 136696
DEFAULT_RAM_EMU_BSS_SIZE = 0
DEFAULT_RAM_UC_ADDRESS = 0x24025800
DEFAULT_RAM_UC_CODE_SIZE = 137016
DEFAULT_RAM_UC_BSS_SIZE = 13384
DEFAULT_CONTEXT_BEFORE = 64 * 1024
DEFAULT_CONTEXT_AFTER = 64 * 1024
DEFAULT_CHUNK_SIZE = 16 * 1024


def read_region(backend, address: int, size: int, chunk_size: int) -> bytes:
    """Read a region in bounded chunks through the debug-probe binding."""
    result = bytearray()
    for offset in range(0, size, chunk_size):
        count = min(chunk_size, size - offset)
        chunk = backend.read_memory(address + offset, count)
        if len(chunk) != count:
            raise IOError(
                f"short read at 0x{address + offset:08x}: "
                f"got {len(chunk)} bytes, expected {count}"
            )
        result.extend(chunk)
        print(f"read 0x{address + offset:08x} +{count:#x}")
    return bytes(result)


def save_dump(out_dir: Path, filename: str, address: int, data: bytes) -> dict:
    path = out_dir / filename
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"saved {path} ({len(data)} bytes, sha256={digest})")
    return {
        "file": filename,
        "address": f"0x{address:08x}",
        "size": len(data),
        "sha256": digest,
    }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path,
                        default=Path("captures/pico8-device"),
                        help="directory for raw dumps and metadata")
    parser.add_argument("--cold-address", type=lambda s: int(s, 0),
                        default=DEFAULT_COLD_ADDRESS)
    parser.add_argument("--cold-size", type=lambda s: int(s, 0),
                        default=DEFAULT_COLD_SIZE)
    parser.add_argument("--itcm-address", type=lambda s: int(s, 0),
                        default=DEFAULT_ITCM_ADDRESS)
    parser.add_argument("--itcm-size", type=lambda s: int(s, 0),
                        default=DEFAULT_ITCM_SIZE)
    parser.add_argument("--ram-emu-address", type=lambda s: int(s, 0),
                        default=DEFAULT_RAM_EMU_ADDRESS)
    parser.add_argument("--ram-emu-code-size", type=lambda s: int(s, 0),
                        default=DEFAULT_RAM_EMU_CODE_SIZE)
    parser.add_argument("--ram-emu-bss-size", type=lambda s: int(s, 0),
                        default=DEFAULT_RAM_EMU_BSS_SIZE)
    parser.add_argument("--ram-uc-address", type=lambda s: int(s, 0),
                        default=DEFAULT_RAM_UC_ADDRESS)
    parser.add_argument("--ram-uc-code-size", type=lambda s: int(s, 0),
                        default=DEFAULT_RAM_UC_CODE_SIZE)
    parser.add_argument("--ram-uc-bss-size", type=lambda s: int(s, 0),
                        default=DEFAULT_RAM_UC_BSS_SIZE)
    parser.add_argument("--context-before", type=lambda s: int(s, 0),
                        default=DEFAULT_CONTEXT_BEFORE,
                        help="extra NOR bytes to read before the cold-code hint")
    parser.add_argument("--context-after", type=lambda s: int(s, 0),
                        default=DEFAULT_CONTEXT_AFTER,
                        help="extra NOR bytes to read after the cold-code hint")
    parser.add_argument("--chunk-size", type=lambda s: int(s, 0),
                        default=DEFAULT_CHUNK_SIZE)
    args = parser.parse_args()
    for name in ("cold_size", "itcm_size", "ram_emu_code_size",
                 "ram_uc_code_size", "chunk_size"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    for name in ("context_before", "context_after", "ram_emu_bss_size",
                 "ram_uc_bss_size"):
        if getattr(args, name) < 0:
            parser.error(f"--{name.replace('_', '-')} cannot be negative")
    if args.cold_address < args.context_before:
        parser.error("context-before would underflow the address space")
    return args


def main() -> int:
    args = parse_args()
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    cold_start = args.cold_address
    context_start = cold_start - args.context_before
    context_size = args.context_before + args.cold_size + args.context_after
    backend = OpenOCDBackend()
    records = []

    print("Connecting through gnwmanager's OpenOCDBackend (read-only dump)...")
    try:
        backend.open()
        # Separate reads keep the exact reported cold-code range alongside a
        # wider window that can reveal its boundary and neighbouring contents.
        itcm = read_region(backend, args.itcm_address, args.itcm_size,
                           args.chunk_size)
        records.append(save_dump(out_dir, "itcm-window.bin",
                                 args.itcm_address, itcm))

        # CORE v3 segment destinations from the current firmware's shared
        # linker regions. Read code and BSS separately: code is comparable to
        # the packed payload; BSS is runtime-created data, not part of the bin.
        for stem, address, code_size, bss_size in (
            ("ram-emu", args.ram_emu_address, args.ram_emu_code_size,
             args.ram_emu_bss_size),
            ("ram-uc", args.ram_uc_address, args.ram_uc_code_size,
             args.ram_uc_bss_size),
        ):
            live_code = read_region(backend, address, code_size,
                                    args.chunk_size)
            records.append(save_dump(out_dir, f"{stem}-loaded-code.bin",
                                     address, live_code))
            if bss_size:
                live_bss = read_region(backend, address + code_size, bss_size,
                                       args.chunk_size)
                records.append(save_dump(
                    out_dir, f"{stem}-loaded-bss.bin",
                    address + code_size, live_bss))

        cold = read_region(backend, args.cold_address, args.cold_size,
                           args.chunk_size)
        records.append(save_dump(out_dir, "cold-code-hint.bin",
                                 args.cold_address, cold))

        context = read_region(backend, context_start, context_size,
                              args.chunk_size)
        records.append(save_dump(out_dir, "nor-context.bin",
                                 context_start, context))
    except (OpenOCDError, OSError) as exc:
        raise SystemExit(f"device read failed: {exc}") from exc
    finally:
        if getattr(backend, "_openocd_process", None) is not None:
            backend.close()

    metadata = {
        "method": "gnwmanager OpenOCDBackend.read_memory",
        "device_writes": False,
        "itcm_is_full_window_not_trimmed_blob": True,
        "ram_addresses_from": "game-and-watch-retro-go-sd shared linker regions",
        "ram_payload_sizes_from": "pico8.bin CORE v3 segment table",
        "ram_bss_dumped_separately": True,
        "cold_address_and_size_are_log_hints": True,
        "dumps": records,
    }
    manifest = out_dir / "dump.json"
    manifest.write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"saved {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
