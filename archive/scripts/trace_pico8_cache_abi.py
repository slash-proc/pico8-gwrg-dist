#!/usr/bin/env python3
"""Catch PICO-8's cold-sidecar cache/mapping ABI call on the connected device.

Uses gnwmanager's Python OpenOCDBackend directly. It does not reset the device
or write flash. The backend's open() terminates an existing process named
openocd, so do not start this while another OpenOCD session owns the probe.

Run this, then exit and relaunch a PICO-8 game. The script checks the RC12
bank-2 ABI table, catches the firmware cache entry points, records arguments
and caller PC/LR, then removes its breakpoints and resumes the target.
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from gnwmanager.ocdbackend.openocd_backend import OpenOCDBackend


VTOR = 0xE000ED08
ABI = 0x08100400
ABI_CACHE_FLASH_OFFSET = 0x218
ABI_CACHE_FLASH_RELOCATE_OFFSET = 0x21C
ABI_FOPEN_OFFSET = 0x088
ABI_LOOKUP_DATA_OFFSET = 0x34C
ABI_STORE_DATA_OFFSET = 0x350
ABI_STORE_DATA_BEGIN_OFFSET = 0x358
EXPECTED_CACHE_FLASH = 0x0810D849
EXPECTED_CACHE_FLASH_RELOCATE = 0x0810D865
EXPECTED_FOPEN = 0x0812A9BD
EXPECTED_LOOKUP_DATA = 0x0810F6F5
EXPECTED_STORE_DATA = 0x0810FA59
EXPECTED_STORE_DATA_BEGIN = 0x08116115  # gw_abi_store_data_begin trampoline in this ELF

ENDPOINTS = {
    0x0810D848: "odroid_overlay_cache_file_in_flash",
    0x0810D864: "odroid_overlay_cache_file_in_flash_relocate",
    0x0812A9BC: "fopen",
    0x0810F6F4: "lookup_data_in_flash",
    0x0810FA58: "store_data_in_flash",
    0x0810F798: "store_data_begin",
}


def command(backend, text: str) -> str:
    response = backend(text, decode=False).decode("utf-8", errors="replace").strip()
    if response:
        print(f"OpenOCD {text}: {response}", flush=True)
    return response


def read_c_string(backend, address: int, limit: int = 128) -> str | None:
    if address == 0:
        return None
    try:
        raw = backend.read_memory(address, limit)
    except Exception as exc:
        return f"<unreadable at 0x{address:08x}: {exc}>"
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def wait_until_halted(backend, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_state = None
    while time.monotonic() < deadline:
        state = backend("targets", decode=False).decode("utf-8", errors="replace").strip()
        current = "halted" if "halted" in state.lower() else "running"
        if current != last_state:
            print(f"Target {current}; waiting for PICO-8 sidecar load.", flush=True)
            last_state = current
        if current == "halted":
            return
        time.sleep(0.2)
    raise TimeoutError("timed out waiting for a cache/mapping ABI breakpoint")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=900,
                        help="seconds to wait for the PICO-8 sidecar call")
    parser.add_argument("--report", type=Path,
                        default=Path("captures/pico8-device/cache-abi-trace.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    backend = OpenOCDBackend()
    report = {
        "firmware": "v2.0.0-rc12 sd-bank2",
        "elf": "captures/retro-go-rc12-sd-bank2/retro-go-debug.elf",
        "abi_address": f"0x{ABI:08x}",
        "abi_slots": {},
        "hits": [],
    }
    armed = False
    stopped_by_us = False

    print("Connecting through gnwmanager OpenOCDBackend (no CLI).", flush=True)
    try:
        backend.open()
        backend.halt()
        stopped_by_us = True

        vtor = backend.read_uint32(VTOR)
        if vtor != 0x08100000:
            raise RuntimeError(f"expected bank-2 VTOR 0x08100000, got 0x{vtor:08x}")

        cache_ptr = backend.read_uint32(ABI + ABI_CACHE_FLASH_OFFSET)
        relocate_ptr = backend.read_uint32(ABI + ABI_CACHE_FLASH_RELOCATE_OFFSET)
        fopen_ptr = backend.read_uint32(ABI + ABI_FOPEN_OFFSET)
        lookup_ptr = backend.read_uint32(ABI + ABI_LOOKUP_DATA_OFFSET)
        store_ptr = backend.read_uint32(ABI + ABI_STORE_DATA_OFFSET)
        begin_ptr = backend.read_uint32(ABI + ABI_STORE_DATA_BEGIN_OFFSET)
        report["vtor"] = f"0x{vtor:08x}"
        report["abi_slots"] = {
            "odroid_overlay_cache_file_in_flash": {
                "slot": f"0x{ABI + ABI_CACHE_FLASH_OFFSET:08x}",
                "value": f"0x{cache_ptr:08x}",
                "expected": f"0x{EXPECTED_CACHE_FLASH:08x}",
            },
            "odroid_overlay_cache_file_in_flash_relocate": {
                "slot": f"0x{ABI + ABI_CACHE_FLASH_RELOCATE_OFFSET:08x}",
                "value": f"0x{relocate_ptr:08x}",
                "expected": f"0x{EXPECTED_CACHE_FLASH_RELOCATE:08x}",
            },
            "fopen": {"slot": f"0x{ABI + ABI_FOPEN_OFFSET:08x}",
                      "value": f"0x{fopen_ptr:08x}", "expected": f"0x{EXPECTED_FOPEN:08x}"},
            "lookup_data_in_flash": {"slot": f"0x{ABI + ABI_LOOKUP_DATA_OFFSET:08x}",
                                     "value": f"0x{lookup_ptr:08x}", "expected": f"0x{EXPECTED_LOOKUP_DATA:08x}"},
            "store_data_in_flash": {"slot": f"0x{ABI + ABI_STORE_DATA_OFFSET:08x}",
                                    "value": f"0x{store_ptr:08x}", "expected": f"0x{EXPECTED_STORE_DATA:08x}"},
            "store_data_begin": {"slot": f"0x{ABI + ABI_STORE_DATA_BEGIN_OFFSET:08x}",
                                 "value": f"0x{begin_ptr:08x}", "expected": f"0x{EXPECTED_STORE_DATA_BEGIN:08x}"},
        }
        print(f"ABI slot +0x218 -> 0x{cache_ptr:08x} (cache_file_in_flash)", flush=True)
        print(f"ABI slot +0x21c -> 0x{relocate_ptr:08x} (cache_file_in_flash_relocate)", flush=True)
        for name, value in (("fopen", fopen_ptr), ("lookup_data_in_flash", lookup_ptr),
                            ("store_data_in_flash", store_ptr), ("store_data_begin", begin_ptr)):
            print(f"ABI {name} -> 0x{value:08x}", flush=True)
        if (cache_ptr, relocate_ptr, fopen_ptr, lookup_ptr, store_ptr, begin_ptr) != (
            EXPECTED_CACHE_FLASH, EXPECTED_CACHE_FLASH_RELOCATE, EXPECTED_FOPEN,
            EXPECTED_LOOKUP_DATA, EXPECTED_STORE_DATA, EXPECTED_STORE_DATA_BEGIN
        ):
            raise RuntimeError("live ABI table does not match the RC12 bank-2 ELF symbols")

        for address, name in ENDPOINTS.items():
            command(backend, f"rbp 0x{address:08x}")
            command(backend, f"bp 0x{address:08x} 2 hw")
            armed = True
        backend.resume()
        stopped_by_us = False
        print("Breakpoints armed. Exit the PICO-8 game, then launch it again.", flush=True)

        while True:
            wait_until_halted(backend, args.timeout)
            stopped_by_us = True
            pc = backend.read_register("pc") & ~1
            if pc not in ENDPOINTS:
                raise RuntimeError(f"unexpected breakpoint PC 0x{pc:08x}")
            regs = {}
            for reg in ("r0", "r1", "r2", "r3", "r12", "sp", "lr", "pc"):
                try:
                    regs[reg] = backend.read_register(reg)
                except Exception:
                    pass
            first_arg = read_c_string(backend, regs.get("r0", 0))
            text_arg_reg = "r1" if ENDPOINTS[pc] == "store_data_begin" else "r0"
            text_arg = read_c_string(backend, regs.get(text_arg_reg, 0))
            hit = {
                "endpoint": ENDPOINTS[pc],
                "pc": f"0x{pc:08x}",
                "text_argument_register": text_arg_reg,
                "text_argument": text_arg,
                "registers": {k: f"0x{v:08x}" for k, v in regs.items()},
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            }
            relevant = "pico8" in (text_arg or "").lower() or "cold" in (text_arg or "").lower()
            if ENDPOINTS[pc] in ("odroid_overlay_cache_file_in_flash",
                                 "odroid_overlay_cache_file_in_flash_relocate",
                                 "fopen"):
                relevant = relevant or (text_arg or "").replace("\\", "/").lower().endswith(".ro")
            if relevant:
                report["hits"].append(hit)
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(report, indent=2) + "\n")
                print(f"Hit {ENDPOINTS[pc]} {text_arg_reg}={text_arg!r} LR=0x{regs.get('lr', 0):08x}", flush=True)

            if text_arg and text_arg.replace("\\", "/").lower().rsplit("/", 1)[-1] == "pico8.ro":
                report["matched_pico8_ro"] = True
                report["caller_region"] = (
                    "RAM_EMU" if 0x2404B000 <= (regs.get("lr", 0) & ~1) < 0x2406C5F8 else
                    "RAM_UC" if 0x24025800 <= (regs.get("lr", 0) & ~1) < 0x24046F38 else
                    "ITCM" if (regs.get("lr", 0) & ~1) < 0x10000 else
                    "other (inspect LR against firmware ABI trampoline/core ranges)"
                )
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(report, indent=2) + "\n")
                print(f"Saved {args.report}; removing breakpoints and resuming.", flush=True)
                break

            backend.resume()
            stopped_by_us = False

    except Exception as exc:
        print(f"trace failed: {exc}", flush=True)
        raise
    finally:
        if getattr(backend, "_openocd_process", None) is not None:
            if armed:
                for address in ENDPOINTS:
                    try:
                        command(backend, f"rbp 0x{address:08x}")
                    except Exception:
                        pass
            if stopped_by_us:
                try:
                    backend.resume()
                    print("Resumed target after trace cleanup.", flush=True)
                except Exception:
                    pass
            backend.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
