#!/usr/bin/env python3
"""Trace PICO-8 cold sidecar loading through gnwmanager's Python debugger API.

This uses OpenOCDBackend directly (no CLI), does not reset or write flash, and
leaves the target running after the breakpoints are armed.  It records the
RAM-side sidecar copy, CRC/key lookup, cache miss/store path, and the buffer
after PICO-8's cold-blob relocation loop.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from gnwmanager.ocdbackend.openocd_backend import OpenOCDBackend


VTOR = 0xE000ED08
EXPECTED_VTOR = 0x08100000
ABI = 0x08100400

# These are hardware breakpoints so the PICO-8 RAM code can be watched even
# though its RAM_UC image is copied in after the debugger is armed.
POINTS = {
    0x0810D878: "odroid_overlay_cache_file_in_ram",
    0x24025A08: "pico8_crc_key_start",
    0x0810F6F4: "lookup_data_in_flash",
    0x0810F798: "store_data_begin",
    0x24025A9A: "pico8_cold_blob_after_relocation",
    0x24026500: "pico8_store_data_append_bridge",
}

REPORT = Path("captures/pico8-device/cold-path-trace.json")


def read_c_string(backend, address, limit=160):
    if not address:
        return None
    try:
        return backend.read_memory(address, limit).split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        )
    except Exception as exc:
        return f"<unreadable: {exc}>"


def target_state(backend):
    return backend("targets", decode=False).decode("utf-8", errors="replace")


def command(backend, text):
    return backend(text, decode=False).decode("utf-8", errors="replace").strip()


def main():
    backend = OpenOCDBackend()
    armed = []
    stopped_by_us = False
    report = {
        "firmware": "v2.0.0-rc12 sd-bank2",
        "elf": "captures/retro-go-rc12-sd-bank2/retro-go-debug.elf",
        "points": {f"0x{a:08x}": n for a, n in POINTS.items()},
        "hits": [],
    }

    print("Connecting through gnwmanager OpenOCDBackend Python bindings.", flush=True)
    backend.open()
    try:
        backend.halt()
        vtor = backend.read_uint32(VTOR)
        if vtor != EXPECTED_VTOR:
            raise RuntimeError(f"unexpected live VTOR 0x{vtor:08x}")
        report["vtor"] = f"0x{vtor:08x}"
        report["initial_pc"] = f"0x{backend.read_register('pc'):08x}"

        # Confirm this is the expected RC12 bank-2 ABI before planting PCs.
        for offset, expected in ((0x218, 0x0810D849), (0x21C, 0x0810D865),
                                 (0x34C, 0x0810F6F5), (0x358, 0x08116115)):
            actual = backend.read_uint32(ABI + offset)
            if actual != expected:
                raise RuntimeError(
                    f"ABI slot +0x{offset:x}: expected 0x{expected:08x}, got 0x{actual:08x}"
                )

        for address in POINTS:
            command(backend, f"rbp 0x{address:08x}")
            response = command(backend, f"bp 0x{address:08x} 2 hw")
            if "breakpoint set" not in response.lower():
                raise RuntimeError(f"failed to arm 0x{address:08x}: {response}")
            armed.append(address)

        print("Trace armed; target will resume. Relaunch PICO-8 now.", flush=True)
        backend.resume()
        stopped_by_us = False

        while True:
            state = target_state(backend).lower()
            if "halted" not in state:
                time.sleep(0.1)
                continue

            stopped_by_us = True
            pc = backend.read_register("pc") & ~1
            if pc not in POINTS:
                print(f"Unexpected halt at 0x{pc:08x}; resuming.", flush=True)
                backend.resume()
                stopped_by_us = False
                continue

            regs = {}
            for name in ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                         "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"):
                try:
                    regs[name] = backend.read_register(name)
                except Exception:
                    pass

            item = {
                "endpoint": POINTS[pc],
                "pc": f"0x{pc:08x}",
                "registers": {k: f"0x{v:08x}" for k, v in regs.items()},
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            }
            if pc == 0x0810D878:
                item["path"] = read_c_string(backend, regs.get("r0", 0))
                item["dest"] = f"0x{regs.get('r1', 0):08x}"
            elif pc == 0x0810F6F4:
                item["key"] = read_c_string(backend, regs.get("r0", 0))
                item["size_out_ptr"] = f"0x{regs.get('r1', 0):08x}"
            elif pc == 0x0810F798:
                item["key"] = read_c_string(backend, regs.get("r1", 0))
                item["size"] = regs.get("r2", 0)
            elif pc == 0x24025A08:
                item["cold_buffer"] = f"0x{regs.get('r7', 0):08x}"
                item["cold_size"] = regs.get("r6", 0)
            elif pc == 0x24025A9A:
                # At this PC the relocation scan has completed; r7 still holds
                # the source base. The next instruction changes it to 4KB.
                buf = regs.get("r7", 0)
                item["cold_buffer"] = f"0x{buf:08x}"
                item["cold_size"] = regs.get("r6", 0)
                size = min(regs.get("r6", 0), 0x1A3F8)
                if buf and size:
                    item["post_relocation_prefix_hex"] = backend.read_memory(
                        buf, min(size, 64)
                    ).hex()
            elif pc == 0x24026500:
                item["append_stream"] = f"0x{regs.get('r0', 0):08x}"
                item["append_buffer"] = f"0x{regs.get('r1', 0):08x}"
                item["append_length"] = regs.get("r2", 0)

            report["hits"].append(item)
            REPORT.parent.mkdir(parents=True, exist_ok=True)
            REPORT.write_text(json.dumps(report, indent=2) + "\n")
            print(f"Hit {item['endpoint']}; saved {REPORT}", flush=True)

            backend.resume()
            stopped_by_us = False
    finally:
        if getattr(backend, "_openocd_process", None) is not None:
            if stopped_by_us:
                try:
                    backend.resume()
                except Exception:
                    pass
            for address in armed:
                try:
                    command(backend, f"rbp 0x{address:08x}")
                except Exception:
                    pass
            backend.close()


if __name__ == "__main__":
    main()
