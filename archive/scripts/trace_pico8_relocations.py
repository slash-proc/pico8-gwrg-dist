#!/usr/bin/env python3
"""Catch the PICO-8 core handoff and its first cold-pointer relocations.

Uses gnwmanager's Python OpenOCDBackend directly. The caller must use the
matching Retro-Go v2.0.0-rc12 SD bank 2 firmware.
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from gnwmanager.ocdbackend.openocd_backend import OpenOCDBackend


# RC12 SD bank2 symbols, checked against debug/retro-go-debug.elf.
AFTER_SEGMENT_LOAD = 0x08113E58  # run_dynamic_core, after load_gnw_segments succeeds
WATCHES = {
    "RAM_EMU cold pointer": (0x2404B0BC, 0xBEF008B5),
    "RAM_UC cold base ref 0": (0x24025C38, 0xBEEF0000),
    "RAM_UC cold base ref 1": (0x24025C3C, 0xBEEF0000),
}


def command(backend, text: str) -> str:
    response = backend(text, decode=False).decode("utf-8", errors="replace").strip()
    if response:
        print(f"OpenOCD {text}: {response}", flush=True)
    return response


def read_pc(backend) -> int:
    return backend.read_register("pc")


def wait_until_halted(backend, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    last_state = None
    while time.monotonic() < deadline:
        state = backend("targets", decode=False).decode("utf-8", errors="replace").strip()
        is_halted = "halted" in state.lower()
        current = "halted" if is_halted else "running" if "running" in state.lower() else state
        if current != last_state:
            print(f"Waiting for {label}: target {current or 'state unknown'}", flush=True)
            last_state = current
        if is_halted:
            return
        time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {label}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=900,
                        help="seconds to wait for each breakpoint/watchpoint")
    parser.add_argument("--report", type=Path,
                        default=Path("captures/pico8-device/relocation-watchpoint.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    backend = OpenOCDBackend()
    report = {
        "firmware": "v2.0.0-rc12 sd-bank2",
        "after_segment_load_breakpoint": f"0x{AFTER_SEGMENT_LOAD:08x}",
        "watchpoints": [],
        "events": [],
    }

    print("Connecting through gnwmanager OpenOCDBackend.", flush=True)
    print("This briefly halts the target to install a hardware breakpoint.", flush=True)
    try:
        backend.open()
        backend.halt()
        initial_pc = read_pc(backend)
        print(f"Halted at PC=0x{initial_pc:08x}", flush=True)

        pc = initial_pc & ~1
        at_handoff = pc == AFTER_SEGMENT_LOAD
        in_pico8_uc = 0x24025800 <= pc < (0x24025800 + 137016)
        if at_handoff:
            print("At the post-load boundary; checking original segment values.", flush=True)
        elif in_pico8_uc:
            print("Already halted inside PICO-8 RAM_UC code; watching remaining refs.", flush=True)
        else:
            # Remove a stale breakpoint at this address if this script is rerun.
            command(backend, f"rbp 0x{AFTER_SEGMENT_LOAD:08x}")
            command(backend, f"bp 0x{AFTER_SEGMENT_LOAD:08x} 2 hw")
            backend.resume()
            print("Armed. Exit the current PICO-8 game, then launch it again.", flush=True)
            wait_until_halted(backend, args.timeout, "segment-load boundary")
            pc = read_pc(backend) & ~1
            if pc != AFTER_SEGMENT_LOAD:
                raise RuntimeError("target halted somewhere other than the segment-load breakpoint")
            at_handoff = True
            print(f"Stopped at post-load boundary PC=0x{pc:08x}", flush=True)

        before = []
        pending = []
        for label, (address, expected) in WATCHES.items():
            value = backend.read_uint32(address)
            before.append({
                "label": label,
                "address": f"0x{address:08x}",
                "expected_source": f"0x{expected:08x}",
                "value_at_handoff": f"0x{value:08x}",
            })
            print(f"{label} @0x{address:08x}: 0x{value:08x}", flush=True)
            live_expected = (expected + 0xD1210000) & 0xFFFFFFFF
            if value == expected:
                pending.append((label, address, expected, live_expected))
            elif value == live_expected:
                print("  already relocated", flush=True)
            elif at_handoff:
                raise RuntimeError(
                    f"{label} does not match the captured source value; refusing to arm its watchpoint"
                )

        command(backend, f"rbp 0x{AFTER_SEGMENT_LOAD:08x}")
        if not pending:
            raise RuntimeError("all watched words are already relocated; nothing left to catch")
        for label, address, _expected, _live_expected in pending:
            command(backend, f"rwp 0x{address:08x}")
            command(backend, f"wp 0x{address:08x} 4 w")
            report["watchpoints"].append({"label": label, "address": f"0x{address:08x}"})

        report["values_before_watchpoints"] = before
        backend.resume()
        print("Watching relocation stores for the remaining sentinel words.", flush=True)
        while pending:
            wait_until_halted(backend, args.timeout, "relocation watchpoint")
            pc = read_pc(backend)
            event = {"pc": f"0x{pc:08x}", "registers": {}, "watched_values": []}
            for reg in ("r0", "r1", "r2", "r3", "r12", "lr", "xpsr"):
                try:
                    event["registers"][reg] = f"0x{backend.read_register(reg):08x}"
                except Exception:
                    pass
            changed = []
            for label, address, _expected, live_expected in list(pending):
                value = backend.read_uint32(address)
                item = {"label": label, "address": f"0x{address:08x}",
                        "value_when_halted": f"0x{value:08x}"}
                event["watched_values"].append(item)
                print(f"{label} @0x{address:08x}: 0x{value:08x}", flush=True)
                if value == live_expected:
                    changed.append((label, address))
            event["matched_watchpoints"] = [label for label, _ in changed]
            report["events"].append(event)
            for label, address in changed:
                command(backend, f"rwp 0x{address:08x}")
                pending = [entry for entry in pending if entry[0] != label]
            if pending:
                print("Resuming to catch remaining relocation(s).", flush=True)
                backend.resume()
        report["captured_at_utc"] = datetime.now(timezone.utc).isoformat()

        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Saved {args.report}", flush=True)
        print("Target is left halted at the final watchpoint for inspection.", flush=True)
    except Exception as exc:
        print(f"trace failed: {exc}", flush=True)
        raise
    finally:
        if getattr(backend, "_openocd_process", None) is not None:
            backend.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
