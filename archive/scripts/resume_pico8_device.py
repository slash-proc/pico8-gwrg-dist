#!/usr/bin/env python3
"""Resume the connected target through gnwmanager's Python OpenOCD binding."""

from gnwmanager.ocdbackend.openocd_backend import OpenOCDBackend


backend = OpenOCDBackend()
try:
    backend.open()
    pc = backend.read_register("pc")
    backend.resume()
    print(f"Resumed target from PC=0x{pc:08x}")
finally:
    if getattr(backend, "_openocd_process", None) is not None:
        backend.close()
