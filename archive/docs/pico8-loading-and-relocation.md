# PICO-8 core loading and relocation notes

This records the current reverse-engineering evidence for running the closed
PICO-8 core when its mapped cold-data sidecar is stored in FrogFS on a
flash-only installation. It distinguishes direct observations from conclusions
that still need a device check.

## Current working answer

The core is not one flat image. `pico8.bin` is a CORE v3 container holding
three loadable segments. The raw 107,512-byte cold template is embedded at the
tail of `RAM_EMU`: segment offset `0x7200`, live RAM address `0x24052200`.
Retro-Go loads it with the rest of that segment. PICO-8 also relocates pointers
inside this template when creating the NOR copy, then separately patches
references to the cold blob in RAM/ITCM/RAM_UC. The log's
`1 RAM, 5 ITCM, 26 RAM_UC` counts only the latter pass.

On the traced SD firmware, PICO-8 computes the key from the raw RAM template,
then calls `lookup_data_in_flash()`. On a miss, it calls `store_data_begin()`,
relocates pointers inside the RAM template to the reserved NOR address, and
streams the patched bytes with `store_data_append()`/`store_data_finish()`.
The key remains `cold:pico8:b13aeac5:107512`: it identifies the raw template,
not the relocated NOR copy. The raw template's CRC32 is `b13aeac5`.

For flash-only, the arrangement is:

1. Keep `pico8.bin` on LittleFS, as an ordinary dynamically loaded core.
2. Extract the raw cold template from the tail of `RAM_EMU` and package it as
   an uncompressed mapped FrogFS artifact.
3. After FrogFS layout fixes the final XIP address, relocate pointers inside
   that artifact from `0xBEEF0000` to its final address.
4. After FrogFS placement, have the web-builder write
   `/data/mappedsidecars.bin` in LittleFS with a record
   `9035759b<TAB>0xXIP_ADDRESS<TAB>107512`. That first field is
   `crc32("cold:pico8:b13aeac5:107512")`, matching Retro-Go's normal cache
   lookup. `b13aeac5` within the full key is the cold template's raw CRC before
   relocation. `lookup_data_in_flash()` hashes the full key and returns the
   mapped pointer; the `store_data_*` slots remain null.
   The sidecar manifest declares the full string as `lookupKey`; that explicit
   declaration opts this artifact into index generation.
5. PICO-8 then performs its normal runtime relocation of references in
   RAM/ITCM/RAM_UC using the returned XIP address.

The web builder already performs mapped placement and relocation. The missing
pieces are generation of `/data/mappedsidecars.bin` after final placement and
a flash-only implementation of the lookup slot that hashes the full ABI key
with the existing Retro-Go CRC routine and reads its address from that LittleFS file.
The core's `RAM_EMU` segment supplies the raw template and thus
the same key before lookup; it does not need to load a separate raw `.ro` file.

## Evidence and provenance

The live capture was taken from a Game & Watch running Retro-Go
`v2.0.0-rc12`, `sd-bank2`, with the device debugger. The release ELF used for
symbol resolution is
[`retro-go-debug.elf`](../captures/retro-go-rc12-sd-bank2/retro-go-debug.elf)
(SHA-256 `fea90f51a20a56d222b055c0829e4de7b41945d3d753258ff988617cebe29e31`).
The device-side captures and trace are under
[`captures/pico8-device/`](../captures/pico8-device/) and the extracted
segments are under [`captures/pico8-extracted/`](../captures/pico8-extracted/).
The capture/analyzer/trace scripts are under [`scripts/`](../scripts/).

The boot/game log is
`retro-go-output-2026-10-01T08-01-54-211Z.log` in the project directory. Its
important line is:

```text
P8: cold code 107512 bytes in flash @0x90100000 (cached), refs patched: 1 RAM, 5 ITCM, 26 RAM_UC
```

“Cold code” is the log's term for the separate mapped sidecar; it should not be
read as proof that all 107,512 bytes are executable instructions. The blob
contains cold code and read-only data. The term “patch count” below refers to
pointer references updated in the loaded segments, not bytes changed in the
sidecar.

## What is in `pico8.bin`

The inspected `pico8.bin` is 321,542 bytes. Its CORE v3 header is 982 bytes;
segment payload begins at file offset `0x3DE`. The payload is fully accounted
for by these segments, with no trailing bytes:

| CORE segment | File offset | Code bytes | BSS bytes | Live base |
|---|---:|---:|---:|---:|
| `RAM_EMU` | `0x3DE` | 136,696 | 0 | `0x2404B000` |
| `ITCM` | `0x219D6` | 46,840 | 0 | `0x00000000` |
| `RAM_UC` | `0x2D0CE` | 137,016 | 13,384 | `0x24025800` |

`RAM_UC` includes a 150,400-byte code+BSS span. Its BSS starts at
`0x24046F38`. `RAM_UC` is the LUT8 bonus/framebuffer region. The **mapped NOR
copy** is not a separate input payload in the CORE container; its raw template
is embedded in `RAM_EMU` as described below.

The cold template occupies `RAM_EMU` segment bytes `[0x7200, 0x215F8)` (file
offset `0x75DE` through the end of that segment), exactly 107,512 bytes. Its
standard CRC32 is `b13aeac5`, matching the key observed on device. Its live
RAM range is `0x24052200..0x2406C5F8`.

The live cold sidecar was observed at XIP address `0x90100000`, length 107,512
bytes (`0x1A3F8`). The cart follows at `0x9011B000`, length 34,413 bytes
(`0x866D`), according to the log. These are addresses for this firmware/image
layout, not constants to bake into all builds: the final FrogFS file offset and
firmware's external-flash base/offset determine the address in a flash-only
image.

## Load sequence observed and source-verified

### 1. Retro-Go selects and prepares the dynamic core

The log shows Retro-Go mounting storage, registering `/cores/pico8.bin`,
initializing the emulator, then starting `celeste.p8`. The PICO-8 cold-data log
appears after game launch and before the later cart-specific stages such as
Lua initialization and cart ROM handling.

In the matching Retro-Go source, `run_dynamic_core()` in
`Core/Src/retro-go/rg_emulators.c` probes the CORE metadata, calculates the
payload offset after the header, and calls `load_gnw_segments()`. That function:

1. Switches the LCD to LUT8 before using a `RAM_UC` segment.
2. Resolves each segment's fixed region and checks that code+BSS fit.
3. Reserves ITCM before copying it (the allocator clears the reserved span).
4. Copies each segment's code from the `.bin` using
   `rg_storage_copy_file_range_to_ram()`.
5. Zeroes each segment's BSS and updates D-cache/I-cache state.
6. Seeds the core `ram_start` and reserves the `RAM_UC` bonus pool.
7. Calls the first segment's entry trampoline.

This firmware loader copies the CORE segments; it does not perform the
PICO-8-specific `.ro` sentinel scan shown in the trace. The relocation writes
occur after the core has control.

### 2. PICO-8 resolves its cold sidecar

The P8 log says the cold blob is in flash at `0x90100000` and marked
`(cached)`. This establishes that by the time the line is emitted, PICO-8 has
selected a flash address for the `.ro` data. The log alone does not establish
whether SD firmware copied it there on that run, found it in a cache, or got
the address through a firmware callback.

On a flash-only firmware build, the current Retro-Go source routes
`/cores/*.ro` and `/cores/*.xip` paths to FrogFS, while `/cores/*.bin` remains
on LittleFS. This extension-based routing is in `Core/Src/syscalls.c` in the
`is_mapped_core_sidecar()` / `is_frogfs_path()` path. The generic
`odroid_overlay_cache_file_in_flash_relocate()` API has two build-specific
behaviors in `Core/Src/porting/odroid_overlay.c`:

* On SD builds it copies the file into the flash cache and invokes the optional
  relocation callback on each chunk before programming.
* On flash-only builds it calls `rg_frogfs_get_file_data()` and returns the
  direct memory-mapped pointer and size. It does not copy the file and ignores
  the callback, because the source is already at its final flash address and
  FrogFS is read-only.

Thus a mapped `.ro` entry in FrogFS needs to be pre-relocated by the image
builder. A normal `fopen()`/`fread()` is not the required XIP handoff; the core
uses the firmware cache/mapping API for the pointer.

The SD trace distinguishes that mapped-file API from the PICO-8 cold-data
cache. The `odroid_overlay_cache_file_in_flash()` hit was for
`/roms/pico8/celeste.p8.png` (the cart), not `pico8.ro`. No
`odroid_overlay_cache_file_in_flash_relocate()` hit was observed for the cold
blob. The new trace confirms no `odroid_overlay_cache_file_in_ram()` call
either: the template was already loaded as the end of `RAM_EMU`. PICO-8
computes the CRC before lookup; on a miss it patches the template buffer and
then writes it in 27 chunks (26 × 4096 bytes plus 1016 bytes). The key and
call registers are in [`cold-path-trace.json`](../captures/pico8-device/cold-path-trace.json).

### 3. PICO-8 relocates references in the loaded segments

The breakpoint at the post-`load_gnw_segments()` return address (`0x08113E58`)
showed source sentinel values in RAM before the core handoff. Hardware
watchpoints then caught the PICO-8 code writing the relocated values. The
observed sentinel base is `0xBEEF0000`, and the target sidecar base is
`0x90100000`, giving a delta of `0xD1210000`.

The proprietary core's Thumb code in `RAM_UC` behaves like a pointer-range
relocator: it checks aligned words against the cold blob's address interval,
masks bit 0 for the range test (to recognize Thumb function pointers), adds the
delta to the original unmasked word, and writes it back. Thus a pointer's
offset into the sidecar and its Thumb bit are retained. The exact list of
memory spans passed to the scanner is not known, but live writes plus the P8
log confirm patch counts in all three loaded regions.

#### Captured relocated references

| Region | Offset | Before | After |
|---|---:|---:|---:|
| ITCM | `+0xB514` | `0xBEEF543D` | `0x9010543D` |
| ITCM | `+0xB564` | `0xBEF09AB1` | `0x90119AB1` |
| ITCM | `+0xB5FC` | `0xBEF09049` | `0x90119049` |
| ITCM | `+0xB64C` | `0xBEEF25AD` | `0x901025AD` |
| ITCM | `+0xB6A4` | `0xBEF09255` | `0x90119255` |
| RAM_EMU | `+0xBC` | `0xBEF008B5` | `0x901108B5` |
| RAM_UC | `+0x438` | `0xBEEF0000` | `0x90100000` |
| RAM_UC | `+0x43C` | `0xBEEF0000` | `0x90100000` |

The trace logged 26 RAM_UC changes total. The table shows only the two base
references that were independently surfaced in the captured source/diff data;
the other 24 individual addresses are in the watchpoint trace artifact. ITCM
diff has exactly the five references above. The RAM_EMU snapshot changed in
many places during execution; only one matched the relocation delta, agreeing
with the P8 log's `1 RAM` count. A raw scan for sentinel-shaped words in RAM_EMU
finds additional candidates, but those are not confirmed runtime patches.

At the first watched relocation, registers included `r0=0xD1210000` (delta),
`r1=0xBEEF0000` (source base), `r2=0x90100000` (target base), and `r12=1`
(patch count for that pass). The watchpoint trace file records the other hits.
The device was resumed after capture.

## What does the patching?

There are two different jobs, which is the source of the earlier ambiguity:

* **PICO-8 patches pointers inside the cold template** on an SD cache miss,
  after computing the raw-template key and reserving a NOR destination. The
  patched blob is what it stores. A cache hit returns that already-patched
  blob.
* **PICO-8 separately patches references to the cold blob** in `RAM_EMU`,
  `ITCM`, and `RAM_UC`, using the address returned by lookup. The log's 32
  reported patches count this second pass, not the cold template's internal
  pointers.
* The mapped-sidecar builder can perform the first job ahead of time for
  flash-only FrogFS placement.

So the “1 RAM” is not an identifier for the sidecar and not a base-only
replacement. The confirmed RAM_EMU word is `0xBEF008B5`, which relocates to
`0x901108B5`: it keeps the `0x10B5` offset from the sidecar base. RAM_EMU,
ITCM, and RAM_UC are all part of the reference-patching pass to the blob.

## FrogFS pre-patching model

The GBA core is the closest local design reference. Its
[`gwrg.json`](../../gba-retro-go-sd/gwrg.json) declares `gba.xip` as `mapped`
with `relocBase: 0xDEC00000`. The GBA linker emits cold text and remaining
rodata as a separate `.xip` sidecar. This is the same general format expected
for a blob linked against a known sentinel base and ultimately dereferenced
from memory-mapped QSPI.

The GWRG distribution spec represents mapped artifacts with `mapped` and
`relocBase` metadata in a version manifest; see
[`spec/03-manifest.md`](../../gwrg-dist-spec/spec/03-manifest.md) and the
core-specific context in [`spec/07-cores.md`](../../gwrg-dist-spec/spec/07-cores.md).
The producer states the sidecar's link base; the installer/build pipeline does
not have to infer it from the binary.

In the checked-out Retro-Go source, FrogFS image generation already has a
post-layout mapped-file patch stage (`scripts/frogfs_pico8_ro.py`, invoked from
`scripts/gen_frogfs_image.py`). It finds the uncompressed sidecar in the
finished FrogFS image, computes the payload's final address as
`extflash_base + extflash_offset + payload_offset`, adds the delta from
`0xBEEF0000` to eligible aligned pointers, and refreshes the image CRC. The
parallel generic manifest/build path uses `mapped` plus `relocBase` for
arbitrary sidecars. This is the key build-time primitive for the proposed
flash-only layout; older PICO-8 scripts should not be treated as authoritative
about which sentinel the current core uses. The live trace independently
supports `0xBEEF0000` for this capture.

The `.ro` must remain uncompressed in FrogFS for direct XiP, and the address
must be calculated against the *final assembled image*, including any
external-flash offset. Patching before FrogFS layout would use the wrong target
address. Likewise, the target is build/image-layout specific; a different
FrogFS offset or firmware layout requires a newly patched image.

## What needs changing for PICO-8

The GBA behavior is already implemented in the web builder. To use it for
PICO-8, extract the cold template from `pico8.bin`'s `RAM_EMU` segment, publish
it as a mapped sidecar with `mapped: true` and
`relocBase: 0xBEEF0000` (numeric in `manifest.json`; the producer-side
`gwrg.json` convention may encode the number as a hex string). Keep `pico8.bin`
as the ordinary core artifact. The mapped flag routes the cold sidecar into FrogFS on a
flash install even though it belongs under `cores/`; the relocation base tells
the post-pack pass how to turn its sentinel pointers into real XIP pointers.

The web builder already carries mapped placement metadata through artifact preparation,
routes mapped files to FrogFS, computes their final XIP address, relocates
eligible pointers, and refreshes the FrogFS CRC. Only artifacts that declare a
`lookupKey` get an index entry. After that layout pass, it should write
`/data/mappedsidecars.bin` in LittleFS with the CRC32 of the full cache key
mapped to the sidecar's final XIP address and size. On SD,
the raw template still feeds the runtime cache; on flash-only, lookup should
return the pre-relocated FrogFS copy.

The remaining work is to extract the raw template from the `RAM_EMU` segment,
have the builder emit its mapped, pre-relocated artifact and LittleFS index,
and implement the read-only flash-only lookup. PICO-8 will continue patching
references in RAM/ITCM/RAM_UC after the lookup returns the mapped address.

## Known unknowns / next useful checks

* The new trace caught 27 append calls but not `store_data_finish()` directly.
* We have not yet implemented or device-tested the flash-only lookup/index.
* Do not assume the sentinel is fixed across every PICO-8 release. The device
  trace establishes `0xBEEF0000` for the captured RC12 run; a new blob should
  be scanned and its relocation counts checked against a live load.

## Local references

Paths below are relative to `~/Nerd/git/`:

* Retro-Go loader: `game-and-watch-retro-go-sd/Core/Src/retro-go/rg_emulators.c`
* Segment file reads: `game-and-watch-retro-go-sd/Core/Src/retro-go/rg_storage.c`
* Flash-only `/cores/*.ro` and `.xip` routing:
  `game-and-watch-retro-go-sd/Core/Src/syscalls.c`
* Mapped-sidecar patch callback/API and flash write path:
  `game-and-watch-retro-go-sd/Core/Inc/gw_flash_alloc.h`,
  `game-and-watch-retro-go-sd/Core/Src/gw_flash_alloc.c`
* FrogFS final-image patching:
  `game-and-watch-retro-go-sd/scripts/frogfs_pico8_ro.py`,
  `game-and-watch-retro-go-sd/scripts/gen_frogfs_image.py`
* GBA sidecar/linker layout:
  `gba-retro-go-sd/gwrg.json`, `gba-retro-go-sd/ld/gba_core.ld`,
  `gba-retro-go-sd/src/main_gba.c`
* Web builder's mapped-artifact design and implementation:
  `gnw-web-builder/docs/MAPPED_ARTIFACTS.md`,
  `gnw-web-builder/packages/fs-builders/src/mappedReloc.ts`,
  `gnw-web-builder/apps/web/src/lib/engine/flashInstall.ts`
* Distribution metadata:
  `gwrg-dist-spec/spec/03-manifest.md`,
  `gwrg-dist-spec/spec/07-cores.md`
