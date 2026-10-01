# PICO-8 flash-only mapped cold data: implementation plan

## Target behavior

On flash-only installs, PICO-8 loads `pico8.bin` normally from LittleFS. Its
`RAM_EMU` segment contains the 107,512-byte raw cold template. PICO-8 computes
the raw-template key `cold:pico8:b13aeac5:107512` and asks the firmware ABI for
the matching cached data. The flash-only firmware should find a pre-relocated,
uncompressed FrogFS sidecar and return its mapped address and size. PICO-8
then patches its normal references in RAM, ITCM, and RAM_UC. The SD cache write
functions remain unused on flash-only builds.

## Work sequence

1. **Prepare Retro-Go work branch.** Fetch upstream, fast-forward the local
   `external_cores` base if possible, and create a separate implementation
   branch from that updated base. Preserve all existing worktrees and changes.
2. **Implement flash-only lookup.** Keep the flash-only key-to-address index
   at `/data/mappedsidecars.bin` in LittleFS. The web-builder writes it after
   final FrogFS placement. Each record is
   `crc32(full-key-string)<TAB>0xXIP_ADDRESS<TAB>SIZE<LF>`, matching
   `gw_flash_alloc.c`. The full key is
   `cold:pico8:b13aeac5:107512`; `b13aeac5` is the raw template CRC inside
   that key, while `9035759b` is the CRC32 of the full key string and the
   index lookup value. Keep the `store_data_*` slots null and SD behavior
   unchanged. The index is separate from FrogFS; the cold sidecar is mapped in
   FrogFS with the observed relocation base.
3. **Prepare the mapped artifact.** Extract bytes `[0x7200, 0x215F8)` from the
   `RAM_EMU` payload of `pico8.bin` (file offset `0x75DE`, length `0x1A3F8`).
   Confirm the raw CRC32 is `b13aeac5`. Treat `0xBEEF0000` as the currently
   observed relocation base, and validate that assumption against the built
   sidecar and device before relying on it.
4. **Add web-builder bundle support.** Describe the sidecar in the
   GWRG distribution manifest as `mapped: true` with `relocBase: 0xBEEF0000`.
   Include the sidecar in the core's bundle ZIP alongside the ordinary
   `pico8.bin` payload. The `pico8.ro` artifact declares its full
   `lookupKey: "cold:pico8:b13aeac5:107512"`; that declaration is what opts it
   into the mapped-sidecar index. The web-builder hashes that string with the
   Retro-Go cache-key CRC32 rule and writes the resulting address entry to
   `/data/mappedsidecars.bin` after FrogFS placement. Other mapped artifacts
   without `lookupKey` get no index entry. Keep the sidecar uncompressed in the
   installed FrogFS image.
5. **Relocate after final placement.** Use the existing mapped-artifact
   pipeline to apply the sidecar relocation only after FrogFS layout is final,
   so internal pointers target the artifact's actual XIP address. Refresh
   affected FrogFS integrity metadata after patching. Do not hard-code a
   device address such as `0x90100000`.
6. **Verify the artifact and lookup contract.** Check extraction length and
   CRC, manifest and ZIP contents, final FrogFS address, relocated pointers,
   index key-hash/address, and that lookup returns the same mapped range. Confirm the
   raw key is calculated before lookup and that the returned artifact has the
   expected patched contents.
7. **Verify end-to-end on flash-only hardware.** Install using the web-builder,
   launch PICO-8, and check logs for a successful mapped cold-data lookup with
   no SD cache writes. Confirm gameplay and that the returned XIP range is the
   sidecar in FrogFS.
8. **Review and submit.** Keep Retro-Go and web-builder changes reviewable,
   document the tested install, and open a Retro-Go PR only after the complete
   web-builder-to-device path succeeds.

## Evidence and open checks

The current reverse-engineering notes and trace evidence are in
[`pico8-loading-and-relocation.md`](pico8-loading-and-relocation.md). The raw
template is embedded at the end of `RAM_EMU`; it is not a separate input
`.ro` file. The key CRC is over that raw template, before the core relocates
its internal pointers. The cached NOR copy contains those pointers relocated
to its own final XIP address. Confirm the sidecar sentinel, index representation,
and bundle ZIP conventions from the current spec and builder before coding
against them.
