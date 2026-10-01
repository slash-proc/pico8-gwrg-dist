#!/usr/bin/env python3
"""Build an offline GWRG bundle for the flash-only PICO-8 sidecar experiment.

The source commit is required so the bundle does not claim false provenance.
The cold sidecar is the extracted raw template; the GWRG mapped-artifact step
applies relocBase after it chooses the final FrogFS address.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

from make_bundle import build as build_bundle


ROOT = Path(__file__).resolve().parents[1]
DECLARATIONS = ROOT / "gwrg.json"
EXPECTED_CRC32 = 0xB13AEAC5
DEFAULT_REPO = "Macs75/pico8_gnw_distro"
DEFAULT_REF = "v.2.0.0"


def file_record(path: Path, filename: str, *, mapped: bool = False,
                reloc_base: int | None = None,
                lookup_key: str | None = None) -> tuple[dict, bytes]:
    data = path.read_bytes()
    record = {
        "filename": filename,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "url": filename,
    }
    if mapped:
        record["mapped"] = True
    if reloc_base is not None:
        record["relocBase"] = reloc_base
    if lookup_key is not None:
        record["lookupKey"] = lookup_key
    return record, data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-bin", type=Path, default=ROOT / "pico8.bin")
    parser.add_argument("--cold-data", type=Path,
                        default=ROOT / "captures/pico8-extracted/pico8-cold-template.bin")
    parser.add_argument("--out", type=Path,
                        default=ROOT / "dist/pico8-v.2.0.0-bundle.zip",
                        help="bundle ZIP path; manifest and payloads are staged beside it")
    parser.add_argument("--source-repo", default=DEFAULT_REPO)
    parser.add_argument("--source-ref", default=DEFAULT_REF)
    parser.add_argument("--source-commit", required=True,
                        help="exact commit that supplied pico8.bin")
    args = parser.parse_args()

    core = args.core_bin.read_bytes()
    if len(core) < 8 or core[:4] != b"CORE":
        raise SystemExit("pico8.bin is not a CORE container")
    version, header_size = struct.unpack_from("<HH", core, 4)
    if version != 3 or header_size < 16 or 8 + header_size > len(core):
        raise SystemExit("unexpected/truncated CORE container header")
    abi_version, abi_min_size = struct.unpack_from("<II", core, 8)
    if abi_version != 2:
        raise SystemExit(f"expected firmware ABI 2; pico8.bin requires {abi_version}")

    cold = args.cold_data.read_bytes()
    if len(cold) != 107512 or zlib.crc32(cold) & 0xFFFFFFFF != EXPECTED_CRC32:
        raise SystemExit("cold template size/CRC does not match the traced cache key")

    declared = json.loads(DECLARATIONS.read_text(encoding="utf-8"))
    declared_artifacts = declared.get("artifacts", {})
    declared_systems = declared.get("systems", {})

    artifacts = []
    payloads = []
    for path, name in (
        (args.core_bin, "pico8.bin"),
        (args.cold_data, "pico8.ro"),
    ):
        declaration = declared_artifacts.get(name, {})
        reloc_base = declaration.get("relocBase")
        if isinstance(reloc_base, str):
            reloc_base = int(reloc_base, 0)
        record, data = file_record(
            path,
            name,
            mapped=declaration.get("mapped", False),
            reloc_base=reloc_base,
            lookup_key=declaration.get("lookupKey"),
        )
        artifacts.append(record)
        payloads.append((name, data))

    manifest = {
        "schemaVersion": 1,
        "project": "pico8",
        "title": "PICO-8",
        "source": {
            "repo": args.source_repo,
            "commit": args.source_commit,
            "ref": args.source_ref,
        },
        "tools": [],
        "targets": [{
            "id": "gnw-retro-go",
            "platform": "game-and-watch",
            "label": "Game & Watch (Retro-Go)",
            "kind": "core",
            "requiresAbi": {"version": abi_version, "minSize": abi_min_size},
            "artifacts": artifacts,
            "systems": [{
                "id": "pico8",
                "longName": "PICO-8",
                "shortName": "PICO-8",
                "extensions": [".p8", ".p8.png"],
                "browse": "file",
                "compression": declared_systems["pico8"]["compression"],
            }],
        }],
    }

    stage = args.out.parent / args.out.stem
    stage.mkdir(parents=True, exist_ok=True)
    for name, data in payloads:
        (stage / name).write_bytes(data)
    manifest_path = stage / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    build_bundle(manifest_path=manifest_path, src_dir=stage, out=args.out)

    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    print(f"source: {args.source_repo}@{args.source_ref} ({args.source_commit})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
