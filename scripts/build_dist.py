#!/usr/bin/env python3
"""Mirror recent published PICO-8 releases into the GWRG Pages dist tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def gh_json(*args: str):
    return json.loads(subprocess.check_output(["gh", *args], text=True))


def download_asset(repo: str, tag: str, asset: str, directory: Path) -> Path:
    if Path(asset).name != asset or asset.startswith("."):
        raise SystemExit(f"refusing unsafe release asset name: {asset!r}")
    subprocess.run([
        "gh", "release", "download", tag, "--repo", repo,
        "--pattern", asset, "--dir", str(directory),
    ], check=True)
    path = directory / asset
    if not path.is_file():
        raise SystemExit(f"release {tag} did not provide {asset}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--retain", type=int, default=5)
    parser.add_argument("--require-tag")
    args = parser.parse_args()
    if args.retain < 1:
        raise SystemExit("--retain must be at least 1")

    releases = gh_json("release", "list", "--repo", args.repo, "--limit", "100",
                       "--json", "tagName,publishedAt,isPrerelease,isDraft")
    releases = [r for r in releases if not r["isDraft"] and r.get("publishedAt")]
    releases.sort(key=lambda r: r["publishedAt"], reverse=True)
    if args.require_tag and args.require_tag not in {r["tagName"] for r in releases}:
        raise SystemExit(f"published release {args.require_tag} is missing from {args.repo}")
    releases = releases[:args.retain]

    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True, exist_ok=True)
    versions = []
    with tempfile.TemporaryDirectory(prefix="pico8-dist-") as temp_name:
        temp = Path(temp_name)
        for release in releases:
            tag = release["tagName"]
            if Path(tag).name != tag or tag in (".", ".."):
                raise SystemExit(f"refusing unsafe release tag: {tag!r}")
            staging = temp / tag
            staging.mkdir()
            manifest_path = download_asset(args.repo, tag, "manifest.json", staging)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("project") != "pico8" or manifest.get("source", {}).get("ref") != tag:
                raise SystemExit(f"manifest identity does not match release {tag}")

            target = manifest["targets"][0]
            bundle_name = f"pico8-{tag.lower()}-bundle.zip"
            filenames = {"manifest.json", bundle_name}
            sizes: dict[str, tuple[int, str]] = {}
            for artifact in target["artifacts"]:
                filename = artifact["url"]
                if Path(filename).name != filename or filename.startswith("."):
                    raise SystemExit(f"{tag}: unsafe artifact url {filename!r}")
                filenames.add(filename)
                sizes[filename] = (artifact["bytes"], artifact["sha256"])

            for filename in sorted(filenames - {"manifest.json"}):
                src = download_asset(args.repo, tag, filename, staging)
                if filename in sizes:
                    expected_bytes, expected_hash = sizes[filename]
                    payload = src.read_bytes()
                    if len(payload) != expected_bytes or hashlib.sha256(payload).hexdigest() != expected_hash:
                        raise SystemExit(f"{tag}: integrity check failed for {filename}")

            out_version = args.out / tag
            out_version.mkdir(parents=True, exist_ok=True)
            for filename in filenames:
                shutil.copy2(staging / filename, out_version / filename)
            shutil.copy2(staging / bundle_name, args.out / bundle_name)

            versions.append({
                "tag": tag,
                "manifest": f"{tag}/manifest.json",
                "publishedAt": release["publishedAt"],
                "prerelease": release["isPrerelease"],
                "kind": target["kind"],
                "requiresAbi": target["requiresAbi"],
                "needsUserFiles": False,
                "bundle": bundle_name,
            })

    index = {
        "schemaVersion": 1,
        "project": "pico8",
        "title": "PICO-8",
        "repo": args.repo,
        "releasesUrl": f"https://github.com/{args.repo}/releases",
        "retained": args.retain,
        "versions": versions,
    }
    (args.out / "versions.json").write_text(json.dumps(index, indent=2) + "\n",
                                             encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
