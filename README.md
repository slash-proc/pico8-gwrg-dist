# PICO-8 for Game & Watch Retro-Go

This repository publishes PICO-8 core bundles in the
[GWRG distribution format](https://github.com/slash-proc/gwrg-dist-spec).
Each project tag must match a release tag in
[`Macs75/pico8_gnw_distro`](https://github.com/Macs75/pico8_gnw_distro).

## Release process

Push a tag matching the upstream release tag, such as `v.2.0.0`. GitHub Actions
downloads the upstream release asset matching `pico8_*.zip`, extracts `pico8.bin`
and its cold-data range,
builds a manifest and offline bundle, publishes the release assets, then
rebuilds the Pages `dist/` directory and `versions.json` from published
releases.

The release script uses the validated PICO-8 CORE v3 layout: the 107,512-byte
cold-data range begins at offset `0x7200` in `RAM_EMU`. Update those two
constants in `scripts/build_pico8_release.py` if a new release changes the
layout. `gwrg.json` records the exact v2.0.0 lookup key as the first-release
baseline. Later tags compare against the previous published sidecar. The
generated manifest uses the same format as the working v2.0.0 bundle, including
the exact `lookupKey` field.

The tag workflow selects one upstream release asset matching `pico8_*.zip`
and reads `pico8.bin` from it.
Published files are available under `/dist/<tag>/`; the
`/dist/versions.json` index lists retained releases. The offline bundle is
published alongside the index at `/dist/` root.

## Local packaging

```sh
python3 scripts/build_pico8_release.py \
  --core-bin pico8.bin \
  --source-ref v.2.0.0 --source-commit <upstream-commit> \
  --out-dir dist/v.2.0.0
```

The device captures, investigation notes, and superseded scripts are kept in
[`archive/`](archive/). Local binary captures and bundle archives are ignored
by Git.
