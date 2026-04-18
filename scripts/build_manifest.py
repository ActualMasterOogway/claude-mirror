"""
Build a Claude Code manifest.json for patched binaries.

Reads a directory of patched binaries named `{platform}-{binary}` (e.g.
`linux-x64-claude`, `win32-x64-claude.exe`) and emits a manifest in the
shape Claude Code's updater expects:

    {"platforms": {"<platform>": {"checksum": "<sha256>"}}}

Usage:
    python build_manifest.py <patched_dir> [--out <file>]
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PLATFORMS = ("linux-x64", "linux-x64-musl", "darwin-x64", "win32-x64")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def platform_from_name(name: str) -> str | None:
    for p in sorted(PLATFORMS, key=len, reverse=True):
        if name.startswith(p + "-"):
            return p
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    platforms: dict[str, dict[str, str]] = {}
    for entry in sorted(args.dir.iterdir()):
        if not entry.is_file():
            continue
        plat = platform_from_name(entry.name)
        if plat is None:
            continue
        platforms[plat] = {"checksum": sha256(entry)}

    missing = [p for p in PLATFORMS if p not in platforms]
    if missing:
        print(f"[build_manifest] WARNING: missing platforms: {missing}", file=sys.stderr)

    manifest = {"platforms": platforms}
    text = json.dumps(manifest, indent=2) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
