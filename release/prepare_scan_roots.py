#!/usr/bin/env python3
"""Safely unpack prebuilt package archives for non-executing SBOM inspection."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def _relative(value: str) -> Path:
    if "\\" in value or "\x00" in value:
        raise ValueError("archive path contains forbidden characters")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("archive path is absolute or traversing")
    return Path(*pure.parts)


def _destination(root: Path, name: str) -> Path:
    relative = _relative(name)
    destination = root / relative
    if root.resolve() not in destination.parent.resolve().parents and destination.parent.resolve() != root.resolve():
        raise ValueError("archive path escaped extraction root")
    return destination


def extract_wheel(archive_path: Path, output: Path) -> None:
    output.mkdir(mode=0o700, parents=True)
    seen: set[Path] = set()
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            destination = _destination(output, member.filename)
            relative = destination.relative_to(output)
            if relative in seen:
                raise ValueError("wheel contains a duplicate path")
            seen.add(relative)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode) or member.is_dir():
                if member.is_dir():
                    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                raise ValueError("wheel contains a symbolic link")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.open(member) as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target)
            os.chmod(destination, 0o600)


def extract_npm(archive_path: Path, output: Path) -> None:
    output.mkdir(mode=0o700, parents=True)
    seen: set[Path] = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            destination = _destination(output, member.name)
            relative = destination.relative_to(output)
            if relative in seen:
                raise ValueError("npm archive contains a duplicate path")
            seen.add(relative)
            if member.isdir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise ValueError("npm archive contains an unsupported filesystem entry")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("npm archive regular file has no bytes")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with source, destination.open("xb") as target:
                shutil.copyfileobj(source, target)
            os.chmod(destination, 0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--npm", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("scan-root output must not already exist")
    args.output.mkdir(mode=0o700, parents=True)
    extract_wheel(args.wheel, args.output / "python")
    extract_npm(args.npm, args.output / "npm")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
