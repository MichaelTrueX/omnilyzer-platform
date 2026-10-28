#!/usr/bin/env python3
"""File: release/analytics_oci_context.py

Purpose: Export an immutable, sanitized Analytics OCI build context from exact
         verified Git blobs. Build tooling MUST consume this archive instead
         of copying a mutable checkout or accepting untracked local files.
Links: release/analytics_task013_build_input.py (M05 PR231),
       release/analytics_source_admission.py, release/products/analytics-source.json,
       Analytics Dockerfile.analytics and .dockerignore, Task013 original OCI builder.
Authority: local build INPUT only; does not publish/sign/promote/authorize a release.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile

from deployment.policy import DeploymentPolicyError
from release.analytics_task013_build_input import build_input

ERROR = "ANALYTICS_OCI_CONTEXT_DENIED"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Section 1: a bounded, conservative exclusion contract. These are intentional
# subset rules, not an attempt to reinterpret or replace Docker's .dockerignore.
# The existing .dockerignore still applies at Docker/BuildKit context import.
DROP_COMPONENTS = frozenset({
    ".git", "node_modules", ".next", ".venv", "venv", "__pycache__",
    ".cache", "coverage", ".nyc_output", "backups", "logs", "tmp", "temp",
    "secrets", "private",
})
DROP_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".kdbx", ".sqlite", ".sqlite3",
    ".db", ".log", ".tar", ".tgz", ".zip", ".bak", ".dump", ".sql.gz",
)
ESSENTIAL = frozenset({
    "Dockerfile.analytics", ".dockerignore", "package.json",
    "package-lock.json", "next.config.js", "prisma/schema.prisma",
    "app/readyz/route.ts", "app/livez/route.ts",
})
MAX_PATH_BYTES = 800
MAX_FILES = 10000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def _git(checkout: Path, *args: str, timeout: int = 20) -> bytes:
    """Read a committed Git object, never using a shell or network command."""
    try:
        value = subprocess.run(
            ["git", "-C", str(checkout), *args],
            capture_output=True, check=True, timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise DeploymentPolicyError(ERROR) from exc
    return value.stdout


def _name(raw: bytes) -> str:
    """Reject noncanonical paths and traversal before writing any tar header."""
    if not raw or len(raw) > MAX_PATH_BYTES or b"\x00" in raw or b"\\" in raw:
        raise DeploymentPolicyError(ERROR)
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DeploymentPolicyError(ERROR) from exc
    parts = name.split("/")
    if (name.startswith("/") or any(not x or x in (".", "..") for x in parts)
            or PurePosixPath(name).as_posix() != name):
        raise DeploymentPolicyError(ERROR)
    return name


def _excluded(name: str) -> bool:
    """Drop tracked secrets, local caches and saved operational artefacts."""
    parts = name.split("/")
    for part in parts:
        low = part.lower()
        if (low in DROP_COMPONENTS or low.startswith(".venv_")
                or low.startswith("venv_") or low == ".env"
                or low.startswith(".env.") or low.endswith(DROP_SUFFIXES)):
            return True
    return False


def snapshot_committed_tree(
    checkout: Path, expected_commit: str, output: Path,
) -> dict[str, object]:
    """Export only eligible regular committed Git blobs to a new deterministic tar.

    This is the materialization part of a source admission. The caller must
    run M01/M05's authoritative build_input() first. Tracked secret-like files
    are excluded even when mistakenly present in source history. Untracked or
    ignored working files are NEVER included. The output is created exclusively
    with permissions 0600 and cannot overwrite existing paths/symlinks.
    """
    if (not isinstance(checkout, Path) or not isinstance(output, Path)
            or not isinstance(expected_commit, str) or not SHA40.fullmatch(expected_commit)):
        raise DeploymentPolicyError(ERROR)
    checkout = checkout.resolve(strict=True)
    if not checkout.is_dir() or output.exists() or output.is_symlink():
        raise DeploymentPolicyError(ERROR)
    head = _git(checkout, "rev-parse", "HEAD").decode("ascii").strip()
    if head != expected_commit:
        raise DeploymentPolicyError(ERROR)

    # Section 2: enumerate exact immutable tree entries, never trust the checkout.
    listing = _git(checkout, "ls-tree", "-r", "-l", "-z", "--full-tree", expected_commit)
    rows: list[tuple[str, str, int, int]] = []
    total = 0
    for record in listing.split(b"\x00"):
        if not record:
            continue
        try:
            meta, rawname = record.split(b"\t", 1)
            mode, objtype, oid, rawsize = meta.split()
            name = _name(rawname)
            if _excluded(name):
                continue
            if (mode not in (b"100644", b"100755") or objtype != b"blob"
                    or SHA40.fullmatch(oid.decode("ascii")) is None):
                raise ValueError("non-regular Git entry")
            size = int(rawsize)
            if size < 0 or size > MAX_FILE_BYTES:
                raise ValueError("oversized source blob")
        except (ValueError, UnicodeDecodeError) as exc:
            raise DeploymentPolicyError(ERROR) from exc
        total += size
        rows.append((name, oid.decode("ascii"), size, 0o755 if mode == b"100755" else 0o644))
        if total > MAX_TOTAL_BYTES or len(rows) > MAX_FILES:
            raise DeploymentPolicyError(ERROR)
    selected = {x[0] for x in rows}
    if not ESSENTIAL.issubset(selected) or len(rows) != len(selected):
        raise DeploymentPolicyError(ERROR)

    # Section 3: write canonical archive from Git content, not source worktree.
    # In CI this archive should be passed directly into ORIGINAL Task013 BuildKit.
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    count = 0
    try:
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as file:
            fd = None
            with tarfile.open(fileobj=file, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for name, oid, size, mode in rows:
                    data = _git(checkout, "cat-file", "blob", oid)
                    if len(data) != size:
                        raise DeploymentPolicyError(ERROR)
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = size, mode, 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    tar.addfile(info, io.BytesIO(data))
                    count += 1
        archive_sha = hashlib.sha256(output.read_bytes()).hexdigest()
        if not SHA256.fullmatch(archive_sha):
            raise DeploymentPolicyError(ERROR)
        return {
            "schema_version": 1,
            "source_commit": expected_commit,
            "context_sha256": archive_sha,
            "file_count": count,
            "context_kind": "verified-git-regular-files-no-working-tree",
            "release_authorized": False,
            "deployment_authorized": False,
        }
    except BaseException:
        if fd is not None:
            os.close(fd)
        if output.exists():
            output.unlink()
        raise


def main() -> int:
    """Validate the M05 build input then materialize its immutable OCI tar."""
    parser = argparse.ArgumentParser(description="Immutable, unsigned Task013 OCI build context")
    parser.add_argument("--analytics-checkout", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        admission = build_input(args.analytics_checkout)
        if (admission.get("release_authorized") is not False
                or admission.get("deployment_authorized") is not False):
            raise DeploymentPolicyError(ERROR)
        result = snapshot_committed_tree(
            args.analytics_checkout, admission["analytics_source_commit"], args.output,
        )
    except (DeploymentPolicyError, OSError, ValueError) as exc:
        print(f"{ERROR}: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
