#!/usr/bin/env python3
# File: release/analytics_private_handoff.py
# Purpose: Encrypt private Analytics OCI source evidence before an artifact
#          leaves a release job in the PUBLIC platform GitHub repository.
# Related: release/analytics_handoff_recipient.asc,
#          .github/workflows/platform-release.yml,
#          release/tests/test_analytics_private_handoff.py.
# Security: Public-key-only source job; protected publisher jobs hold the
#          private decryption key. Refuse symlinks, unsafe archive paths,
#          extraction overwrites and unverified decryption. Never print keys.
"""Minimal streaming OpenPGP envelope for original Analytics Task013 jobs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile

RECIPIENT = Path(__file__).with_name("analytics_handoff_recipient.asc")
RECIPIENT_FINGERPRINT = "C831E132F855D5830AEE0FF7F2462BA6518AD974"
KEY_ENVIRONMENT = "ANALYTICS_HANDOFF_PRIVATE_KEY"
MAX_MEMBER_BYTES = 8 * 1024**3
MAX_TOTAL_BYTES = 12 * 1024**3


class EnvelopeDenied(ValueError):
    """A fail-closed private artifact transport error, never key material."""


def _gpg(args: list[str], *, home: str, input_bytes: bytes | None = None) -> bytes:
    """Run GnuPG in an isolated temporary keyring with bounded diagnostics."""
    environment = dict(os.environ, GNUPGHOME=home)
    result = subprocess.run(
        ["gpg", "--batch", "--no-tty", "--quiet", *args],
        input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=environment, timeout=180, check=False,
    )
    if result.returncode != 0:
        raise EnvelopeDenied("ANALYTICS_HANDOFF_GPG_DENIED")
    return result.stdout


def _paths(root: Path):
    """Enumerate only regular files and directories under the trusted handoff."""
    if not root.is_dir() or root.is_symlink():
        raise EnvelopeDenied("ANALYTICS_HANDOFF_SOURCE_DENIED")
    paths = sorted(root.rglob("*"))
    if not paths:
        raise EnvelopeDenied("ANALYTICS_HANDOFF_EMPTY_SOURCE_DENIED")
    for path in paths:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise EnvelopeDenied("ANALYTICS_HANDOFF_UNSAFE_SOURCE_DENIED")
        yield path


def encrypt(source: Path, output: Path, *, public_key: Path = RECIPIENT,
            fingerprint: str = RECIPIENT_FINGERPRINT) -> None:
    """Stream a private directory through GPG without uploading plaintext."""
    source = source.absolute()
    if output.exists() or not public_key.is_file():
        raise EnvelopeDenied("ANALYTICS_HANDOFF_ENCRYPT_INPUT_DENIED")
    # Verify the complete filesystem tree BEFORE starting the encryptor.
    files = list(_paths(source))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="analytics-gpg-public-") as home:
        _gpg(["--import", str(public_key)], home=home)
        keys = _gpg(["--with-colons", "--fingerprint", "--list-keys"], home=home)
        if f"fpr:::::::::{fingerprint}:".encode() not in keys:
            raise EnvelopeDenied("ANALYTICS_HANDOFF_RECIPIENT_PIN_DENIED")
        process = subprocess.Popen(
            ["gpg", "--batch", "--no-tty", "--quiet", "--trust-model", "always",
             "--recipient", fingerprint, "--encrypt", "--output", str(output)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=dict(os.environ, GNUPGHOME=home),
        )
        try:
            assert process.stdin is not None
            with tarfile.open(fileobj=process.stdin, mode="w|", dereference=True) as archive:
                for path in files:
                    archive.add(path, arcname=path.relative_to(source).as_posix(),
                                recursive=False)
            process.stdin.close()
            if process.wait(timeout=300) != 0 or not output.is_file() or output.stat().st_size == 0:
                raise EnvelopeDenied("ANALYTICS_HANDOFF_ENCRYPT_FAILED")
        except (OSError, tarfile.TarError, subprocess.TimeoutExpired, EnvelopeDenied):
            if process.poll() is None:
                process.kill()
            process.wait()
            output.unlink(missing_ok=True)
            raise EnvelopeDenied("ANALYTICS_HANDOFF_ENCRYPT_FAILED") from None


def _extract_verified_stream(stream, destination: Path) -> None:
    """Extract only relative regular tar members with strict per-file bounds."""
    total = 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (member.name.startswith("/") or not name.parts or
                    any(part in (".", "..") for part in name.parts) or
                    member.size < 0 or member.size > MAX_MEMBER_BYTES):
                raise EnvelopeDenied("ANALYTICS_HANDOFF_UNSAFE_MEMBER_DENIED")
            # Exclude symlinks, hardlinks, devices, FIFOs and extensions.
            if not (member.isfile() or member.isdir()):
                raise EnvelopeDenied("ANALYTICS_HANDOFF_UNSAFE_TYPE_DENIED")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise EnvelopeDenied("ANALYTICS_HANDOFF_SIZE_DENIED")
            target = destination.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                src = archive.extractfile(member)
                if src is None:
                    raise EnvelopeDenied("ANALYTICS_HANDOFF_MEMBER_DENIED")
                with src, target.open("xb") as dst:
                    remaining = member.size
                    while remaining:
                        chunk = src.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise EnvelopeDenied("ANALYTICS_HANDOFF_TRUNCATED_DENIED")
                        dst.write(chunk)
                        remaining -= len(chunk)


def decrypt(source: Path, destination: Path, *, private_key: str | None = None) -> None:
    """Read a protected key from memory and refuse unverified ciphertext."""
    key = private_key if private_key is not None else os.environ.get(KEY_ENVIRONMENT)
    if not key or not source.is_file() or destination.exists():
        raise EnvelopeDenied("ANALYTICS_HANDOFF_DECRYPT_INPUT_DENIED")
    with tempfile.TemporaryDirectory(prefix="analytics-gpg-private-") as home:
        _gpg(["--import"], home=home, input_bytes=key.encode("utf-8"))
        process = subprocess.Popen(
            ["gpg", "--batch", "--no-tty", "--quiet", "--decrypt", str(source)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, GNUPGHOME=home),
        )
        try:
            destination.mkdir(mode=0o700, parents=True, exist_ok=False)
            assert process.stdout is not None
            _extract_verified_stream(process.stdout, destination)
            process.stdout.close()
            if process.wait(timeout=300) != 0:
                raise EnvelopeDenied("ANALYTICS_HANDOFF_DECRYPT_AUTH_DENIED")
            # Prevent an unrelated ciphertext from masquerading as a handoff.
            for required in ("candidate/source.tar", "candidate/analytics.oci.tar",
                             "analytics-source-claim.json", "oci-grype.json"):
                if not (destination / required).is_file():
                    raise EnvelopeDenied("ANALYTICS_HANDOFF_INCOMPLETE_DENIED")
        except (OSError, tarfile.TarError, subprocess.TimeoutExpired, EnvelopeDenied):
            if process.poll() is None:
                process.kill()
            if process.stdout is not None:
                process.stdout.close()
            process.wait()
            shutil.rmtree(destination, ignore_errors=True)
            raise EnvelopeDenied("ANALYTICS_HANDOFF_DECRYPT_DENIED") from None


def main() -> int:
    """Expose only two explicit release job operations, without secret logs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("encrypt", "decrypt"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "encrypt":
            encrypt(args.source, args.destination)
            print("ANALYTICS_PRIVATE_HANDOFF_ENCRYPTED")
        else:
            decrypt(args.source, args.destination)
            print("ANALYTICS_PRIVATE_HANDOFF_DECRYPTED")
    except (EnvelopeDenied, OSError):
        raise SystemExit("ANALYTICS_PRIVATE_HANDOFF_DENIED") from None
    return 0


if __name__ == "__main__":
    sys.exit(main())
