#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_offhost_receive.py
Purpose: Independently decrypt and verify an age-encrypted Keycloak backup
    directly from SSH on small-laptop without storing ciphertext or plaintext.
Related: services/identity/ops/keycloak_offhost_backup.py,
    services/identity/tests/test_keycloak_offhost_receive.py, SECURITY.md.

The production ciphertext streams from SSH to age decryption and the
integrity checker. Neither ciphertext nor plaintext is written on this laptop.
Private SSH decryption key stays on the laptop, never on production.
A one-time encrypted copy is not a recurring offsite backup policy.
"""
import argparse
import hashlib
import threading
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile

LAPTOP_HOST = "small-laptop"
LAPTOP_USER = "trust"
REMOTE_USER = "trusthansen"
REMOTE_IP = "46.62.147.181"
REMOTE_PORT = 2222
SOURCE_DIR = ("/home/trusthansen/.cache/omnilyzer-identity-production-preflight")
CIPHERTEXT_NAME = "omnilyzer-keycloak-offhost-20261103.tar.age"
REMOTE_PATH = SOURCE_DIR + "/" + CIPHERTEXT_NAME
IDENTITY = Path("/home/trust/.ssh/id_ed25519_family_mesh")
IDENTITY_PUB = Path("/home/trust/.ssh/id_ed25519_family_mesh.pub")
AGE_BIN = Path("/home/trust/.cache/omnilyzer-identity-offhost/extracted/usr/bin/age")
EXPECTED_PUBLIC_KEY_SHA256 = (
    "d6955c0bbc8a74847aa464196ac516275561ce6a7306674c9a8dd39d5150a492"
)
EXPECTED_FILES = (
    "keycloak.pgcustom",
    "keycloak.env",
    "sumlaude-bff-client.env",
    "omnilyzer-keycloak.service",
    "sha256sum.txt",
)
MAX_ARCHIVE_MEMBER = 4 * 1024 * 1024 * 1024


# Section: Verify all local operator and public-key boundaries without network.
def digest(path):
    """Compute SHA256 of a nonsecret public key or encrypted ciphertext."""
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def preflight():
    """Collect all independent receiver issues before starting an SSH pull."""
    problems = []
    if socket.gethostname().split(".")[0] != LAPTOP_HOST:
        problems.append("not the approved small-laptop")
    if os.geteuid() != pwd.getpwnam(LAPTOP_USER).pw_uid:
        problems.append("must use unprivileged authorized laptop owner")
    for name, path in (("identity", IDENTITY), ("public key", IDENTITY_PUB),
                       ("age", AGE_BIN)):
        try:
            meta = path.lstat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid()
                    or (meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH))):
                problems.append("unexpected " + name + " owner/type/mode")
        except OSError:
            problems.append("missing laptop " + name)
    try:
        if stat.S_IMODE(IDENTITY.lstat().st_mode) != 0o600:
            problems.append("SSH private identity key not mode0600")
        if digest(IDENTITY_PUB) != EXPECTED_PUBLIC_KEY_SHA256:
            problems.append("SSH recipient no longer matches verified laptop")
    except OSError:
        problems.append("SSH key fingerprints unavailable")
    return problems


# Section: Validate the exact, authenticated decrypted tar stream without disk.
def verify_tar_stream(reader):
    """Hash each member, reject extras/traversal, match protected manifest."""
    hashes = {}
    sizes = {}
    manifest = None
    with tarfile.open(fileobj=reader, mode="r|") as archive:
        for index, member in enumerate(archive):
            if index > len(EXPECTED_FILES):
                raise RuntimeError("encrypted archive has unexpected extra members")
            expected = (EXPECTED_FILES + ("manifest.json",))[index]
            if (not member.isfile() or member.name != expected or
                    member.size < 1 or member.size > MAX_ARCHIVE_MEMBER):
                raise RuntimeError("decrypted recovery archive member invalid")
            fileobj = archive.extractfile(member)
            if fileobj is None:
                raise RuntimeError("encrypted recovery member unreadable")
            digest_obj = hashlib.sha256()
            actual_size = 0
            first_bytes = b""
            manifest_content = bytearray()
            while True:
                chunk = fileobj.read(1024 * 1024)
                if not chunk:
                    break
                if actual_size == 0:
                    first_bytes = chunk[:5]
                actual_size += len(chunk)
                if actual_size > MAX_ARCHIVE_MEMBER:
                    raise RuntimeError("decrypted recovery member exceeds size limit")
                digest_obj.update(chunk)
                if member.name == "manifest.json":
                    if actual_size > 65536:
                        raise RuntimeError("encrypted recovery manifest too large")
                    manifest_content.extend(chunk)
            if actual_size != member.size:
                raise RuntimeError("incomplete authenticated recovery member")
            if member.name == "keycloak.pgcustom" and first_bytes != b"PGDMP":
                raise RuntimeError("PostgreSQL custom dump header invalid")
            if member.name == "manifest.json":
                manifest = json.loads(bytes(manifest_content))
            else:
                hashes[member.name] = digest_obj.hexdigest()
                sizes[member.name] = actual_size
    if manifest is None or set(hashes) != set(EXPECTED_FILES):
        raise RuntimeError("encrypted recovery manifest or files missing")
    if manifest.get("format") != "omnilyzer-keycloak-offhost-v1" or (
            manifest.get("recipient_public_key_sha256") !=
            EXPECTED_PUBLIC_KEY_SHA256) or (
            manifest.get("issuer") !=
            "https://login.omnilyzer.ai/realms/omnilyzer"):
        raise RuntimeError("backup source/format/recipient contract mismatch")
    files = manifest.get("recovery_files")
    if not isinstance(files, dict) or set(files) != set(EXPECTED_FILES):
        raise RuntimeError("recovery inventory differs from manifest")
    for filename in EXPECTED_FILES:
        data = files[filename]
        if data != {"sha256": hashes[filename], "bytes": sizes[filename]}:
            raise RuntimeError("authenticated Keycloak content digest mismatch")
    # db sha256 is duplicated inside the root-protected original manifest.
    # Hash and content are already authenticated by age, never print DB rows.
    return hashes["keycloak.pgcustom"]


def verify_age_file(path):
    """Decrypt to a tar reader stream, with no plaintext file on disk."""
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("encrypted backup not a regular file")
    with path.open("rb") as binary:
        if not binary.read(24).startswith(b"age-encryption.org/v1"):
            raise RuntimeError("expected age encryption header absent")
    process = subprocess.Popen(
        [str(AGE_BIN), "-d", "-i", str(IDENTITY), str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        dump_sha256 = verify_tar_stream(process.stdout)
        process.stdout.close()
        exit_status = process.wait(timeout=90)
        if exit_status != 0:
            raise RuntimeError("age authentication/decryption failed")
    except Exception:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        raise
    finally:
        if process.stderr:
            process.stderr.close()
    return dump_sha256


# Section: Independently decrypt real encrypted backup only in process streams.
def verify_remote_stream(expected_digest):
    """Stream production ciphertext through age and verify the exact manifest.

    Keep the SSH transport authentication and age recipient key independently
    pinned. No production data or plaintext is saved or logged on the laptop.
    """
    errors = preflight()
    if errors:
        raise RuntimeError("OFFHOST_VERIFY_HOLD " + "; ".join(errors))
    if not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
        raise RuntimeError("expected ciphertext SHA256 required")
    ssh = subprocess.Popen([
        "/usr/bin/ssh", "-p", str(REMOTE_PORT),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=12",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        REMOTE_USER + "@" + REMOTE_IP,
        "/usr/bin/cat", "--", REMOTE_PATH,
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    age = subprocess.Popen(
        [str(AGE_BIN), "-d", "-i", str(IDENTITY)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    digest_result = hashlib.sha256()
    transfer = {"bytes": 0, "error": None}

    def pipe_ciphertext():
        """Move only encrypted chunks between processes and calculate SHA256."""
        try:
            while True:
                chunk = ssh.stdout.read(1024 * 1024)
                if not chunk:
                    break
                transfer["bytes"] += len(chunk)
                if transfer["bytes"] > MAX_ARCHIVE_MEMBER + 1024 * 1024:
                    raise RuntimeError("encrypted recovery unexpectedly large")
                digest_result.update(chunk)
                age.stdin.write(chunk)
            age.stdin.close()
        except (OSError, RuntimeError, BrokenPipeError) as exc:
            transfer["error"] = type(exc).__name__
            if not age.stdin.closed:
                age.stdin.close()

    worker = threading.Thread(target=pipe_ciphertext, name="m01-age-ciphertext-pipe",
                              daemon=True)
    worker.start()
    try:
        pg_sha256 = verify_tar_stream(age.stdout)
        # Drain bounded tar padding before waiting for process authentication.
        if len(age.stdout.read(1048577)) > 1048576:
            raise RuntimeError("unexpected decrypted tar trailing bytes")
        age.stdout.close()
        worker.join(timeout=90)
        if worker.is_alive():
            raise RuntimeError("ciphertext transfer exceeded bounded deadline")
        if transfer["error"]:
            raise RuntimeError("encrypted SSH transfer failed: " + transfer["error"])
        if age.wait(timeout=20) != 0 or ssh.wait(timeout=20) != 0:
            raise RuntimeError("SSH or age decryption failed")
        if digest_result.hexdigest() != expected_digest:
            raise RuntimeError("encrypted transfer SHA256 differs from root export")
        print("M01_OFFHOST_STREAM_VERIFY_PASS " +
              "real_production_encrypted_stream_verified=true " +
              "age_decrypt_authenticated=true pg_and_manifest_sha256_verified=true " +
              "ciphertext_saved_to_key_laptop=false plaintext_saved=false " +
              "production_not_modified=true keycloak_pg_sha256=" + pg_sha256)
    finally:
        for process in (age, ssh):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for stream in (process.stdout, process.stdin, process.stderr):
                if stream and not stream.closed:
                    stream.close()


def main(argv=None):
    """Read-only preflight or stream authenticated production backup."""
    parser = argparse.ArgumentParser(description="Protected off-host recovery receiver")
    parser.add_argument("action", choices=("preflight", "verify-stream"))
    parser.add_argument("--sha256", default="")
    args = parser.parse_args(argv)
    if args.action == "preflight":
        errors = preflight()
        print("M01_OFFHOST_RECEIVER_" +
              ("HOLD " + "; ".join(errors) if errors else "PREFLIGHT_PASS"))
        return 2 if errors else 0
    verify_remote_stream(args.sha256)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, tarfile.TarError,
            subprocess.SubprocessError) as exc:
        print("M01_OFFHOST_RECEIVE_HOLD " +
              (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__),
              file=sys.stderr)
        sys.exit(2)
