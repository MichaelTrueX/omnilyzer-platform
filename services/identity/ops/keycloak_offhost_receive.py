#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_offhost_receive.py
Purpose: Pull and independently verify an age-encrypted production Keycloak
    recovery snapshot on the already authorized small-laptop.
Related: services/identity/ops/keycloak_offhost_backup.py,
    services/identity/tests/test_keycloak_offhost_receive.py, SECURITY.md.

The production backup is downloaded only as ciphertext over an existing
host-key-verified SSH connection. It is decrypted directly to a streaming
in-memory integrity checker, with NO plaintext file written on the laptop.
Private SSH decryption key stays on the laptop, never on production.
A one-time encrypted copy is not a recurring offsite backup policy.
"""
import argparse
import hashlib
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
DEST_DIR = Path("/home/trust/.local/share/omnilyzer/identity-backups")
DEST_FILE = DEST_DIR / CIPHERTEXT_NAME
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
    if DEST_FILE.exists() or DEST_FILE.is_symlink():
        problems.append("encrypted backup already exists; no overwrite")
    if DEST_DIR.exists():
        try:
            state = DEST_DIR.lstat()
            if (not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid()
                    or stat.S_IMODE(state.st_mode) != 0o700):
                problems.append("laptop encrypted backup directory not private0700")
        except OSError:
            problems.append("destination directory cannot be inspected")
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


# Section: Pull only ciphertext over the preexisting SSH transport.
def pull_verify(expected_digest):
    """One-time trusted-host SSH pull then authenticated streaming validation."""
    errors = preflight()
    if errors:
        raise RuntimeError("OFFHOST_RECEIVE_HOLD " + "; ".join(errors))
    if not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
        raise RuntimeError("expected ciphertext SHA256 must be supplied")
    DEST_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    DEST_DIR.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".keycloak-offhost-", dir=DEST_DIR)
    os.close(fd)
    try:
        scp = subprocess.run([
            "/usr/bin/scp", "-q", "-P", str(REMOTE_PORT),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=12",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            REMOTE_USER + "@" + REMOTE_IP + ":" + REMOTE_PATH, temporary,
        ], check=False, capture_output=True, timeout=180)
        if scp.returncode:
            raise RuntimeError("SSH ciphertext-only download did not complete")
        if digest(Path(temporary)) != expected_digest:
            raise RuntimeError("encrypted transfer SHA256 mismatch")
        pg_sha256 = verify_age_file(Path(temporary))
        os.chmod(temporary, 0o600)
        os.replace(temporary, DEST_FILE)
        temporary = None
        print("M01_OFFHOST_RECEIVE_VERIFY_PASS " +
              "ssh_host_verified=true ciphertext_sha256_verified=true " +
              "age_decrypt_authenticated=true manifest_and_pg_sha256_verified=true " +
              "plaintext_saved_to_laptop=false existing_files_untouched=true " +
              "production_not_modified=true encrypted_copy_present=true " +
              "keycloak_pg_sha256=" + pg_sha256)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    """Read-only preflight or pull+verify ciphertext from production."""
    parser = argparse.ArgumentParser(description="Protected off-host recovery receiver")
    parser.add_argument("action", choices=("preflight", "pull-verify"))
    parser.add_argument("--sha256", default="")
    args = parser.parse_args(argv)
    if args.action == "preflight":
        errors = preflight()
        print("M01_OFFHOST_RECEIVER_" +
              ("HOLD " + "; ".join(errors) if errors else "PREFLIGHT_PASS"))
        return 2 if errors else 0
    pull_verify(args.sha256)
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
