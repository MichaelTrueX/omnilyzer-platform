#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_offhost_backup.py
Purpose: Encrypt the already independently restored Keycloak local recovery
    archive to an independently verified offline laptop SSH/age recipient.
Related: services/identity/ops/keycloak_prod_recovery.py,
    services/identity/tests/test_keycloak_offhost_backup.py,
    docs/adr/0003-keycloak-bff-and-native-authentication.md, SECURITY.md.

The only supported environment is the existing truexmainserver production
Keycloak. Plaintext never leaves its root-only backup directory. Ciphertext is
staged under an existing operator-owned private directory for an authenticated
off-host SSH pull. No root key, OAuth secret, database row, password, or PII
is committed or displayed. It never changes Keycloak/Nginx/PG services.
The encrypted copy is a point-in-time DR seed, not recurring backup acceptance.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

HOST = "truexmainserver"
OWNER = "trusthansen"
BACKUP_ROOT = Path("/var/backups/omnilyzer-keycloak")
RECIPIENT = Path("/home/trusthansen/.cache/omnilyzer-identity-production-preflight/"
                 "small-laptop-keycloak-backup-recipient.pub")
STAGING = Path("/home/trusthansen/.cache/omnilyzer-identity-production-preflight")
CIPHERTEXT_BASENAME = "omnilyzer-keycloak-offhost-20261103.tar.age"
CIPHERTEXT_ROOT = BACKUP_ROOT / CIPHERTEXT_BASENAME
CIPHERTEXT_STAGED = STAGING / CIPHERTEXT_BASENAME
RECEIVER_FINGERPRINT_SHA256 = (
    "d6955c0bbc8a74847aa464196ac516275561ce6a7306674c9a8dd39d5150a492"
)
AGE_VERSION = "1.1.1-1ubuntu0.24.04.3"
AGE_BIN = Path("/usr/bin/age")
FILES = (
    "keycloak.pgcustom",
    "keycloak.env",
    "sumlaude-bff-client.env",
    "omnilyzer-keycloak.service",
    "sha256sum.txt",
)


# Section: Verify the encrypted backup's recovery source and recipient first.
def file_digest(path):
    """Hash a checked regular file incrementally without exposing its contents."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_metadata(path, *, root_required=True, mode=0o600):
    """Assert exact file metadata; symlinks and multi-link files are forbidden."""
    record = path.lstat()
    if (not stat.S_ISREG(record.st_mode) or record.st_nlink != 1 or
            stat.S_IMODE(record.st_mode) != mode or
            (root_required and record.st_uid != 0)):
        raise RuntimeError("backup file ownership/type/mode invalid: " + path.name)
    return record


def inspect_backup_directory(root=BACKUP_ROOT):
    """Inspect complete, original, independently restored local backup without SQL."""
    metadata = root.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or
            stat.S_IMODE(metadata.st_mode) != 0o700):
        raise RuntimeError("Keycloak local recovery directory not root 0700")
    allowed = set(FILES)
    found = {p.name for p in root.iterdir()}
    if found != allowed:
        raise RuntimeError("Keycloak recovery file inventory unexpected")
    checks = {}
    for name in FILES:
        path = root / name
        record = file_metadata(path)
        if record.st_size <= 0:
            raise RuntimeError("empty Keycloak recovery file: " + name)
        checks[name] = {"sha256": file_digest(path), "bytes": record.st_size}
    with (root / "keycloak.pgcustom").open("rb") as dump:
        if dump.read(5) != b"PGDMP":
            raise RuntimeError("backup PostgreSQL archive signature invalid")
    recorded = (root / "sha256sum.txt").read_text(encoding="ascii").strip()
    expected = checks["keycloak.pgcustom"]["sha256"] + "  keycloak.pgcustom"
    if recorded != expected:
        raise RuntimeError("existing Keycloak database backup SHA256 mismatches")
    return checks


def preflight():
    """Collect independent mismatches before any package or backup mutation."""
    problems = []
    if socket.gethostname().split(".")[0] != HOST or os.geteuid() != 0:
        problems.append("owner-root on truexmainserver required")
    try:
        owner = pwd.getpwnam(OWNER)
        staging_meta = STAGING.lstat()
        if (not stat.S_ISDIR(staging_meta.st_mode) or
                staging_meta.st_uid != owner.pw_uid or
                bool(staging_meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH))):
            problems.append("operator staging directory not private to expected user")
        key_meta = file_metadata(RECIPIENT, root_required=False)
        if key_meta.st_uid != owner.pw_uid:
            problems.append("age recipient not owned by expected operator")
        if file_digest(RECIPIENT) != RECEIVER_FINGERPRINT_SHA256:
            problems.append("backup recipient public key SHA256 does not match laptop")
        key_text = RECIPIENT.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+ trust@small-laptop",
                            key_text):
            problems.append("backup recipient is not exact pinned SSH Ed25519 format")
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        problems.append("cannot validate recipient: " + type(exc).__name__)
    try:
        inspect_backup_directory()
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        # Fail with specific source type, not any sensitive backup contents.
        problems.append("original recovery backup unavailable: " + str(exc))
    for target in (CIPHERTEXT_ROOT, CIPHERTEXT_STAGED):
        if target.exists() or target.is_symlink():
            problems.append("previous ciphertext exists; inspect before rerun")
    if shutil.disk_usage("/").free < 8 * 1024**3:
        problems.append("less than 8GiB free for secure backup")
    try:
        result = subprocess.run(["/usr/bin/systemctl", "show",
                                 "omnilyzer-keycloak.service",
                                 "-p", "ActiveState", "-p", "UnitFileState", "--no-pager"],
                                capture_output=True, text=True, check=True, timeout=12)
        if "ActiveState=active" not in result.stdout.splitlines() or (
                "UnitFileState=enabled" not in result.stdout.splitlines()):
            problems.append("Keycloak running+boot-enabled source not verified")
    except (OSError, subprocess.SubprocessError):
        problems.append("cannot inspect production identity service")
    try:
        version = subprocess.run(["/usr/bin/apt-cache", "policy", "age"],
                                 capture_output=True, text=True, check=True, timeout=12)
        if AGE_VERSION not in version.stdout:
            problems.append("signed Ubuntu age package version not available")
    except (OSError, subprocess.SubprocessError):
        problems.append("Ubuntu age package metadata unavailable")
    return problems


# Section: Create the ciphertext without writing another plaintext archive.
def ensure_signed_age():
    """Install only the exact Ubuntu age package from configured signed apt."""
    result = subprocess.run(
        ["/usr/bin/apt-get", "install", "-y", "--no-install-recommends",
         "age=" + AGE_VERSION],
        capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError("signed Ubuntu age package installation failed")
    version = subprocess.run([str(AGE_BIN), "--version"],
                             check=True, capture_output=True, text=True, timeout=10)
    if version.stdout.strip() != "1.1.1":
        raise RuntimeError("unexpected age crypto binary version")


def create_tar_stream(writer, checks):
    """Write fixed five-file tar with internal integrity manifest to age stdin."""
    manifest = {
        "format": "omnilyzer-keycloak-offhost-v1",
        "issuer": "https://login.omnilyzer.ai/realms/omnilyzer",
        "recovery_files": checks,
        "recipient_public_key_sha256": RECEIVER_FINGERPRINT_SHA256,
        "source": "independently-restored-production-local-Keycloak-backup",
    }
    payload = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) +
               "\n").encode("ascii")
    with tarfile.open(mode="w|", fileobj=writer) as archive:
        for name in FILES:
            path = BACKUP_ROOT / name
            # Root-owned original data files were independently checked first.
            member = tarfile.TarInfo(name)
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mode = 0o600
            member.mtime = 0
            member.size = checks[name]["bytes"]
            with path.open("rb") as stream:
                archive.addfile(member, stream)
        record = tarfile.TarInfo("manifest.json")
        record.uid = 0
        record.gid = 0
        record.mode = 0o600
        record.mtime = 0
        record.size = len(payload)
        archive.addfile(record, io.BytesIO(payload))


def encrypt_to_root(checks):
    """Encrypt directly from a tar stream; no additional unencrypted tar on disk."""
    fd = os.open(CIPHERTEXT_ROOT, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            process = subprocess.Popen(
                [str(AGE_BIN), "-R", str(RECIPIENT)],
                stdin=subprocess.PIPE, stdout=output, stderr=subprocess.PIPE)
            try:
                create_tar_stream(process.stdin, checks)
                process.stdin.close()
                process.stdin = None
                _, error = process.communicate(timeout=120)
                if process.returncode != 0:
                    raise RuntimeError("age encryption command failed")
                output.flush()
                os.fsync(output.fileno())
            except Exception:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
                raise
        with CIPHERTEXT_ROOT.open("rb") as result:
            if not result.read(24).startswith(b"age-encryption.org/v1"):
                raise RuntimeError("age encryption file header mismatch")
        if CIPHERTEXT_ROOT.stat().st_size < 1024:
            raise RuntimeError("encrypted backup unexpectedly small")
    except Exception:
        CIPHERTEXT_ROOT.unlink(missing_ok=True)
        raise
    return CIPHERTEXT_ROOT.stat().st_size, file_digest(CIPHERTEXT_ROOT)


# Section: Expose ciphertext only to the authenticated operator for SSH pull.
def stage_ciphertext(digest):
    """Transfer encrypted bytes to one existing operator-private directory."""
    owner = pwd.getpwnam(OWNER)
    fd = os.open(CIPHERTEXT_STAGED, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            with CIPHERTEXT_ROOT.open("rb") as source:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        if file_digest(CIPHERTEXT_STAGED) != digest:
            raise RuntimeError("staged ciphertext SHA mismatch")
        os.chown(CIPHERTEXT_STAGED, owner.pw_uid, owner.pw_gid)
    except Exception:
        CIPHERTEXT_STAGED.unlink(missing_ok=True)
        raise


def export_once():
    """One owner-root export; never send plaintext or launch network transfers."""
    problems = preflight()
    if problems:
        raise RuntimeError("OFFHOST_HOLD: " + "; ".join(problems))
    ensure_signed_age()
    checks = inspect_backup_directory()
    size, digest = encrypt_to_root(checks)
    stage_ciphertext(digest)
    print("M01_OFFHOST_ENCRYPTED_EXPORT_PASS age=1.1.1 recipient_pinned=true " +
          "payload=verified_restorable_keycloak_backup plaintext_offhost=false " +
          "bytes=" + str(size) + " sha256=" + digest +
          " ciphertext_staged_for_ssh_pull=true service_changes=false " +
          "independent_offhost_decryption_pending=true")


def main(argv=None):
    """Read-only preflight or explicit one-time owner-root encrypted export."""
    parser = argparse.ArgumentParser(description="Keycloak age encrypted offhost export")
    parser.add_argument("action", choices=("preflight", "export"))
    args = parser.parse_args(argv)
    if args.action == "preflight":
        issues = preflight()
        print("M01_OFFHOST_" + ("HOLD " + "; ".join(issues)
              if issues else "PREFLIGHT_PASS"))
        return 2 if issues else 0
    export_once()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, UnicodeError,
            subprocess.SubprocessError, tarfile.TarError) as exc:
        print("M01_OFFHOST_HOLD " +
              (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__),
              file=sys.stderr)
        sys.exit(2)
