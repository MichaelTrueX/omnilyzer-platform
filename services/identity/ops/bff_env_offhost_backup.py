#!/usr/bin/env python3
"""File: services/identity/ops/bff_env_offhost_backup.py
Purpose: Make one root-owned, age-encrypted recovery copy of the *existing*
  production Sumlaude Django BFF EnvironmentFile. Reuse the previously
  independently verified small-laptop age/SSH recipient from Keycloak backup.
Related: ops/keycloak_offhost_backup.py, ops/prepare_identity_runtime_env.py,
  tests/test_bff_env_offhost_backup.py,
  docs/adr/0003-keycloak-bff-and-native-authentication.md.

Preflight is read-only. Export creates encrypted bytes only: root0600 local
copy and identical 0600 encrypted-only operator SSH-pull stage. No decrypted
archive, plaintext copy, database dump, new password, new recipient, app or DB
service, DNS change or release switch. Offhost verification and storage are
distinct steps: a staged ciphertext is NOT a completed offsite backup.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys


# Section 1: Preserve the exact original release, recipient and storage trust.
HOST = "truexmainserver"
OWNER = "trusthansen"
CURRENT = Path("/opt/omnilyzer/identity/current")
OLD_RELEASE = Path("/opt/omnilyzer/identity/releases/"
                   "d65d14b69d3e5c899ab9291741b9029669244168")
PRIVATE_DIR = Path("/etc/omnilyzer/identity")
KEYCLOAK_DIR = Path("/etc/omnilyzer/keycloak")
ENV = PRIVATE_DIR / "identity.env"
CLIENT = KEYCLOAK_DIR / "sumlaude-bff-client.env"
DB_SOURCE = PRIVATE_DIR / "identity-session-db.env.partial"
GO = PRIVATE_DIR / "owner-approved-go"
AGE = Path("/usr/bin/age")
RECIPIENT = Path("/home/trusthansen/.cache/"
                 "omnilyzer-identity-production-preflight/"
                 "small-laptop-keycloak-backup-recipient.pub")
RECIPIENT_SHA256 = (
    "d6955c0bbc8a74847aa464196ac516275561ce6a7306674c9a8dd39d5150a492"
)
STAGING_DIR = Path("/home/trusthansen/.cache/"
                   "omnilyzer-identity-production-preflight")
BACKUP_DIR = Path("/var/backups/omnilyzer-bff")
CIPHER_NAME = "omnilyzer-bff-identity-env-20261106.age"
ROOT_CIPHER = BACKUP_DIR / CIPHER_NAME
STAGED_CIPHER = STAGING_DIR / CIPHER_NAME
ROOT_OPERATOR_DIR = Path("/run/m01-bff-env-backup")
ROOT_OPERATOR = ROOT_OPERATOR_DIR / "bff_env_offhost_backup.py"
CLIENT_KEYS = {"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"}
DB_KEYS = {"IDENTITY_PG_DATABASE", "IDENTITY_PG_USER",
           "IDENTITY_PG_PASSWORD", "IDENTITY_PG_HOST", "IDENTITY_PG_PORT"}
ALL_KEYS = CLIENT_KEYS | DB_KEYS | {
    "DJANGO_SECRET_KEY", "TOKEN_FERNET_KEY", "PRODUCT_ORIGIN",
    "SUMLAUDE_ISSUER_DSN",
}
ISSUER_DSN = (
    "dbname=sumlaude_learning user=sumlaude_identity_issuer "
    "host=/var/run/postgresql port=5432"
)


def hold(why):
    """Stop before sensitive file writes, without echoing any credential."""
    raise RuntimeError("M01_BFF_BACKUP_HOLD " + why)


def digest(path):
    """Return SHA256 of public key or ciphertext without logging plaintext."""
    sha = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1048576), b""):
            sha.update(block)
    return sha.hexdigest()


def file_bytes(path, *, owner_uid=0, mode=0o600):
    """Read a single exact-ownership regular file with no links or path races."""
    prior = path.lstat()
    if (not stat.S_ISREG(prior.st_mode) or prior.st_uid != owner_uid or
            (owner_uid == 0 and prior.st_gid != 0) or
            stat.S_IMODE(prior.st_mode) != mode or prior.st_nlink != 1):
        hold("unexpected protected source or recipient metadata")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        now = os.fstat(fd)
        if (now.st_ino != prior.st_ino or now.st_dev != prior.st_dev):
            hold("protected source changed during read")
        result = os.read(fd, 8193)
        if not result or len(result) > 8192:
            hold("protected source is empty or unexpectedly large")
        return result
    finally:
        os.close(fd)


def parse_env(payload, *, expected):
    """Parse only the exact root-generated ASCII env; never support shell eval."""
    try:
        content = payload.decode("ascii")
    except UnicodeError:
        hold("environment source contains non-ASCII bytes")
    if not content.endswith("\n") or "\r" in content or "\0" in content:
        hold("environment source line endings invalid")
    result = {}
    for line in content.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in expected or key in result or not value:
            hold("environment source field mismatch")
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if any(char in value for char in '\\"\'\r\n\0') or not value:
            hold("environment source value requires unsupported escaping")
        result[key] = value
    if set(result) != expected:
        hold("environment source field inventory incomplete")
    return result


def inspect_configuration():
    """Verify real BFF keys and that client/DB secrets match original fragments."""
    live = parse_env(file_bytes(ENV), expected=ALL_KEYS)
    client = parse_env(file_bytes(CLIENT), expected=CLIENT_KEYS)
    database = parse_env(file_bytes(DB_SOURCE), expected=DB_KEYS)
    if any(live[k] != value for source in (client, database)
           for k, value in source.items()):
        hold("runtime env credentials differ from original protected fragments")
    if (live["OIDC_ISSUER"] != "https://login.omnilyzer.ai/realms/omnilyzer"
            or live["OIDC_CLIENT_ID"] != "sumlaude-bff"
            or live["PRODUCT_ORIGIN"] != "https://app.sumlaude.com"
            or live["SUMLAUDE_ISSUER_DSN"] != ISSUER_DSN
            or len(live["DJANGO_SECRET_KEY"]) < 50):
        hold("identity runtime BFF issuer or session contract mismatch")
    try:
        key = live["TOKEN_FERNET_KEY"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}=", key):
            hold("Fernet key format changed")
        if len(base64.urlsafe_b64decode(key.encode("ascii"))) != 32:
            hold("Fernet key length changed")
    except (ValueError, UnicodeError):
        hold("Fernet key cannot be decoded")
    return True


def operator_guard():
    """Require the exact root0500 private /run script, never mutable home source."""
    if os.geteuid() != 0 or Path(__file__).absolute() != ROOT_OPERATOR:
        hold("expected host root operator required")
    directory = ROOT_OPERATOR_DIR.lstat()
    script = ROOT_OPERATOR.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            stat.S_IMODE(directory.st_mode) != 0o700 or
            not stat.S_ISREG(script.st_mode) or script.st_uid != 0 or
            script.st_gid != 0 or script.st_nlink != 1 or
            stat.S_IMODE(script.st_mode) != 0o500):
        hold("root-only operator custody mismatch")


def preflight():
    """Read-only validate source, crypto recipient and disabled production."""
    operator_guard()
    if socket.gethostname().split(".")[0] != HOST:
        hold("wrong production host")
    for directory in (PRIVATE_DIR, KEYCLOAK_DIR):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o700):
            hold("identity configuration parent protection changed")
    if GO.exists() or GO.is_symlink():
        hold("BFF activation marker already exists")
    if not CURRENT.is_symlink() or CURRENT.resolve() != OLD_RELEASE:
        hold("BFF selected release changed")
    for unit in ("omnilyzer-identity.service", "sumlaude-native.service"):
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", unit, "-p", "ActiveState",
             "-p", "UnitFileState", "--no-pager"],
            capture_output=True, text=True, check=False, timeout=12,
        )
        if (result.returncode != 0 or
                "ActiveState=inactive" not in result.stdout.splitlines() or
                "UnitFileState=disabled" not in result.stdout.splitlines()):
            hold("BFF or Native no longer inactive and disabled")
    if BACKUP_DIR.exists() or BACKUP_DIR.is_symlink():
        hold("previous BFF backup root exists; do not overwrite")
    if STAGED_CIPHER.exists() or STAGED_CIPHER.is_symlink():
        hold("previous encrypted operator stage exists; do not overwrite")
    owner = pwd.getpwnam(OWNER)
    info = STAGING_DIR.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner.pw_uid or
            info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        hold("existing encrypted operator staging directory not protected")
    recipient = file_bytes(RECIPIENT, owner_uid=owner.pw_uid)
    if digest(RECIPIENT) != RECIPIENT_SHA256 or not re.fullmatch(
            rb"ssh-ed25519 [A-Za-z0-9+/=]+ trust@small-laptop\n?", recipient):
        hold("verified Keycloak backup recipient key mismatch")
    try:
        result = subprocess.run([str(AGE), "--version"],
                                capture_output=True, check=False, timeout=8)
        if result.returncode or result.stdout.strip() != b"1.1.1":
            hold("existing reviewed age 1.1.1 unavailable")
    except (OSError, subprocess.SubprocessError):
        hold("age crypto executable not available")
    if shutil.disk_usage("/").free < 1024**3:
        hold("insufficient free filesystem capacity for encrypted backup")
    inspect_configuration()
    print("M01_BFF_BACKUP_ROOT_PREFLIGHT_PASS "
          "runtime_env_root0600=true client_and_DB_fragments_match=true "
          "signing_and_fernet_format_pass=true recipient_SHA256_pinned=true "
          "age_1_1_1=true BFF_and_Native_disabled_inactive=true "
          "no_plaintext_exposed=true no_write=true")


# Section 2: Create no plaintext copies, encrypt one existing protected file.
def open_checked_source():
    """Open the root-only env without following links, and verify inode/mode."""
    info = ENV.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_gid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600):
        hold("root-only source metadata changed before encryption")
    fd = os.open(ENV, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    after = os.fstat(fd)
    if (after.st_ino != info.st_ino or after.st_dev != info.st_dev or
            after.st_uid != 0 or stat.S_IMODE(after.st_mode) != 0o600):
        os.close(fd)
        hold("root-only source changed during encryption open")
    return os.fdopen(fd, "rb")


def exclusive_cipher():
    """Stream root-only identity.env directly into an exclusive age ciphertext."""
    BACKUP_DIR.mkdir(mode=0o700)
    info = BACKUP_DIR.lstat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        hold("encrypted backup root directory protections changed")
    fd = os.open(ROOT_CIPHER, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output, open_checked_source() as secret:
            done = subprocess.run([str(AGE), "-R", str(RECIPIENT)],
                                  stdin=secret, stdout=output,
                                  stderr=subprocess.PIPE, timeout=25,
                                  check=False)
            if done.returncode:
                hold("age encryption failed, no credential output")
            output.flush()
            os.fsync(output.fileno())
        with ROOT_CIPHER.open("rb") as src:
            header = src.read(24)
        if not header.startswith(b"age-encryption.org/v1"):
            hold("age ciphertext header invalid")
        size = ROOT_CIPHER.stat().st_size
        if size < 350 or size > 32768:
            hold("encrypted configuration backup size outside expected bounds")
        return digest(ROOT_CIPHER), size
    except Exception:
        ROOT_CIPHER.unlink(missing_ok=True)
        raise


def stage_cipher(digest_sha):
    """Duplicate only encrypted bytes for existing verified SSH offhost pull."""
    owner = pwd.getpwnam(OWNER)
    fd = os.open(STAGED_CIPHER, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as out, ROOT_CIPHER.open("rb") as src:
            shutil.copyfileobj(src, out, length=1048576)
            out.flush()
            os.fsync(out.fileno())
        if digest(STAGED_CIPHER) != digest_sha:
            hold("staged ciphertext SHA256 mismatch")
        os.chown(STAGED_CIPHER, owner.pw_uid, owner.pw_gid)
        os.chmod(STAGED_CIPHER, 0o600)
    except Exception:
        STAGED_CIPHER.unlink(missing_ok=True)
        raise


def export_once():
    """Run checked age encryption exactly once; never start an app service."""
    preflight()
    inspect_configuration()
    sha, size = exclusive_cipher()
    stage_cipher(sha)
    print("M01_BFF_BACKUP_LOCAL_ENCRYPTED_EXPORT_PASS "
          "single_root_only_source=true age_ciphertext_only=true "
          "no_second_plaintext_copy=true "
          "recipient_key_separate_small_laptop=true "
          "root_and_staged_sha256_match=true "
          "offsite_storage_PENDING=true "
          "bytes=" + str(size) + " sha256=" + sha)


def main(argv=None):
    """Dispatch root-only read-only preflight or first encrypted export."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "export"))
    action = parser.parse_args(argv).action
    if action == "preflight":
        preflight()
    else:
        export_once()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, UnicodeError,
            subprocess.SubprocessError) as exc:
        print(str(exc) if isinstance(exc, RuntimeError) else
              "M01_BFF_BACKUP_HOLD " + type(exc).__name__, file=sys.stderr)
        sys.exit(2)
