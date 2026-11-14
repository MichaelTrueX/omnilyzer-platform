#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_offhost_store.py
Purpose: Store an authenticated SSH-relayed, age-encrypted production Keycloak
    recovery snapshot on michael-laptop, away from the decryption private key.
Related: services/identity/ops/keycloak_offhost_backup.py,
    services/identity/ops/keycloak_offhost_receive.py,
    services/identity/tests/test_keycloak_offhost_store.py, SECURITY.md.

michael-laptop has no SSH authorization to the production identity backup.
The already-approved small-laptop is used as a streaming SSH jump, without
writing the backup there. Only age ciphertext is transferred or stored.
Every SSH host is checked against already independently verified public keys.
The private decryption key stays exclusively on small-laptop.
"""
import argparse
import hashlib
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile

HOST = "michael-laptop"
USER = "michael"
JUMP_HOST = "192.168.68.116"
JUMP_USER = "trust"
JUMP_KNOWN_HOSTS = Path("/home/michael/.cache/omnilyzer-identity-offhost/small-laptop-known-host")
JUMP_KNOWN_HOSTS_SHA256 = "abf7bed721e19089ac3913addee134caa1f782d30ddbb5dda542b0568f74e2cd"
JUMP_IDENTITY = Path("/home/michael/.ssh/id_ed25519_family_mesh")
PROD_HOST = "46.62.147.181"
PROD_USER = "trusthansen"
PROD_PORT = 2222
CIPHERTEXT = "omnilyzer-keycloak-offhost-20261103.tar.age"
PROD_FILE = ("/home/trusthansen/.cache/omnilyzer-identity-production-preflight/" +
             CIPHERTEXT)
ROOT = Path("/home/michael/.local/share/omnilyzer/identity-backups")
TARGET = ROOT / CIPHERTEXT
LIMIT = 4 * 1024 * 1024 * 1024


# Section: Guard exact approved host and separate SSH identities before transfer.
def file_hash(path):
    """Compute SHA256 incrementally, without opening any plaintext backup."""
    result = hashlib.sha256()
    with path.open("rb") as inp:
        for chunk in iter(lambda: inp.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def preflight():
    """Collect independent source identity, SSH-host and destination mismatches."""
    problems = []
    if socket.gethostname().split(".")[0] != HOST or os.geteuid() != pwd.getpwnam(USER).pw_uid:
        problems.append("must be unprivileged michael on michael-laptop")
    for path in (JUMP_KNOWN_HOSTS, JUMP_IDENTITY):
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o600):
                problems.append("SSH identity/host key must be owner-only regular file")
        except OSError:
            problems.append("required pinned SSH file not found")
    try:
        if file_hash(JUMP_KNOWN_HOSTS) != JUMP_KNOWN_HOSTS_SHA256:
            problems.append("small-laptop SSH public host key changed")
    except OSError:
        problems.append("small-laptop host key unreadable")
    if TARGET.exists() or TARGET.is_symlink():
        problems.append("encrypted backup already stored; do not overwrite")
    if ROOT.exists():
        try:
            info = ROOT.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o700):
                problems.append("encrypted backup destination not user-private0700")
        except OSError:
            problems.append("destination cannot be inspected")
    return problems


# Section: Only ciphertext moves through both authenticated SSH connections.
def relay_command():
    """Return fixed SSH arguments for existing two-hop identity transport."""
    nested = (
        "/usr/bin/ssh -p 2222 -o BatchMode=yes "
        "-o StrictHostKeyChecking=yes -o ConnectTimeout=12 "
        "-o ServerAliveInterval=15 -o ServerAliveCountMax=3 "
        + PROD_USER + "@" + PROD_HOST + " /usr/bin/cat -- " + PROD_FILE
    )
    return [
        "/usr/bin/ssh", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(JUMP_KNOWN_HOSTS),
        "-o", "ConnectTimeout=12",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "IdentitiesOnly=yes", "-i", str(JUMP_IDENTITY),
        JUMP_USER + "@" + JUMP_HOST, nested,
    ]


def store(expected_sha256):
    """Store only verified ciphertext, atomically and exactly once."""
    issues = preflight()
    if issues:
        raise RuntimeError("OFFHOST_STORAGE_HOLD " + "; ".join(issues))
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise RuntimeError("verified production ciphertext SHA256 required")
    ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
    ROOT.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".m01-receiving-", dir=ROOT)
    try:
        with os.fdopen(fd, "wb") as output:
            result = subprocess.run(relay_command(), check=False,
                                    stdout=output, stderr=subprocess.PIPE,
                                    timeout=180)
            if result.returncode:
                raise RuntimeError("pinned two-hop SSH ciphertext relay failed")
            output.flush()
            os.fsync(output.fileno())
        received = Path(temporary)
        with received.open("rb") as content:
            if not content.read(24).startswith(b"age-encryption.org/v1"):
                raise RuntimeError("received file is not age ciphertext")
        size = received.stat().st_size
        if size < 1024 or size > LIMIT:
            raise RuntimeError("encrypted Keycloak backup size invalid")
        if file_hash(received) != expected_sha256:
            raise RuntimeError("offhost ciphertext SHA256 mismatch")
        received.chmod(0o600)
        os.replace(temporary, TARGET)
        temporary = None
        print("M01_OFFHOST_KEY_SEPARATED_STORAGE_PASS " +
              "host=michael-laptop two_ssh_host_keys_verified=true " +
              "ciphertext_sha256_verified=true " +
              "no_ciphertext_saved_on_key_laptop=true " +
              "private_decryption_key_not_on_storage_host=true " +
              "age_encrypted_file_stored_mode0600=true " +
              "bytes=" + str(size) + " sha256=" + expected_sha256)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    """Read-only laptop preflight or first authenticated encrypted snapshot."""
    parser = argparse.ArgumentParser(description="Keycloak encrypted DR copy")
    parser.add_argument("action", choices=("preflight", "store"))
    parser.add_argument("--sha256", default="")
    args = parser.parse_args(argv)
    if args.action == "preflight":
        issues = preflight()
        print("M01_OFFHOST_STORAGE_" +
              ("HOLD " + "; ".join(issues) if issues else "PREFLIGHT_PASS"))
        return 2 if issues else 0
    store(args.sha256)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("M01_OFFHOST_STORAGE_HOLD " +
              (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__),
              file=sys.stderr)
        sys.exit(2)
