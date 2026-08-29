import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DIGEST_RE = re.compile(r"^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
STAGES = ("dev", "staging", "prod")


def run(args, *, cwd=None, env=None, check=True, capture=True):
    merged = os.environ.copy()
    if env:
        merged.update(env)
    result = subprocess.run(args, cwd=cwd, env=merged, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout or ''}")
    return result


def immutable_ref(value):
    return bool(DIGEST_RE.fullmatch(value or ""))


def require_immutable(value):
    if not immutable_ref(value):
        raise ValueError(f"mutable or invalid image reference rejected: {value}")
    return value


def require_loopback(binding):
    if not binding.startswith("127.0.0.1:"):
        raise ValueError(f"non-loopback binding rejected: {binding}")
    return binding


def migration_checksum(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_migration_checksum(recorded, path):
    actual = migration_checksum(path)
    if recorded != actual:
        raise ValueError(f"migration checksum mismatch: {Path(path).name}")
    return True


class AuditLog:
    FORBIDDEN_KEYS = {"password", "secret", "credential", "db_password"}

    def __init__(self, path, known_secrets=()):
        self.path = Path(path)
        self.known_secrets = tuple(known_secrets)

    def append(self, event, **fields):
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "actor": "spike-runner", "event": event, **fields}
        encoded = json.dumps(record, sort_keys=True)
        lowered = {str(k).lower() for k in record}
        if lowered & self.FORBIDDEN_KEYS or any(value and value in encoded for value in self.known_secrets):
            raise ValueError("secret-bearing audit record rejected")
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(encoded + "\n")

    def validate(self):
        text = self.path.read_text()
        if any(value and value in text for value in self.known_secrets):
            raise ValueError("known secret found in audit log")
        return [json.loads(line) for line in text.splitlines()]


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def read_json(path):
    return json.loads(Path(path).read_text())


def http_json(url, expected=200, timeout=3):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            status = response.status
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        status = error.code
        payload = json.loads(error.read())
    if status != expected:
        raise AssertionError(f"{url}: expected {expected}, got {status}: {payload}")
    return payload


def wait_until(operation, timeout=60, interval=1):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            return operation()
        except Exception as error:
            last = error
            time.sleep(interval)
    raise TimeoutError(f"condition not met: {last}")
