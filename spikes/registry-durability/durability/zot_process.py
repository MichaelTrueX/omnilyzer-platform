"""Verified zot binary and isolated loopback process management."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time

from .registry_client import RegistryClient


EXPECTED_VERSION = "v2.1.20"
EXPECTED_BINARY_SHA256 = "a32e42d042d1f17b5b1317e55cc1a415a744c873dcd05c25c56b665478258bcb"
DEFAULT_ZOT_BIN = Path("/usr/local/bin/zot")


@dataclass(frozen=True)
class VerifiedBinary:
    path: Path
    version: str
    sha256: str
    version_output: str


def verify_binary() -> VerifiedBinary:
    """Require the exact Task 008D zot binary before testing storage."""
    configured = Path(os.environ.get("ZOT_BIN", str(DEFAULT_ZOT_BIN)))
    path = configured.resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise RuntimeError("ZOT_BIN is not an executable regular file")
    binary_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if binary_sha256 != EXPECTED_BINARY_SHA256:
        raise RuntimeError(f"zot binary SHA-256 is not {EXPECTED_BINARY_SHA256}")
    completed = subprocess.run(
        [str(path), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    output = (completed.stdout + completed.stderr).strip()
    parsed = None
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("message") == "version":
            parsed = value
            break
    if parsed is None or not str(parsed.get("commit", "")).startswith(EXPECTED_VERSION + "-"):
        raise RuntimeError("zot --version did not report the exact expected release")
    return VerifiedBinary(path, EXPECTED_VERSION, binary_sha256, output)


def unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class ZotProcess:
    """One zot process bound only to a dynamically selected loopback port."""

    def __init__(self, binary: VerifiedBinary, runtime: Path, storage: Path) -> None:
        self.binary = binary
        self.runtime = runtime
        self.storage = storage
        self.port = unused_loopback_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.process: subprocess.Popen[bytes] | None = None
        self.log_stream = None
        self.clean_shutdown = False

    def _write_config(self) -> Path:
        if self.storage.resolve() == Path("/var/lib/zot"):
            raise RuntimeError("refusing to use the live zot storage path")
        self.runtime.mkdir(mode=0o700, parents=True, exist_ok=False)
        log_dir = self.runtime / "logs"
        log_dir.mkdir(mode=0o700)
        config = {
            "distSpecVersion": "1.1.1",
            "storage": {
                "rootDirectory": str(self.storage.resolve()),
                "dedupe": True,
                "gc": False,
            },
            "http": {"address": "127.0.0.1", "port": str(self.port)},
            "log": {
                "level": "info",
                "output": str(log_dir / "zot.log"),
                "audit": str(log_dir / "audit.log"),
            },
        }
        config_path = self.runtime / "config.json"
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        config_path.chmod(0o600)
        subprocess.run(
            [str(self.binary.path), "verify", str(config_path)],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return config_path

    def start(self) -> RegistryClient:
        if self.process is not None:
            raise RuntimeError("zot process is already started")
        config_path = self._write_config()
        process_log = self.runtime / "process.log"
        process_log.touch(mode=0o600)
        self.log_stream = process_log.open("ab", buffering=0)
        self.process = subprocess.Popen(
            [str(self.binary.path), "serve", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=self.log_stream,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        client = RegistryClient(self.base_url)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"zot exited during startup with status {self.process.returncode}")
            try:
                client.ping()
                return client
            except (OSError, RuntimeError):
                time.sleep(0.05)
        raise RuntimeError("isolated zot did not become ready")

    def stop(self) -> bool:
        if self.process is None:
            return self.clean_shutdown
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                self.clean_shutdown = False
            else:
                self.clean_shutdown = self.process.returncode == 0
        else:
            self.clean_shutdown = self.process.returncode == 0
        if self.log_stream is not None:
            self.log_stream.close()
            self.log_stream = None
        self.process = None
        return self.clean_shutdown

    def __enter__(self) -> RegistryClient:
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        self.stop()
