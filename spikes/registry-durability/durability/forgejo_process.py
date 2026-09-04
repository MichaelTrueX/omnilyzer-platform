"""Local Forgejo binary discovery and isolated process lifecycle for Task 012B."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener


CACHED_IMAGE = "codeberg.org/forgejo/forgejo@sha256:214f4ae63ee78be1e445e58573c88dc7215e72091210852e0df94eaac1a25685"


@dataclass(frozen=True)
class ForgejoBinary:
    path: Path
    recorded_path: str
    version: str
    sha256: str
    source: str


def prepare_binary(runtime: Path) -> ForgejoBinary:
    """Use an explicit/host binary, or extract the locally cached pinned image binary."""
    override = os.environ.get("FORGEJO_BIN")
    discovered = override or shutil.which("forgejo")
    source = "FORGEJO_BIN" if override else "host PATH"
    if discovered:
        path = Path(discovered).resolve(strict=True)
        recorded_path = str(path)
    else:
        subprocess.run(
            ["docker", "image", "inspect", CACHED_IMAGE],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        container = subprocess.run(
            ["docker", "create", "--network", "none", CACHED_IMAGE],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise RuntimeError("docker returned a malformed temporary container ID")
        path = runtime / "forgejo"
        try:
            subprocess.run(
                ["docker", "cp", f"{container}:/app/gitea/gitea", str(path)],
                check=True,
                capture_output=True,
            )
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        path.chmod(0o700)
        recorded_path = "/app/gitea/gitea"
        source = CACHED_IMAGE + ":/app/gitea/gitea"
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError("Forgejo binary is not an executable regular file")
    output = subprocess.run(
        [str(path), "--version"], check=True, capture_output=True, text=True, timeout=10
    ).stdout.strip()
    match = re.fullmatch(r"forgejo version ([^ ]+).*", output)
    if match is None:
        raise RuntimeError("Forgejo version output is unexpected")
    return ForgejoBinary(
        path=path,
        recorded_path=recorded_path,
        version=match.group(1),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        source=source,
    )


def _loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class ForgejoProcess:
    """Forgejo configured entirely below one temporary state directory."""

    def __init__(self, binary: ForgejoBinary, state: Path, *, exclude_port: int | None = None) -> None:
        self.binary = binary
        self.state = state
        self.port = _loopback_port()
        while self.port == exclude_port:
            self.port = _loopback_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.config = state / "custom/conf/app.ini"
        self.database = state / "forgejo.db"
        self.package_storage = state / "data/packages"
        self.process: subprocess.Popen[bytes] | None = None
        self.log = None
        self.clean_shutdown = False

    def initialize(self) -> None:
        if self.state.exists() and any(self.state.iterdir()):
            raise RuntimeError("Forgejo state must begin empty")
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._write_config()
        self._command("migrate")

    def _write_config(self) -> None:
        self.config.parent.mkdir(mode=0o700, parents=True)
        for path in (self.state / "data", self.package_storage, self.state / "repositories", self.state / "log"):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        config = f"""APP_NAME = Task 012B Synthetic Forgejo
RUN_MODE = prod
RUN_USER = {os.environ.get('USER', 'task012')}

[server]
PROTOCOL = http
HTTP_ADDR = 127.0.0.1
HTTP_PORT = {self.port}
DOMAIN = 127.0.0.1
ROOT_URL = {self.base_url}/
APP_DATA_PATH = {self.state / 'data'}
DISABLE_SSH = true
START_SSH_SERVER = false
OFFLINE_MODE = true

[database]
DB_TYPE = sqlite3
PATH = {self.database}

[repository]
ROOT = {self.state / 'repositories'}

[storage.packages]
STORAGE_TYPE = local
PATH = {self.package_storage}

[security]
INSTALL_LOCK = true
SECRET_KEY = task012b-synthetic-secret-key-not-for-production
INTERNAL_TOKEN = 012b012b012b012b012b012b012b012b012b012b012b012b012b012b012b012b

[service]
DISABLE_REGISTRATION = true
REQUIRE_SIGNIN_VIEW = false

[mailer]
ENABLED = false

[picture]
DISABLE_GRAVATAR = true

[log]
MODE = file
LEVEL = warn
ROOT_PATH = {self.state / 'log'}
"""
        self.config.write_text(config, encoding="utf-8")
        self.config.chmod(0o600)

    def configure_restored(self) -> None:
        if not self.database.is_file() or not self.package_storage.is_dir():
            raise RuntimeError("restored Forgejo state lacks database or package storage")
        (self.state / "repositories").mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.state / "log").mkdir(mode=0o700, parents=True, exist_ok=True)
        self._write_config()
        self._command("migrate")

    def _command(self, *arguments: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [str(self.binary.path), *arguments, "--config", str(self.config), "--work-path", str(self.state)],
            check=False,
            capture_output=capture,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            detail = ((completed.stderr or "") + (completed.stdout or "")).replace("\n", " ")[:1000]
            raise RuntimeError(f"isolated Forgejo command failed: {detail}")
        return completed

    def create_publisher(self) -> str:
        self._command(
            "admin", "user", "create",
            "--username", "task012b",
            "--password", "Task012b-Synthetic-Password-Only!",
            "--email", "task012b@invalid.example",
            "--admin",
            "--must-change-password=false",
        )
        token = self._command(
            "admin", "user", "generate-access-token",
            "--username", "task012b",
            "--token-name", "task012b-synthetic",
            "--scopes", "write:package,read:package",
            "--raw",
        ).stdout.strip()
        if not token or any(character.isspace() for character in token):
            raise RuntimeError("Forgejo generated a malformed temporary token")
        return token

    def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("Forgejo is already running")
        process_log = self.state / "process.log"
        process_log.touch(mode=0o600)
        self.log = process_log.open("ab", buffering=0)
        self.process = subprocess.Popen(
            [str(self.binary.path), "web", "--config", str(self.config), "--work-path", str(self.state)],
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"Forgejo exited during startup with {self.process.returncode}")
            try:
                with opener.open(self.base_url + "/api/healthz", timeout=1) as response:
                    if response.status == 200:
                        return
            except (OSError, URLError):
                time.sleep(0.05)
        raise RuntimeError("isolated Forgejo did not become ready")

    def stop(self) -> bool:
        if self.process is None:
            return self.clean_shutdown
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=20)
                self.clean_shutdown = self.process.returncode == 0
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                self.clean_shutdown = False
        else:
            self.clean_shutdown = self.process.returncode == 0
        if self.log is not None:
            self.log.close()
            self.log = None
        self.process = None
        return self.clean_shutdown
