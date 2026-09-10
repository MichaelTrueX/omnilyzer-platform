"""Closed Docker/Compose implementation of the Task 014 DEV runtime boundary.

Nothing is executed at import time. Callers provide domain values; command argv,
paths, service names, and HTTP targets are generated only from closed allowlists.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
from typing import Mapping, Protocol

from .controller import DeploymentPlan
from .policy import DeploymentPolicyError, validate_semver, validate_slot, validate_source_sha


PROJECT = "omnilyzer-task014-dev"
COMPOSE_FILE = Path(__file__).parent / "runtime/dev/compose.yaml"
WORKING_DIRECTORY = COMPOSE_FILE.parent.resolve()
RUNTIME_CONFIG_FILE = WORKING_DIRECTORY / "canary-runtime.json"
RUNTIME_CONFIG_BYTES = b'{"CANARY_DEPENDENCY_REQUIRED":"false","CANARY_RUNTIME_CONFIG_ID":"task014-dev","schema_version":1}\n'
IMAGE_PREFIX = "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@"
IMAGE_RE = re.compile(re.escape(IMAGE_PREFIX) + r"sha256:[0-9a-f]{64}\Z")
MIGRATION_IDENTITY = "task014-executable-canary-v1"
MIGRATION_CHECKSUM = "b25e7d2d55bce3e233f58f9607e715daebc2a1a69c37603adbb569604ef76421"
MIGRATION_DIRECTORY = Path("/var/lib/omnilyzer/deployment/dev/canary-runtime")
NGINX_RUNTIME_DIRECTORY = Path("/var/lib/omnilyzer/deployment/dev/nginx-runtime")
MAX_COMMAND_OUTPUT = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 30.0
HTTP_TIMEOUT_SECONDS = 3.0
MAX_HTTP_RESPONSE = 4096


class RuntimeOperationError(DeploymentPolicyError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, argv: tuple[str, ...], *, cwd: Path, environment: Mapping[str, str], timeout: float) -> CommandResult:
        ...


class SubprocessCommandRunner:
    """Bounded runner for the future privileged executor; never invokes a shell."""

    def run(self, argv: tuple[str, ...], *, cwd: Path, environment: Mapping[str, str], timeout: float) -> CommandResult:
        try:
            process = subprocess.Popen(
                argv, cwd=cwd, env=dict(environment), shell=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise RuntimeOperationError("bounded runtime command failed") from exc
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    streams[key.fileobj].extend(chunk)
                    if len(streams[key.fileobj]) > MAX_COMMAND_OUTPUT:
                        raise RuntimeOperationError("runtime command output exceeded its bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            returncode = process.wait(timeout=remaining)
        except (RuntimeOperationError, subprocess.TimeoutExpired) as exc:
            process.kill()
            process.wait()
            if isinstance(exc, RuntimeOperationError):
                raise
            raise RuntimeOperationError("bounded runtime command failed") from exc
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
        stdout = bytes(streams[process.stdout])
        stderr = bytes(streams[process.stderr])
        return CommandResult(
            returncode,
            stdout.decode("utf-8", "replace").replace("\x00", ""),
            stderr.decode("utf-8", "replace").replace("\x00", ""),
        )


class CandidateHttpClient(Protocol):
    def get(self, slot: str, path: str, *, timeout: float, max_bytes: int) -> tuple[int, bytes]:
        ...


def validate_canary_image(value: str) -> str:
    if not isinstance(value, str) or IMAGE_RE.fullmatch(value) is None:
        raise RuntimeOperationError("CANARY_IMAGE must be the exact approved repository@sha256 digest")
    return value


def validate_runtime_configuration(raw: bytes) -> None:
    if not isinstance(raw, bytes) or raw != RUNTIME_CONFIG_BYTES:
        raise RuntimeOperationError("DEV runtime configuration is not the exact canonical closed document")


def candidate_slot(active_slot: str | None) -> str:
    if active_slot is None:
        return "blue"
    validate_slot(active_slot, "active_slot")
    return "green" if active_slot == "blue" else "blue"


class DockerRuntimeAdapter:
    """Production-owned, non-automatic adapter for closed DEV operations."""

    def __init__(
        self, runner: CommandRunner, http: CandidateHttpClient, *, canary_image: str,
    ) -> None:
        self._runner = runner
        self._http = http
        self._canary_image = validate_canary_image(canary_image)
        self._nginx_runtime_directory = NGINX_RUNTIME_DIRECTORY
        self._migration_directory = MIGRATION_DIRECTORY
        self._environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "CANARY_IMAGE": self._canary_image,
        }

    def _require_bound_image(self, image: str) -> str:
        image = validate_canary_image(image)
        if image != self._canary_image:
            raise RuntimeOperationError("image differs from the adapter's authorized CANARY_IMAGE")
        return image

    def _run(self, argv: tuple[str, ...], *, timeout: float = COMMAND_TIMEOUT_SECONDS) -> CommandResult:
        result = self._runner.run(
            argv, cwd=WORKING_DIRECTORY,
            environment=dict(self._environment), timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeOperationError("closed runtime operation returned an unexpected status")
        return result

    @staticmethod
    def _compose(*parts: str) -> tuple[str, ...]:
        return ("docker", "compose", "--project-name", PROJECT, "--file", str(COMPOSE_FILE), *parts)

    def pull_exact_image(self, image: str) -> None:
        image = self._require_bound_image(image)
        self._run(("docker", "pull", image))

    def verify_local_repo_digest(self, image: str) -> None:
        image = self._require_bound_image(image)
        result = self._run(("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image))
        if len(result.stdout.encode("utf-8")) > MAX_COMMAND_OUTPUT:
            raise RuntimeOperationError("local image identity output exceeded its bound")
        try:
            repo_digests = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeOperationError("local image identity was not valid JSON") from exc
        if not isinstance(repo_digests, list) or repo_digests != [image]:
            raise RuntimeOperationError("local RepoDigest does not exactly match CANARY_IMAGE")

    def start_candidate(self, plan: DeploymentPlan) -> None:
        slot = validate_slot(plan.candidate_slot, "candidate_slot")
        if slot != candidate_slot(plan.active_slot):
            raise RuntimeOperationError("plan candidate is not the inactive slot")
        image = self._require_bound_image(plan.exact_image_reference)
        if RUNTIME_CONFIG_FILE.is_symlink() or not RUNTIME_CONFIG_FILE.is_file():
            raise RuntimeOperationError("reviewed runtime configuration is unavailable")
        validate_runtime_configuration(RUNTIME_CONFIG_FILE.read_bytes())
        self.verify_local_repo_digest(image)
        self._run(self._compose("up", "--detach", "--no-deps", "--force-recreate", f"canary-{slot}"))

    def execute_migration(
        self, *, stage: str, exact_image_reference: str, identity: str, checksum: str,
    ) -> None:
        if stage != "dev":
            raise RuntimeOperationError("runtime adapter supports DEV only")
        image = self._require_bound_image(exact_image_reference)
        if identity != MIGRATION_IDENTITY or checksum != MIGRATION_CHECKSUM:
            raise RuntimeOperationError("migration identity or checksum is not authorized")
        if self._migration_directory.is_symlink() or not self._migration_directory.is_dir():
            raise RuntimeOperationError("migration runtime directory is not preinstalled")
        argv = (
            "docker", "run", "--rm", "--network", "none", "--user", "10001:10001", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128", "--memory", "128m", "--cpus", "0.50",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--mount", f"type=bind,src={self._migration_directory},dst=/run/omnilyzer-canary",
            "--entrypoint", "/usr/bin/python", image, "/app/migration.py",
        )
        self._run(argv, timeout=120.0)

    def _response(self, slot: str, path: str) -> tuple[int, dict[str, object]]:
        validate_slot(slot, "slot")
        if path not in ("/livez", "/readyz", "/metadata"):
            raise RuntimeOperationError("application validation path is not authorized")
        status, raw = self._http.get(slot, path, timeout=HTTP_TIMEOUT_SECONDS, max_bytes=MAX_HTTP_RESPONSE)
        if len(raw) > MAX_HTTP_RESPONSE:
            raise RuntimeOperationError("application response exceeded its bound")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeOperationError("application response is not valid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeOperationError("application response must be an object")
        return status, value

    def check_liveness(self, stage: str, slot: str) -> bool:
        if stage != "dev":
            raise RuntimeOperationError("runtime adapter supports DEV only")
        status, value = self._response(slot, "/livez")
        return status == 200 and value == {"live": True}

    def check_readiness(self, stage: str, slot: str) -> bool:
        if stage != "dev":
            raise RuntimeOperationError("runtime adapter supports DEV only")
        status, value = self._response(slot, "/readyz")
        return status == 200 and value.get("ready") is True

    def validate_application(self, plan: DeploymentPlan) -> bool:
        if plan.stage != "dev":
            raise RuntimeOperationError("runtime adapter supports DEV only")
        status, value = self._response(plan.candidate_slot, "/metadata")
        return status == 200 and value == {
            "canary": True,
            "release_version": validate_semver(plan.release_version),
            "source_sha": validate_source_sha(plan.source_sha),
        }

    @staticmethod
    def _active_fragment(slot: str) -> bytes:
        slot = validate_slot(slot, "active_slot")
        return (
            "server {\n"
            "    listen 8080;\n"
            "    server_name canary-dev.omnilyzer.ai;\n"
            f'    set $canary_backend "canary-{slot}:8080";\n'
            "    location / {\n"
            "        proxy_pass http://$canary_backend;\n"
            "        proxy_http_version 1.1;\n"
            "        proxy_set_header Host $host;\n"
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            "        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;\n"
            "    }\n"
            "}\n"
        ).encode("ascii")

    def validate_nginx(self, stage: str) -> bool:
        if stage != "dev":
            raise RuntimeOperationError("runtime adapter supports DEV only")
        self._run(self._compose("exec", "--no-TTY", "deployment-nginx", "nginx", "-t", "-c", "/etc/nginx/nginx.conf"))
        return True

    def _write_active_atomic(self, payload: bytes | None) -> None:
        directory = self._nginx_runtime_directory
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeOperationError("Nginx runtime directory is not preinstalled")
        target = directory / "active.conf"
        if payload is None:
            target.unlink(missing_ok=True)
        else:
            descriptor, name = tempfile.mkstemp(prefix=".active.conf.", dir=directory)
            temporary = Path(name)
            try:
                os.fchmod(descriptor, 0o644)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def switch_traffic(self, stage: str, slot: str) -> None:
        if stage != "dev":
            raise RuntimeOperationError("runtime adapter supports DEV only")
        self._replace_traffic(self._active_fragment(slot))

    def restore_traffic(self, stage: str, previous_slot: str | None) -> None:
        """Restore one closed prior DEV route, including no-active maintenance."""

        if type(stage) is not str or stage != "dev":
            raise RuntimeOperationError("runtime adapter supports DEV only")
        if (
            previous_slot is not None
            and (type(previous_slot) is not str or previous_slot not in ("blue", "green"))
        ):
            raise RuntimeOperationError("previous runtime slot is not authorized")
        payload = (
            None if previous_slot is None else self._active_fragment(previous_slot)
        )
        self._replace_traffic(payload)

    def _replace_traffic(self, payload: bytes | None) -> None:
        target = self._nginx_runtime_directory / "active.conf"
        old = target.read_bytes() if target.is_file() and not target.is_symlink() else None
        if target.exists() and (target.is_symlink() or not target.is_file()):
            raise RuntimeOperationError("active Nginx fragment is not a regular file")
        try:
            self._write_active_atomic(payload)
            self.validate_nginx("dev")
            self._run(self._compose("exec", "--no-TTY", "deployment-nginx", "nginx", "-s", "reload"))
        except BaseException:
            self._write_active_atomic(old)
            try:
                self.validate_nginx("dev")
                self._run(self._compose("exec", "--no-TTY", "deployment-nginx", "nginx", "-s", "reload"))
            except BaseException as restore_error:
                raise RuntimeOperationError("Nginx switch failed and old routing reload could not be confirmed") from restore_error
            raise RuntimeOperationError("Nginx switch failed; old routing was restored")
