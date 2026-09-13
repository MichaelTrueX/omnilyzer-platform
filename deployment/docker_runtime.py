"""Closed Docker/Compose implementation of the Task 014 DEV runtime boundary.

This module contains the closed runtime and concrete Docker Compose candidate
loopback probe. Nothing executes at import or construction time. Candidate
probing occurs only through explicit ``get()`` calls against exact Compose
services and ``127.0.0.1:8080`` inside the selected container, so candidate host
ports are neither required nor used. Other command argv, paths, service names,
and HTTP targets are likewise generated only from closed allowlists.
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
import types
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
_PROBE_SERVICES = {"blue": "canary-blue", "green": "canary-green"}
_PROBE_PATHS = frozenset({"/livez", "/readyz", "/metadata"})
_PROBE_ENVELOPE_MAX_BYTES = MAX_HTTP_RESPONSE * 2 + 64
_CANDIDATE_PROBE_SCRIPT = """import http.client
import json
import sys

def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("/livez", "/readyz", "/metadata"):
            return 1
        connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=2.0)
        connection.request(
            "GET", sys.argv[1],
            headers={"Accept": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        body = response.read(4097)
        status = response.status
        connection.close()
        if type(status) is not int or not 100 <= status <= 599 or len(body) > 4096:
            return 1
        envelope = {"body_hex": body.hex(), "status": status}
        sys.stdout.write(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\\n")
        return 0
    except Exception:
        return 1

raise SystemExit(main())
"""


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


def _candidate_command_run(runner: object):
    """Capture one exact ordinary CommandRunner method without invoking it."""

    if runner is None:
        raise TypeError("candidate probe configuration is invalid")
    try:
        hierarchy = type.__getattribute__(type(runner), "__mro__")
    except (AttributeError, TypeError):
        raise TypeError("candidate probe configuration is invalid") from None
    descriptor: object | None = None
    for base in hierarchy:
        namespace = type.__getattribute__(base, "__dict__")
        if "run" in namespace:
            descriptor = namespace["run"]
            break
    if type(descriptor) is not types.FunctionType:
        raise TypeError("candidate probe configuration is invalid")
    code = descriptor.__code__
    keyword_start = code.co_argcount
    keyword_end = keyword_start + code.co_kwonlyargcount
    if (
        code.co_posonlyargcount != 0
        or code.co_argcount != 2
        or tuple(code.co_varnames[1:2]) != ("argv",)
        or code.co_kwonlyargcount != 3
        or tuple(code.co_varnames[keyword_start:keyword_end])
        != ("cwd", "environment", "timeout")
        or code.co_flags & (0x04 | 0x08 | 0x20 | 0x80 | 0x100 | 0x200)
        or descriptor.__defaults__ is not None
        or descriptor.__kwdefaults__ is not None
    ):
        raise TypeError("candidate probe configuration is invalid")
    return types.MethodType(descriptor, runner)


class DockerComposeCandidateHttpClient:
    """Probe one exact candidate through fixed Docker Compose container exec."""

    __slots__ = ("_configuration",)

    def __init__(self, runner: CommandRunner, *, canary_image: str) -> None:
        """Capture a runner and exact image environment without executing them."""

        run = _candidate_command_run(runner)
        if type(canary_image) is not str:
            raise RuntimeOperationError("candidate probe configuration is invalid")
        image = validate_canary_image(canary_image)
        object.__setattr__(self, "_configuration", (
            run,
            {
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "CANARY_IMAGE": image,
            },
        ))

    def __setattr__(self, name: str, value: object) -> None:
        """Reject supported-API changes to the captured probe configuration."""

        raise AttributeError("candidate probe configuration is immutable")

    def __delattr__(self, name: str) -> None:
        """Reject supported-API deletion of captured probe configuration."""

        raise AttributeError("candidate probe configuration is immutable")

    def get(
        self, slot: str, path: str, *, timeout: float, max_bytes: int,
    ) -> tuple[int, bytes]:
        """Execute one bounded fixed-service same-container loopback probe."""

        if (
            type(slot) is not str
            or slot not in _PROBE_SERVICES
            or type(path) is not str
            or path not in _PROBE_PATHS
            or type(timeout) is not float
            or timeout != HTTP_TIMEOUT_SECONDS
            or type(max_bytes) is not int
            or max_bytes != MAX_HTTP_RESPONSE
        ):
            raise RuntimeOperationError("candidate probe failed")
        run, environment = object.__getattribute__(self, "_configuration")
        argv = (
            "docker", "compose", "--project-name", PROJECT,
            "--file", str(COMPOSE_FILE), "exec", "--no-TTY",
            _PROBE_SERVICES[slot], "/usr/bin/python", "-c",
            _CANDIDATE_PROBE_SCRIPT, path,
        )
        try:
            result = run(
                argv, cwd=WORKING_DIRECTORY,
                environment=dict(environment), timeout=HTTP_TIMEOUT_SECONDS,
            )
            if (
                type(result) is not CommandResult
                or type(result.returncode) is not int
                or result.returncode != 0
                or type(result.stdout) is not str
                or type(result.stderr) is not str
                or result.stderr != ""
            ):
                raise ValueError
            raw = result.stdout.encode("ascii")
            if not raw or len(raw) > _PROBE_ENVELOPE_MAX_BYTES:
                raise ValueError

            def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
                """Build the envelope object while rejecting duplicate fields."""

                value: dict[str, object] = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError
                    value[key] = item
                return value

            envelope = json.loads(
                result.stdout,
                object_pairs_hook=no_duplicates,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError),
            )
            if type(envelope) is not dict or set(envelope) != {"body_hex", "status"}:
                raise ValueError
            status = envelope["status"]
            body_hex = envelope["body_hex"]
            if (
                type(status) is not int
                or not 100 <= status <= 599
                or type(body_hex) is not str
                or len(body_hex) % 2 != 0
                or len(body_hex) > MAX_HTTP_RESPONSE * 2
                or re.fullmatch(r"[0-9a-f]*", body_hex) is None
            ):
                raise ValueError
            canonical = json.dumps(
                {"body_hex": body_hex, "status": status},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ) + "\n"
            if result.stdout != canonical:
                raise ValueError
            body = bytes.fromhex(body_hex)
            if len(body) > MAX_HTTP_RESPONSE:
                raise ValueError
            return status, body
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise RuntimeOperationError("candidate probe failed") from None


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
