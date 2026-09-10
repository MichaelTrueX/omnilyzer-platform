"""Inert, constructor-bound privileged executor orchestration core.

This module performs no installation, I/O, runtime discovery, audit emission,
or deployment by itself.  A later separately reviewed composition must supply
both collaborators and process isolation around this Python boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import threading
import types
from typing import Any, Callable, Protocol

from .broker import MAX_EXECUTOR_RESPONSE_BYTES
from .execution import (
    MAX_CANONICAL_REQUEST_BYTES,
    ExecutorRequest,
    ExecutorRequestError,
    parse_canonical_request,
)
from .identity import ReplayError, ReplayUnavailableError
from .policy import canonical_bytes


EXECUTOR_RESPONSE_SCHEMA_VERSION = 1
EXECUTOR_RESPONSE_FIELDS = frozenset({
    "executor_request_sha256", "schema_version", "status",
})
EXECUTOR_REJECTED_MESSAGE = "executor request is not accepted"
EXECUTOR_UNAVAILABLE_MESSAGE = "executor is unavailable"
_JTI_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_MAX_IDENTIFIER = 2**63 - 1


def _make_execution_gate() -> tuple[
    Callable[[object], bool], Callable[[object], None],
]:
    active: set[int] = set()
    lock = threading.Lock()

    def enter(instance: object) -> bool:
        identity = id(instance)
        with lock:
            if identity in active:
                return False
            active.add(identity)
            return True

    def leave(instance: object) -> None:
        with lock:
            active.remove(id(instance))

    return enter, leave


_ENTER_EXECUTION, _LEAVE_EXECUTION = _make_execution_gate()


class ExecutorRejectedError(Exception):
    """The request or its consumed replay record is definitely rejected."""


class ExecutorUnavailableError(Exception):
    """The executor cannot report a trustworthy completed result."""


class DeploymentOperation(Protocol):
    """One closed deployment operation supplied by later composition."""

    def deploy(self, request: ExecutorRequest) -> None:
        ...


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _ordinary_bound_method(
    dependency: object, name: str, *, positional: tuple[str, ...],
    keyword_only: tuple[str, ...] = (),
) -> Callable[..., Any]:
    """Bind a plain function without invoking a property or descriptor."""

    if dependency is None:
        raise TypeError("executor collaborator is invalid")
    cls = type(dependency)
    try:
        hierarchy = type.__getattribute__(cls, "__mro__")
    except (AttributeError, TypeError):
        raise TypeError("executor collaborator is invalid") from None
    descriptor: object | None = None
    for base in hierarchy:
        namespace = type.__getattribute__(base, "__dict__")
        if name in namespace:
            descriptor = namespace[name]
            break
    if type(descriptor) is not types.FunctionType:
        raise TypeError("executor collaborator is invalid")
    code = descriptor.__code__
    names = code.co_varnames
    disallowed_flags = 0x04 | 0x08 | 0x20 | 0x80 | 0x100 | 0x200
    if (
        code.co_posonlyargcount != 0
        or code.co_argcount != len(positional) + 1
        or code.co_kwonlyargcount != len(keyword_only)
        or tuple(names[1:code.co_argcount]) != positional
        or tuple(
            names[code.co_argcount:code.co_argcount + code.co_kwonlyargcount]
        ) != keyword_only
        or code.co_flags & disallowed_flags
        or descriptor.__defaults__ is not None
        or descriptor.__kwdefaults__ is not None
    ):
        raise TypeError("executor collaborator is invalid")
    return types.MethodType(descriptor, dependency)


@dataclass(frozen=True)
class ExecutorResponse:
    """Closed schema-version-1 executor result."""

    executor_request_sha256: str
    schema_version: int = EXECUTOR_RESPONSE_SCHEMA_VERSION
    status: str = "succeeded"

    @classmethod
    def from_dict(cls, value: Any) -> "ExecutorResponse":
        if cls is not ExecutorResponse or type(value) is not dict:
            raise ValueError("executor response is invalid")
        if (
            len(value) != len(EXECUTOR_RESPONSE_FIELDS)
            or not all(type(key) is str for key in value)
            or set(value) != EXECUTOR_RESPONSE_FIELDS
            or type(value["schema_version"]) is not int
            or value["schema_version"] != EXECUTOR_RESPONSE_SCHEMA_VERSION
            or type(value["status"]) is not str
            or value["status"] != "succeeded"
            or not _valid_sha256(value["executor_request_sha256"])
        ):
            raise ValueError("executor response is invalid")
        return cls(value["executor_request_sha256"])

    def to_dict(self) -> dict[str, object]:
        if (
            type(self) is not ExecutorResponse
            or not _valid_sha256(self.executor_request_sha256)
            or type(self.schema_version) is not int
            or self.schema_version != EXECUTOR_RESPONSE_SCHEMA_VERSION
            or type(self.status) is not str
            or self.status != "succeeded"
        ):
            raise ValueError("executor response is invalid")
        return {
            "executor_request_sha256": self.executor_request_sha256,
            "schema_version": self.schema_version,
            "status": self.status,
        }

    def canonical_bytes(self) -> bytes:
        encoded = canonical_bytes(self.to_dict())
        if not encoded or len(encoded) > MAX_EXECUTOR_RESPONSE_BYTES:
            raise ValueError("executor response is invalid")
        return encoded


def _build_success_response(
    request_hash: str,
) -> bytes:
    return (
        b'{"executor_request_sha256":"' + request_hash.encode("ascii")
        + b'","schema_version":1,"status":"succeeded"}\n'
    )


def parse_canonical_response(raw: bytes) -> ExecutorResponse:
    """Strictly parse exact canonical executor-response bytes."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_EXECUTOR_RESPONSE_BYTES:
        raise ValueError("executor response is invalid")
    try:
        text = raw.decode("ascii")

        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("executor response is invalid")
                value[key] = item
            return value

        decoded = json.loads(text, object_pairs_hook=no_duplicates)
        response = ExecutorResponse.from_dict(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ValueError("executor response is invalid") from None
    if response.canonical_bytes() != raw:
        raise ValueError("executor response is invalid")
    return response


class RestrictedPrivilegedExecutor:
    """Reparse, transition replay, and invoke one fixed deployment operation."""

    __slots__ = ("_operations",)

    def __init__(self, *, replay_guard: object, operation: object) -> None:
        operations = (
            _ordinary_bound_method(
                replay_guard, "begin_execution", positional=("jti",),
                keyword_only=("request_hash", "run_id", "run_attempt"),
            ),
            _ordinary_bound_method(operation, "deploy", positional=("request",)),
            _ordinary_bound_method(
                replay_guard, "finish_execution", positional=("jti",),
                keyword_only=("request_hash", "run_id", "run_attempt"),
            ),
            _build_success_response,
        )
        object.__setattr__(self, "_operations", operations)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("executor collaborators are immutable")

    def execute(self, canonical_request: bytes) -> bytes:
        if (
            type(canonical_request) is not bytes
            or not canonical_request
            or len(canonical_request) > MAX_CANONICAL_REQUEST_BYTES
        ):
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None

        begin_execution, deploy, finish_execution, build_success_response = (
            object.__getattribute__(self, "_operations")
        )
        parse_request = parse_canonical_request
        sha256 = hashlib.sha256

        try:
            request = parse_request(canonical_request)
            if type(request) is not ExecutorRequest:
                raise ExecutorRequestError("executor request type is invalid")
        except ExecutorRequestError:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        except Exception:
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

        try:
            request_hash = sha256(canonical_request).hexdigest()
        except Exception:
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
        if not _valid_sha256(request_hash):
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

        try:
            fields = object.__getattribute__(request, "__dict__")
            if type(fields) is not dict:
                raise TypeError("executor request fields are unavailable")
            snapshot = dict.copy(fields)
            oidc_jti = snapshot["oidc_jti"]
            run_id = snapshot["github_run_id"]
            run_attempt = snapshot["github_run_attempt"]
            if (
                type(oidc_jti) is not str
                or _JTI_RE.fullmatch(oidc_jti) is None
                or ".." in oidc_jti
                or type(run_id) is not int
                or not 1 <= run_id <= _MAX_IDENTIFIER
                or type(run_attempt) is not int
                or not 1 <= run_attempt <= _MAX_IDENTIFIER
            ):
                raise TypeError("executor replay binding is invalid")
        except Exception:
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

        enter_execution = _ENTER_EXECUTION
        leave_execution = _LEAVE_EXECUTION
        if not enter_execution(self):
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
        try:
            try:
                begin_result = begin_execution(
                    oidc_jti,
                    request_hash=request_hash,
                    run_id=run_id,
                    run_attempt=run_attempt,
                )
            except ReplayUnavailableError:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            except ReplayError:
                raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
            except Exception:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            if begin_result is not None:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

            try:
                operation_result = deploy(request)
            except Exception:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            if operation_result is not None:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

            try:
                finish_result = finish_execution(
                    oidc_jti,
                    request_hash=request_hash,
                    run_id=run_id,
                    run_attempt=run_attempt,
                )
            except Exception:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            if finish_result is not None:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

            try:
                response = build_success_response(request_hash)
            except Exception:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            if type(response) is not bytes or len(response) > MAX_EXECUTOR_RESPONSE_BYTES:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            return response
        finally:
            leave_execution(self)


__all__ = (
    "DeploymentOperation",
    "EXECUTOR_RESPONSE_SCHEMA_VERSION",
    "ExecutorRejectedError",
    "ExecutorResponse",
    "ExecutorUnavailableError",
    "RestrictedPrivilegedExecutor",
    "parse_canonical_response",
)
