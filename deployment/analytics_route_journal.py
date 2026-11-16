"""File: deployment/analytics_route_journal.py

Purpose: Durable, product-only Task14B Analytics private route-switch intent.
         Persist exact signed-release *references* before any 3141 mutation,
         and distinguish prepared, candidate_ready, switched, rollback_pending
         and restored outcomes on restart without trusting a partial stage
         or post-commit rollback attempt as a completed promotion.
Related: deployment/analytics_loopback_guard.py (same RootlessKit supervisor),
         deployment/analytics_active_state_review.py (live OCI observation),
         deployment/replay_sqlite.py (separate existing JTI replay authority),
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         deployment/tests/test_analytics_route_journal.py.

Security: This is a storage/consistency primitive, NEVER an approval of an
         image, OIDC principal, signature or deployment. A future owner-reviewed
         UID991 supervisor must provision its exact directory once, without
         modifying the existing 0.15.0 unit. No import-time I/O. The live
         installed unit is intentionally not wired to this new module.
"""
from __future__ import annotations

from contextlib import contextmanager
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import threading

from .policy import canonical_bytes


# Section 1: one product-specific durable journal, not a general state store.
ROUTE_JOURNAL_DIRECTORY = "/var/lib/omnilyzer/deployment/analytics-route"
_FILENAME = "transaction.json"
_TEMP = ".transaction.json.next"
_EXECUTIONS = "executions"
_IMAGE_PREFIX = "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 2048
_MAX_EXECUTION_PROOF_BYTES = 24 * 1024
_MAX_GENERATION = 2**63 - 1
_KEYS = frozenset({
    "schema_version", "phase", "generation", "request_sha256",
    "previous_slot", "previous_image", "previous_container_id",
    "previous_ip", "next_slot", "next_image", "next_container_id", "next_ip",
})
_PHASES = frozenset({"prepared", "candidate_ready", "switched", "rollback_pending", "restored"})
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_ERROR = "TASK014_ANALYTICS_ROUTE_JOURNAL_UNAVAILABLE"


class AnalyticsRouteJournalUnavailable(Exception):
    """One immutable identity or durable route-transition fact is uncertain."""


def _reject() -> None:
    """Produce no filesystem path, image, signature or user payload in errors."""
    raise AnalyticsRouteJournalUnavailable(_ERROR)


# Section 2: immutable transaction grammar and canonical file encoding.
def _route_record(raw: object) -> dict[str, object]:
    """Require one exact, bounded Analytics-to-Analytics route intent."""
    if type(raw) is not dict or set(raw) != _KEYS:
        _reject()
    record = dict(raw)
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != 1
        or record["phase"] not in _PHASES
        or type(record["generation"]) is not int
        or not 1 <= record["generation"] <= _MAX_GENERATION
        or type(record["request_sha256"]) is not str
        or _SHA.fullmatch(record["request_sha256"]) is None
        or record["request_sha256"] == "0" * 64
        or record["previous_slot"] not in ("blue", "green")
        or record["next_slot"] not in ("blue", "green")
        or record["previous_slot"] == record["next_slot"]
    ):
        _reject()
    for key in ("previous_image", "next_image"):
        value = record[key]
        if (
            type(value) is not str or not value.startswith(_IMAGE_PREFIX)
            or _SHA.fullmatch(value[len(_IMAGE_PREFIX):]) is None
            or value == _IMAGE_PREFIX + "0" * 64
        ):
            _reject()
    if record["previous_image"] == record["next_image"]:
        _reject()
    for key in ("previous_container_id", "next_container_id"):
        value = record[key]
        if type(value) is not str or _SHA.fullmatch(value) is None:
            _reject()
    if record["previous_container_id"] == record["next_container_id"]:
        _reject()
    for key in ("previous_ip", "next_ip"):
        value = record[key]
        try:
            address = ipaddress.ip_address(value)
        except (TypeError, ValueError):
            _reject()
        if (
            type(address) is not ipaddress.IPv4Address
            or str(address) != value or not address.is_private
            or address.is_loopback or address.is_link_local
            or address.is_reserved or address.is_multicast
        ):
            _reject()
    if record["previous_ip"] == record["next_ip"]:
        _reject()
    encoded = canonical_bytes(record)
    if type(encoded) is not bytes or len(encoded) > _MAX_BYTES:
        _reject()
    return record


def _decode(payload: bytes) -> dict[str, object]:
    """Refuse duplicate keys, nonfinite numbers and all noncanonical bytes."""
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        data: dict[str, object] = {}
        for name, value in pairs:
            if name in data:
                raise ValueError("duplicate journal key")
            data[name] = value
        return data

    try:
        if type(payload) is not bytes or not 0 < len(payload) <= _MAX_BYTES:
            _reject()
        result = json.loads(
            payload.decode("ascii"), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError),
        )
        verified = _route_record(result)
        if payload != canonical_bytes(verified):
            _reject()
        return verified
    except _CONTROL:
        raise
    except Exception:
        _reject()


def _execution_proof(payload: bytes, request_hash: str) -> dict[str, object]:
    """Decode request bytes; a FINISHED replay must authenticate them separately."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _reject()
            result[key] = value
        return result

    try:
        if (type(payload) is not bytes or not 0 < len(payload) <= _MAX_EXECUTION_PROOF_BYTES
                or type(request_hash) is not str or _SHA.fullmatch(request_hash) is None):
            _reject()
        proof = json.loads(payload.decode('ascii'), object_pairs_hook=unique)
        if (type(proof) is not dict or set(proof) != {
                'schema_version', 'request_base64', 'container_id'}
                or type(proof['schema_version']) is not int or proof['schema_version'] != 1
                or type(proof['container_id']) is not str
                or _SHA.fullmatch(proof['container_id']) is None
                or type(proof['request_base64']) is not str
                or canonical_bytes(proof) != payload):
            _reject()
        raw = base64.b64decode(proof['request_base64'], validate=True)
        if (not 0 < len(raw) <= 16 * 1024
                or base64.b64encode(raw).decode('ascii') != proof['request_base64']
                or hashlib.sha256(raw).hexdigest() != request_hash):
            _reject()
        request = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
        if (type(request) is not dict or canonical_bytes(request) != raw
                or type(request.get('schema_version')) is not int
                or request['schema_version'] != 3
                or request.get('product_id') != 'analytics' or request.get('stage') != 'dev'
                or type(request.get('manifest_digest')) is not str
                or not request['manifest_digest'].startswith('sha256:')
                or _SHA.fullmatch(request['manifest_digest'][7:]) is None
                or request.get('exact_image_reference') !=
                    _IMAGE_PREFIX + request['manifest_digest'][7:]):
            _reject()
        return {'canonical_request': raw, 'container_id': proof['container_id'],
                'image': request['exact_image_reference']}
    except _CONTROL:
        raise
    except Exception:
        _reject()


# Section 3: exact directory/file identities and atomic file publication.
class AnalyticsRouteJournal:
    """One exclusively owned UID991 route journal; no application secrets."""

    __slots__ = ("_directory", "_uid", "_gid", "_locked_fd", "_locked_thread")

    def __init__(
        self,
        directory: str = ROUTE_JOURNAL_DIRECTORY, *,
        expected_uid: int = 991, expected_gid: int = 991,
    ) -> None:
        """Capture a fixed production path; tests use an isolated directory."""
        if (
            type(directory) is not str or not directory.startswith("/")
            or directory.startswith("//") or "\x00" in directory
            or any(part in ("", ".", "..") for part in directory[1:].split("/"))
            or type(expected_uid) is not int or expected_uid < 1
            or type(expected_gid) is not int or expected_gid < 1
        ):
            raise TypeError(_ERROR)
        object.__setattr__(self, "_directory", directory)
        object.__setattr__(self, "_uid", expected_uid)
        object.__setattr__(self, "_gid", expected_gid)
        object.__setattr__(self, "_locked_fd", None)
        object.__setattr__(self, "_locked_thread", None)

    def __setattr__(self, key: str, value: object) -> None:
        """Prevent path or owner substitution after creation."""
        raise AttributeError("Analytics route journal is immutable")

    def _open_dir(self) -> int:
        """Open only existing, nonsymlink, owner-matched mode0700 directory."""
        descriptor = os.open(
            object.__getattribute__(self, "_directory"),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != object.__getattribute__(self, "_uid")
            or info.st_gid != object.__getattribute__(self, "_gid")
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            os.close(descriptor)
            _reject()
        return descriptor

    @contextmanager
    def exclusive(self):
        """Hold a nonblocking kernel lock across intent, port change and result.

        A second process cannot begin or recover an overlapping switch.
        This is operation serialization, NOT a signing/deployment grant.
        """
        if object.__getattribute__(self, "_locked_fd") is not None:
            _reject()
        descriptor = None
        try:
            descriptor = self._open_dir()
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except _CONTROL:
            raise
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            _reject()
        object.__setattr__(self, "_locked_fd", descriptor)
        object.__setattr__(self, "_locked_thread", threading.get_ident())
        try:
            yield self
        finally:
            object.__setattr__(self, "_locked_thread", None)
            object.__setattr__(self, "_locked_fd", None)
            os.close(descriptor)

    def exclusive_active(self) -> bool:
        """Report whether this object owns the still-open operation lock."""
        return (
            object.__getattribute__(self, "_locked_fd") is not None
            and object.__getattribute__(self, "_locked_thread")
                == threading.get_ident()
        )

    def _write_handle(self) -> tuple[int, bool]:
        """Obtain a lock for a single write unless already in a transaction."""
        active = object.__getattribute__(self, "_locked_fd")
        if active is not None:
            if object.__getattribute__(self, "_locked_thread") != threading.get_ident():
                _reject()
            return active, False
        descriptor = self._open_dir()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor, True
        except Exception:
            os.close(descriptor)
            raise

    def _read_at(self, directory_fd: int) -> dict[str, object] | None:
        """Read only a regular, single-link 0600 journal, refusing residue."""
        entries = set(os.listdir(directory_fd))
        if not entries:
            return None
        if entries not in ({_FILENAME}, {_FILENAME, _EXECUTIONS}):
            _reject()
        if _EXECUTIONS in entries:
            # Execution evidence has its own fixed, private namespace. It
            # must not turn a completed transaction into unexpected residue.
            proofs = self._open_executions(directory_fd)
            os.close(proofs)
        handle = os.open(
            _FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        try:
            metadata = os.fstat(handle)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != object.__getattribute__(self, "_uid")
                or metadata.st_gid != object.__getattribute__(self, "_gid")
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or not 0 < metadata.st_size <= _MAX_BYTES
            ):
                _reject()
            payload = os.read(handle, _MAX_BYTES + 1)
            if len(payload) != metadata.st_size:
                _reject()
            result = _decode(payload)
            new_meta = os.fstat(handle)
            if (
                (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns,
                 metadata.st_ctime_ns, metadata.st_size)
                !=
                (new_meta.st_dev, new_meta.st_ino, new_meta.st_mtime_ns,
                 new_meta.st_ctime_ns, new_meta.st_size)
            ):
                _reject()
            return result
        finally:
            os.close(handle)

    def read(self) -> dict[str, object] | None:
        """Return a verified record, or None only for a genuinely empty store."""
        try:
            directory_fd = self._open_dir()
            try:
                return self._read_at(directory_fd)
            finally:
                os.close(directory_fd)
        except _CONTROL:
            raise
        except Exception:
            _reject()

    def record_execution(self, canonical_request: bytes, container_id: str) -> None:
        """Persist verified coordinator inputs BEFORE replay.finish_execution.

        Not approval by itself. The coordinator supplies the independently
        verified canonical signed request and actual staged container ID, never
        copies an image from the route journal. A later reader must match the
        request hash to the protected FINISHED replay before adopting anything.
        Immutable per-request files preserve partial/failed execution evidence.
        """
        try:
            if type(canonical_request) is not bytes:
                _reject()
            request_hash = hashlib.sha256(canonical_request).hexdigest()
            payload = canonical_bytes({'schema_version': 1,
                'request_base64': base64.b64encode(canonical_request).decode('ascii'),
                'container_id': container_id})
            proof = _execution_proof(payload, request_hash)
            with self.exclusive():
                intent = self.read()
                if (type(intent) is not dict or intent.get('phase') != 'switched'
                        or intent.get('request_sha256') != request_hash
                        or intent.get('next_image') != proof['image']
                        or intent.get('next_container_id') != container_id):
                    _reject()
                directory = object.__getattribute__(self, '_locked_fd')
                try:
                    os.mkdir(_EXECUTIONS, 0o700, dir_fd=directory)
                except FileExistsError:
                    pass
                proofs = self._open_executions(directory)
                try:
                    fd = os.open('execution-' + request_hash + '.json',
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=proofs)
                    try:
                        st = os.fstat(fd)
                        if (st.st_uid != object.__getattribute__(self, '_uid')
                                or st.st_gid != object.__getattribute__(self, '_gid')
                                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
                            _reject()
                        with os.fdopen(os.dup(fd), 'wb') as handle:
                            handle.write(payload)
                            handle.flush()
                        os.fsync(fd)
                        os.fsync(proofs)
                        os.fsync(directory)
                    finally:
                        os.close(fd)
                finally:
                    os.close(proofs)
                if self.read_execution(request_hash) != proof:
                    _reject()
        except _CONTROL:
            raise
        except Exception:
            _reject()

    def _open_executions(self, directory: int) -> int:
        """Open the fixed private proof directory without following links."""
        descriptor = os.open(_EXECUTIONS,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            named = os.stat(_EXECUTIONS, dir_fd=directory, follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != object.__getattribute__(self, '_uid')
                    or info.st_gid != object.__getattribute__(self, '_gid')
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                _reject()
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def read_execution(self, request_hash: str) -> dict[str, object]:
        """Read one exact protected proof; legacy/missing proof is HOLD."""
        directory = proofs = descriptor = None
        try:
            if type(request_hash) is not str or _SHA.fullmatch(request_hash) is None:
                _reject()
            name = 'execution-' + request_hash + '.json'
            directory = self._open_dir()
            proofs = self._open_executions(directory)
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                | os.O_CLOEXEC, dir_fd=proofs)
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_uid != object.__getattribute__(self, '_uid')
                    or opened.st_gid != object.__getattribute__(self, '_gid')
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or not 0 < opened.st_size <= _MAX_EXECUTION_PROOF_BYTES):
                _reject()
            with os.fdopen(os.dup(descriptor), 'rb') as handle:
                payload = handle.read(_MAX_EXECUTION_PROOF_BYTES + 1)
            def identity(st):
                return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                        st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            if (len(payload) != opened.st_size
                    or identity(os.fstat(descriptor)) != identity(opened)
                    or identity(os.stat(name, dir_fd=proofs, follow_symlinks=False))
                        != identity(opened)):
                _reject()
            current = os.stat(_EXECUTIONS, dir_fd=directory, follow_symlinks=False)
            opened_directory = os.fstat(proofs)
            if ((current.st_dev, current.st_ino)
                    != (opened_directory.st_dev, opened_directory.st_ino)):
                _reject()
            return _execution_proof(payload, request_hash)
        except _CONTROL:
            raise
        except Exception:
            _reject()
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if proofs is not None:
                os.close(proofs)
            if directory is not None:
                os.close(directory)

    def _replace_at(self, directory_fd: int, new: dict[str, object]) -> None:
        """Write/fsync private temp, atomic rename and fsync enclosing dir."""
        encoded = canonical_bytes(_route_record(new))
        if _TEMP in os.listdir(directory_fd):
            _reject()
        descriptor = os.open(
            _TEMP, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=directory_fd,
        )
        try:
            if os.fstat(descriptor).st_uid != object.__getattribute__(self, "_uid"):
                _reject()
            with os.fdopen(os.dup(descriptor), "wb", closefd=True) as handle:
                handle.write(encoded)
                handle.flush()
            os.fsync(descriptor)
            os.replace(
                _TEMP, _FILENAME, src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            os.close(descriptor)
        if self._read_at(directory_fd) != new:
            _reject()

    def begin(
        self, *, request_sha256: str,
        previous_slot: str, previous_image: str,
        previous_container_id: str, previous_ip: str,
        next_slot: str, next_image: str,
        next_container_id: str, next_ip: str,
    ) -> dict[str, object]:
        """Persist PREPARED before mutating 3142 or 3141; forbid unresolved attempts."""
        try:
            directory_fd, close_when_done = self._write_handle()
            try:
                existing = self._read_at(directory_fd)
                if existing is not None:
                    if existing["phase"] in ("prepared", "candidate_ready", "rollback_pending"):
                        _reject()
                    if existing["phase"] == "switched":
                        if (
                            existing["next_slot"] != previous_slot
                            or existing["next_image"] != previous_image
                            or existing["next_container_id"] != previous_container_id
                        ):
                            _reject()
                    else:
                        if (
                            existing["previous_slot"] != previous_slot
                            or existing["previous_image"] != previous_image
                            or existing["previous_container_id"]
                            != previous_container_id
                        ):
                            _reject()
                generation = 1 if existing is None else existing["generation"] + 1
                record = _route_record({
                    "schema_version": 1, "phase": "prepared",
                    "generation": generation, "request_sha256": request_sha256,
                    "previous_slot": previous_slot,
                    "previous_image": previous_image,
                    "previous_container_id": previous_container_id,
                    "previous_ip": previous_ip, "next_slot": next_slot,
                    "next_image": next_image,
                    "next_container_id": next_container_id,
                    "next_ip": next_ip,
                })
                self._replace_at(directory_fd, record)
                return record
            finally:
                if close_when_done:
                    os.close(directory_fd)
        except _CONTROL:
            raise
        except Exception:
            _reject()

    def finish(
        self, record: dict[str, object], *, phase: str,
    ) -> dict[str, object]:
        """Durably record health, switch, rollback intent or restoration.

        A finished switch can only be rolled back after first recording a
        separate fsync-protected rollback_pending intent. A failed process
        can never clear that intent merely by creating a new release.
        This storage primitive does not authorize an operation or a signer.
        """
        try:
            if phase not in ("candidate_ready", "switched", "rollback_pending", "restored"):
                _reject()
            previous = _route_record(record)
            if not (
                (previous["phase"] == "prepared"
                 and phase in ("candidate_ready", "restored"))
                or (previous["phase"] == "candidate_ready"
                    and phase in ("switched", "restored"))
                or (previous["phase"] == "switched"
                    and phase == "rollback_pending")
                or (previous["phase"] == "rollback_pending"
                    and phase == "restored")
            ):
                _reject()
            directory_fd, close_when_done = self._write_handle()
            try:
                current = self._read_at(directory_fd)
                if current != previous:
                    _reject()
                done = {**previous, "phase": phase}
                self._replace_at(directory_fd, done)
                return done
            finally:
                if close_when_done:
                    os.close(directory_fd)
        except _CONTROL:
            raise
        except Exception:
            _reject()


__all__ = (
    "ROUTE_JOURNAL_DIRECTORY", "AnalyticsRouteJournal",
    "AnalyticsRouteJournalUnavailable",
)
