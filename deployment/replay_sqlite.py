"""Bounded durable SQLite replay state; inert until explicitly initialized and used."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Callable

from .identity import (
    MAX_CLOCK_SKEW_SECONDS,
    MAX_DECIMAL_IDENTIFIER,
    OIDCAuthorizationError,
    ReplayError,
    ReplayUnavailableError,
    validate_jti,
)


PRODUCTION_REPLAY_DATABASE = Path(
    "/var/lib/omnilyzer/deployment/authority/replay.sqlite3"
)
REPLAY_FILENAME = "replay.sqlite3"
DIRECTORY_MODE = 0o770
DATABASE_MODE = 0o660
DATABASE_SIZE_LIMIT = 16 * 1024 * 1024
JOURNAL_SIZE_LIMIT = 17 * 1024 * 1024
PAGE_SIZE = 4096
MAX_PAGE_COUNT = DATABASE_SIZE_LIMIT // PAGE_SIZE
DEFAULT_MAXIMUM_ENTRIES = 10_000
DEFAULT_BUSY_TIMEOUT_MS = 1_000
MAXIMUM_ENTRIES = 10_000
MAXIMUM_BUSY_TIMEOUT_MS = 1_000
SQLITE_INTEGER_MAX = 2**63 - 1
MAX_UID_GID = 2**32 - 2
APPLICATION_ID = 0x4F4D4E52
USER_VERSION = 1

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_STATUSES = frozenset({"consumed", "executing", "finished"})
_GENERIC_UNAVAILABLE = "replay storage is unavailable"
_GENERIC_REPLAY = "replay request is not accepted"

METADATA_SQL = """CREATE TABLE metadata(
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    last_seen_epoch INTEGER NOT NULL CHECK(last_seen_epoch >= 0 AND last_seen_epoch <= 9223372036854775807)
)"""

CONSUMPTIONS_SQL = """CREATE TABLE consumptions(
    jti TEXT PRIMARY KEY
        CHECK(length(jti) BETWEEN 1 AND 128)
        CHECK(substr(jti, 1, 1) GLOB '[A-Za-z0-9]')
        CHECK(jti NOT GLOB '*[^A-Za-z0-9._:@-]*')
        CHECK(instr(jti, '..') = 0),
    retain_until INTEGER NOT NULL
        CHECK(retain_until >= 0 AND retain_until <= 9223372036854775807),
    executor_request_sha256 TEXT NOT NULL
        CHECK(length(executor_request_sha256) = 64)
        CHECK(executor_request_sha256 NOT GLOB '*[^0-9a-f]*'),
    github_run_id INTEGER NOT NULL
        CHECK(github_run_id BETWEEN 1 AND 9223372036854775807),
    github_run_attempt INTEGER NOT NULL
        CHECK(github_run_attempt BETWEEN 1 AND 9223372036854775807),
    status TEXT NOT NULL
        CHECK(status IN ('consumed', 'executing', 'finished')),
    UNIQUE(github_run_id, github_run_attempt)
)"""

EXPIRY_INDEX_SQL = (
    "CREATE INDEX replay_expiry_idx ON consumptions(retain_until, jti)"
)


@dataclass(frozen=True)
class _Binding:
    jti: str
    retain_until: int | None
    request_hash: str
    run_id: int
    run_attempt: int


def _integer(value: object, *, positive: bool) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
    minimum = 1 if positive else 0
    maximum = MAX_DECIMAL_IDENTIFIER if positive else SQLITE_INTEGER_MAX
    if not minimum <= value <= maximum:
        raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
    return value


def _binding(
    jti: object, *, expires_at: object | None, request_hash: object,
    run_id: object, run_attempt: object,
) -> _Binding:
    try:
        safe_jti = validate_jti(jti)
    except OIDCAuthorizationError:
        raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None
    if not isinstance(request_hash, str) or _HASH.fullmatch(request_hash) is None:
        raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
    safe_run_id = _integer(run_id, positive=True)
    safe_attempt = _integer(run_attempt, positive=True)
    retain_until = None
    if expires_at is not None:
        expiry = _integer(expires_at, positive=False)
        if expiry > SQLITE_INTEGER_MAX - MAX_CLOCK_SKEW_SECONDS:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        retain_until = expiry + MAX_CLOCK_SKEW_SECONDS
    return _Binding(
        safe_jti, retain_until, request_hash, safe_run_id, safe_attempt,
    )


def _normalize_sql(value: str | None) -> str:
    if value is None:
        return ""
    return " ".join(value.split())


class SQLiteReplayGuard:
    """Closed durable implementation of the existing ReplayGuard protocol."""

    def __init__(
        self,
        database_path: Path | str,
        *,
        expected_directory_uid: int,
        expected_directory_gid: int,
        maximum_entries: int = DEFAULT_MAXIMUM_ENTRIES,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        current_time: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        try:
            raw_path = os.fspath(database_path)
        except TypeError:
            raise ValueError("replay configuration is invalid") from None
        if not isinstance(raw_path, str):
            raise ValueError("replay configuration is invalid")
        path = Path(raw_path)
        if (
            not path.is_absolute() or path.name != REPLAY_FILENAME
            or str(path) != raw_path
            or raw_path.startswith("//") or "\x00" in raw_path
            or any(part in {".", ".."} for part in raw_path.split("/"))
        ):
            raise ValueError("replay configuration is invalid")
        for value in (expected_directory_uid, expected_directory_gid):
            if (
                isinstance(value, bool) or not isinstance(value, int)
                or not 0 <= value <= MAX_UID_GID
            ):
                raise ValueError("replay configuration is invalid")
        if (
            isinstance(maximum_entries, bool) or not isinstance(maximum_entries, int)
            or not 1 <= maximum_entries <= MAXIMUM_ENTRIES
        ):
            raise ValueError("replay configuration is invalid")
        if (
            isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= MAXIMUM_BUSY_TIMEOUT_MS
        ):
            raise ValueError("replay configuration is invalid")
        if not callable(current_time):
            raise ValueError("replay configuration is invalid")
        self._path = path
        self._directory = path.parent
        self._uid = expected_directory_uid
        self._gid = expected_directory_gid
        self._maximum_entries = maximum_entries
        self._busy_timeout_ms = busy_timeout_ms
        self._current_time = current_time

    def initialize(self) -> None:
        """Explicitly create the database in an already secured empty directory."""

        now = self._sample_clock()
        directory_descriptor: int | None = None
        descriptor: int | None = None
        connection: sqlite3.Connection | None = None
        created_identity: tuple[int, int] | None = None
        directory_identity: tuple[int, int] | None = None
        uncertain = False
        try:
            directory_descriptor = self._open_directory()
            directory_status = os.fstat(directory_descriptor)
            directory_identity = (directory_status.st_dev, directory_status.st_ino)
            self._validate_directory_descriptor(
                directory_descriptor, expected_entries=frozenset(),
            )
            descriptor = os.open(
                REPLAY_FILENAME,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                DATABASE_MODE,
                dir_fd=directory_descriptor,
            )
            os.fchmod(descriptor, DATABASE_MODE)
            file_status = os.fstat(descriptor)
            created_identity = (file_status.st_dev, file_status.st_ino)
            self._validate_file_status(file_status, DATABASE_MODE)
            self._validate_bound_file(directory_descriptor, descriptor)
            connection = self._connect(directory_descriptor)
            self._validate_bound_file(directory_descriptor, descriptor)
            self._configure_initial(connection)
            connection.execute("BEGIN IMMEDIATE")
            self._validate_bound_file(directory_descriptor, descriptor)
            connection.execute(METADATA_SQL)
            connection.execute(CONSUMPTIONS_SQL)
            connection.execute(EXPIRY_INDEX_SQL)
            connection.execute(
                "INSERT INTO metadata(singleton, schema_version, last_seen_epoch) VALUES(1, ?, ?)",
                (USER_VERSION, now),
            )
            connection.execute("COMMIT")
            self._validate_open_store(connection)
            connection.close()
            connection = None
            os.fsync(descriptor)
            self._validate_bound_file(directory_descriptor, descriptor)
            os.fsync(directory_descriptor)
            self._validate_filesystem(directory_descriptor)
        except Exception:
            uncertain = True
        finally:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except Exception:
                    uncertain = True
                try:
                    connection.close()
                except Exception:
                    uncertain = True
            if uncertain and descriptor is not None and directory_descriptor is not None:
                self._quarantine_failed_initialization(
                    directory_descriptor, descriptor, created_identity,
                )
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except Exception:
                    uncertain = True
                    self._poison_descriptor(descriptor)
                    if directory_descriptor is not None:
                        self._quarantine_named_initialization(
                            directory_descriptor, created_identity,
                        )
            if directory_descriptor is not None:
                try:
                    os.close(directory_descriptor)
                except Exception:
                    uncertain = True
                    replacement: int | None = None
                    try:
                        replacement = self._open_directory()
                        replacement_status = os.fstat(replacement)
                        if directory_identity == (
                            replacement_status.st_dev, replacement_status.st_ino,
                        ):
                            self._quarantine_named_initialization(
                                replacement, created_identity,
                            )
                    except Exception:
                        pass
                    finally:
                        if replacement is not None:
                            try:
                                os.close(replacement)
                            except Exception:
                                pass
        if uncertain:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None

    def consume(
        self, jti: str, *, expires_at: int, request_hash: str,
        run_id: int, run_attempt: int,
    ) -> None:
        binding = _binding(
            jti, expires_at=expires_at, request_hash=request_hash,
            run_id=run_id, run_attempt=run_attempt,
        )

        def mutate(connection: sqlite3.Connection, effective_time: int) -> None:
            assert binding.retain_until is not None
            connection.execute(
                "DELETE FROM consumptions WHERE jti IN ("
                "SELECT jti FROM consumptions "
                "WHERE retain_until < ? AND status IN ('consumed', 'finished') "
                "ORDER BY retain_until, jti LIMIT ?)",
                (effective_time, MAXIMUM_ENTRIES),
            )
            count = connection.execute(
                "SELECT count(*) FROM consumptions"
            ).fetchone()
            if count is None or count[0] >= self._maximum_entries:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
            if binding.retain_until < effective_time:
                raise ReplayError(_GENERIC_REPLAY)
            try:
                connection.execute(
                    "INSERT INTO consumptions("
                    "jti, retain_until, executor_request_sha256, github_run_id, "
                    "github_run_attempt, status) VALUES(?, ?, ?, ?, ?, 'consumed')",
                    (
                        binding.jti, binding.retain_until, binding.request_hash,
                        binding.run_id, binding.run_attempt,
                    ),
                )
            except sqlite3.IntegrityError as error:
                if self._is_proven_replay_conflict(connection, binding, error):
                    raise ReplayError(_GENERIC_REPLAY) from None
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None

        self._mutate(mutate)

    def begin_execution(
        self, jti: str, *, request_hash: str, run_id: int, run_attempt: int,
    ) -> None:
        binding = _binding(
            jti, expires_at=None, request_hash=request_hash,
            run_id=run_id, run_attempt=run_attempt,
        )
        self._transition(binding, "consumed", "executing")

    def finish_execution(
        self, jti: str, *, request_hash: str, run_id: int, run_attempt: int,
    ) -> None:
        binding = _binding(
            jti, expires_at=None, request_hash=request_hash,
            run_id=run_id, run_attempt=run_attempt,
        )
        self._transition(binding, "executing", "finished")

    def _transition(self, binding: _Binding, before: str, after: str) -> None:
        def mutate(connection: sqlite3.Connection, effective_time: int) -> None:
            expiry_clause = ""
            parameters: tuple[object, ...] = (
                after, binding.jti, binding.request_hash, binding.run_id,
                binding.run_attempt, before,
            )
            if before == "consumed":
                expiry_clause = " AND retain_until >= ?"
                parameters += (effective_time,)
            cursor = connection.execute(
                "UPDATE consumptions SET status = ? "
                "WHERE jti = ? AND executor_request_sha256 = ? "
                "AND github_run_id = ? AND github_run_attempt = ? AND status = ?"
                + expiry_clause,
                parameters,
            )
            if cursor.rowcount != 1:
                raise ReplayError(_GENERIC_REPLAY)

        self._mutate(mutate)

    def _sample_clock(self) -> int:
        try:
            value = self._current_time()
        except Exception:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None
        return _integer(value, positive=False)

    def _mutate(
        self, operation: Callable[[sqlite3.Connection, int], None],
    ) -> None:
        now = self._sample_clock()
        directory_descriptor: int | None = None
        database_descriptor: int | None = None
        connection: sqlite3.Connection | None = None
        transaction = False
        replay_error: ReplayError | None = None
        unavailable = False
        try:
            directory_descriptor = self._open_directory()
            self._validate_filesystem(directory_descriptor)
            database_descriptor = os.open(
                REPLAY_FILENAME, os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
            self._validate_bound_file(directory_descriptor, database_descriptor)
            connection = self._connect(directory_descriptor)
            self._validate_bound_file(directory_descriptor, database_descriptor)
            self._configure_existing(connection)
            connection.execute("BEGIN IMMEDIATE")
            transaction = True
            self._validate_bound_file(directory_descriptor, database_descriptor)
            self._validate_filesystem(directory_descriptor)
            self._validate_open_store(connection)
            effective_time = self._advance_clock(connection, now)
            operation(connection, effective_time)
            connection.execute("COMMIT")
            transaction = False
            self._validate_bound_file(directory_descriptor, database_descriptor)
        except ReplayUnavailableError:
            unavailable = True
        except ReplayError as error:
            replay_error = error
        except Exception:
            unavailable = True
        finally:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                    transaction = False
                except Exception:
                    unavailable = True
                    replay_error = None
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    unavailable = True
                    replay_error = None
            if database_descriptor is not None:
                try:
                    os.close(database_descriptor)
                except Exception:
                    unavailable = True
                    replay_error = None
            try:
                if directory_descriptor is None:
                    raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
                self._validate_filesystem(directory_descriptor)
            except Exception:
                unavailable = True
                replay_error = None
            if directory_descriptor is not None:
                try:
                    os.close(directory_descriptor)
                except Exception:
                    unavailable = True
                    replay_error = None
        if unavailable:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None
        if replay_error is not None:
            raise ReplayError(_GENERIC_REPLAY) from None

    def _connect(self, directory_descriptor: int) -> sqlite3.Connection:
        bound_path = Path(
            f"/proc/self/fd/{directory_descriptor}/{REPLAY_FILENAME}"
        )
        connection: sqlite3.Connection | None = None
        failed = False
        try:
            connection = sqlite3.connect(
                bound_path.as_uri() + "?mode=rw",
                uri=True,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.enable_load_extension(False)
            return connection
        except Exception:
            failed = True
        finally:
            if failed and connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
        raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None

    def _is_proven_replay_conflict(
        self, connection: sqlite3.Connection, binding: _Binding,
        error: sqlite3.IntegrityError,
    ) -> bool:
        if getattr(error, "sqlite_errorcode", None) not in {
            sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
            sqlite3.SQLITE_CONSTRAINT_UNIQUE,
        }:
            return False
        rows = connection.execute(
            "SELECT jti, github_run_id, github_run_attempt FROM consumptions "
            "WHERE jti = ? OR (github_run_id = ? AND github_run_attempt = ?) "
            "LIMIT 2",
            (binding.jti, binding.run_id, binding.run_attempt),
        ).fetchall()
        return 1 <= len(rows) <= 2 and any(
            row[0] == binding.jti
            or (row[1], row[2]) == (binding.run_id, binding.run_attempt)
            for row in rows
        )

    def _configure_initial(self, connection: sqlite3.Connection) -> None:
        connection.execute(f"PRAGMA page_size={PAGE_SIZE}")
        mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        connection.execute(f"PRAGMA max_page_count={MAX_PAGE_COUNT}")
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={USER_VERSION}")
        self._set_connection_pragmas(connection)

    def _configure_existing(self, connection: sqlite3.Connection) -> None:
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        connection.execute(f"PRAGMA max_page_count={MAX_PAGE_COUNT}")
        self._set_connection_pragmas(connection)

    def _set_connection_pragmas(self, connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        expected = {
            "synchronous": 2, "foreign_keys": 1, "trusted_schema": 0,
            "temp_store": 2, "page_size": PAGE_SIZE,
            "max_page_count": MAX_PAGE_COUNT, "application_id": APPLICATION_ID,
            "user_version": USER_VERSION,
            "busy_timeout": self._busy_timeout_ms,
        }
        for name, required in expected.items():
            row = connection.execute(f"PRAGMA {name}").fetchone()
            if row is None or row[0] != required:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)

    def _advance_clock(self, connection: sqlite3.Connection, now: int) -> int:
        row = connection.execute(
            "SELECT last_seen_epoch FROM metadata WHERE singleton = 1"
        ).fetchone()
        if row is None or len(row) != 1:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        last_seen = _integer(row[0], positive=False)
        if last_seen - now > MAX_CLOCK_SKEW_SECONDS:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        effective = max(now, last_seen)
        cursor = connection.execute(
            "UPDATE metadata SET last_seen_epoch = ? "
            "WHERE singleton = 1 AND last_seen_epoch <= ?",
            (effective, effective),
        )
        if cursor.rowcount != 1:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        return effective

    def _open_directory(self) -> int:
        descriptor: int | None = None
        child: int | None = None
        try:
            descriptor = os.open(
                "/",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            for component in self._directory.parts[1:]:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
                child = None
            result = descriptor
            descriptor = None
            return result
        except Exception:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None
        finally:
            if child is not None:
                try:
                    os.close(child)
                except Exception:
                    pass
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except Exception:
                    pass

    def _bounded_entries(self, directory_descriptor: int) -> frozenset[str]:
        try:
            with os.scandir(directory_descriptor) as iterator:
                entries = [entry.name for entry in islice(iterator, 3)]
            if len(entries) > 2:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
            return frozenset(entries)
        except ReplayUnavailableError:
            raise
        except Exception:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None

    def _validate_directory_descriptor(
        self, directory_descriptor: int, *, expected_entries: frozenset[str],
    ) -> None:
        try:
            directory = os.fstat(directory_descriptor)
            named_directory = os.lstat(self._directory)
            if (
                not stat.S_ISDIR(directory.st_mode)
                or stat.S_IMODE(directory.st_mode) != DIRECTORY_MODE
                or directory.st_uid != self._uid or directory.st_gid != self._gid
                or (directory.st_dev, directory.st_ino)
                != (named_directory.st_dev, named_directory.st_ino)
                or self._bounded_entries(directory_descriptor) != expected_entries
            ):
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        except ReplayUnavailableError:
            raise
        except Exception:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None

    def _validate_file_status(self, value: os.stat_result, mode: int) -> None:
        if (
            not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode)
            or stat.S_IMODE(value.st_mode) != mode or value.st_nlink != 1
            or value.st_uid != self._uid or value.st_gid != self._gid
        ):
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)

    def _validate_filesystem(self, directory_descriptor: int) -> None:
        try:
            entries = self._bounded_entries(directory_descriptor)
            self._validate_directory_descriptor(
                directory_descriptor, expected_entries=entries,
            )
            allowed = {REPLAY_FILENAME, REPLAY_FILENAME + "-journal"}
            if REPLAY_FILENAME not in entries or not entries <= allowed:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
            database = os.stat(
                REPLAY_FILENAME, dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            self._validate_file_status(database, DATABASE_MODE)
            if database.st_size > DATABASE_SIZE_LIMIT:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
            if REPLAY_FILENAME + "-journal" in entries:
                journal = os.stat(
                    REPLAY_FILENAME + "-journal", dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                self._validate_file_status(journal, DATABASE_MODE)
                if journal.st_size > JOURNAL_SIZE_LIMIT:
                    raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        except ReplayUnavailableError:
            raise
        except Exception:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None

    def _validate_bound_file(
        self, directory_descriptor: int, database_descriptor: int,
    ) -> None:
        opened = os.fstat(database_descriptor)
        named = os.stat(
            REPLAY_FILENAME, dir_fd=directory_descriptor, follow_symlinks=False,
        )
        self._validate_file_status(opened, DATABASE_MODE)
        self._validate_file_status(named, DATABASE_MODE)
        if (
            (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_size > DATABASE_SIZE_LIMIT
            or named.st_size > DATABASE_SIZE_LIMIT
        ):
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)

    def _quarantine_failed_initialization(
        self, directory_descriptor: int, database_descriptor: int,
        created_identity: tuple[int, int] | None,
    ) -> None:
        try:
            opened = os.fstat(database_descriptor)
        except Exception:
            return
        if created_identity is None:
            created_identity = (opened.st_dev, opened.st_ino)
        if created_identity != (opened.st_dev, opened.st_ino):
            return
        self._poison_descriptor(database_descriptor)
        try:
            named = os.stat(
                REPLAY_FILENAME, dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if created_identity == (named.st_dev, named.st_ino):
                os.unlink(REPLAY_FILENAME, dir_fd=directory_descriptor)
                os.fsync(directory_descriptor)
        except Exception:
            pass

    def _poison_descriptor(self, database_descriptor: int) -> None:
        try:
            os.fchmod(database_descriptor, 0)
        except Exception:
            pass
        try:
            os.ftruncate(database_descriptor, 0)
            os.fsync(database_descriptor)
        except Exception:
            pass

    def _quarantine_named_initialization(
        self, directory_descriptor: int,
        created_identity: tuple[int, int] | None,
    ) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                REPLAY_FILENAME, os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
            opened = os.fstat(descriptor)
            if created_identity == (opened.st_dev, opened.st_ino):
                self._quarantine_failed_initialization(
                    directory_descriptor, descriptor, created_identity,
                )
        except Exception:
            pass
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except Exception:
                    pass

    def _validate_open_store(self, connection: sqlite3.Connection) -> None:
        integrity = connection.execute("PRAGMA integrity_check").fetchmany(2)
        if integrity != [("ok",)]:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        page_size = connection.execute("PRAGMA page_size").fetchone()
        page_count = connection.execute("PRAGMA page_count").fetchone()
        maximum = connection.execute("PRAGMA max_page_count").fetchone()
        if (
            page_size != (PAGE_SIZE,) or maximum != (MAX_PAGE_COUNT,)
            or page_count is None or isinstance(page_count[0], bool)
            or not isinstance(page_count[0], int)
            or not 0 <= page_count[0] <= MAX_PAGE_COUNT
            or page_count[0] * PAGE_SIZE > DATABASE_SIZE_LIMIT
        ):
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        if connection.execute("PRAGMA application_id").fetchone() != (APPLICATION_ID,):
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        if connection.execute("PRAGMA user_version").fetchone() != (USER_VERSION,):
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        self._validate_schema(connection)
        metadata = connection.execute(
            "SELECT singleton, schema_version, last_seen_epoch FROM metadata"
        ).fetchmany(2)
        if (
            len(metadata) != 1 or metadata[0][0:2] != (1, USER_VERSION)
            or isinstance(metadata[0][2], bool) or not isinstance(metadata[0][2], int)
            or not 0 <= metadata[0][2] <= SQLITE_INTEGER_MAX
        ):
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        count = connection.execute("SELECT count(*) FROM consumptions").fetchone()
        if count is None or not isinstance(count[0], int) or not 0 <= count[0] <= MAXIMUM_ENTRIES:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        rows = connection.execute(
            "SELECT jti, retain_until, executor_request_sha256, github_run_id, "
            "github_run_attempt, status FROM consumptions "
            "ORDER BY retain_until, jti LIMIT ?",
            (MAXIMUM_ENTRIES + 1,),
        ).fetchall()
        if len(rows) != count[0]:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        for jti, retain, request_hash, run_id, run_attempt, status_value in rows:
            try:
                validate_jti(jti)
            except OIDCAuthorizationError:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE) from None
            _integer(retain, positive=False)
            _integer(run_id, positive=True)
            _integer(run_attempt, positive=True)
            if not isinstance(request_hash, str) or _HASH.fullmatch(request_hash) is None:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
            if status_value not in _STATUSES:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "ORDER BY type, name"
        ).fetchmany(6)
        if len(rows) != 5:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        observed = {(kind, name, table): sql for kind, name, table, sql in rows}
        expected_keys = {
            ("table", "metadata", "metadata"),
            ("table", "consumptions", "consumptions"),
            ("index", "replay_expiry_idx", "consumptions"),
            ("index", "sqlite_autoindex_consumptions_1", "consumptions"),
            ("index", "sqlite_autoindex_consumptions_2", "consumptions"),
        }
        if set(observed) != expected_keys:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        expected_sql = {
            ("table", "metadata", "metadata"): METADATA_SQL,
            ("table", "consumptions", "consumptions"): CONSUMPTIONS_SQL,
            ("index", "replay_expiry_idx", "consumptions"): EXPIRY_INDEX_SQL,
        }
        for key, sql in expected_sql.items():
            if _normalize_sql(observed[key]) != _normalize_sql(sql):
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        for name in ("sqlite_autoindex_consumptions_1", "sqlite_autoindex_consumptions_2"):
            if observed[("index", name, "consumptions")] is not None:
                raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        metadata_columns = connection.execute(
            "PRAGMA table_info(metadata)"
        ).fetchmany(4)
        consumption_columns = connection.execute(
            "PRAGMA table_info(consumptions)"
        ).fetchmany(7)
        if metadata_columns != [
            (0, "singleton", "INTEGER", 0, None, 1),
            (1, "schema_version", "INTEGER", 1, None, 0),
            (2, "last_seen_epoch", "INTEGER", 1, None, 0),
        ]:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        if consumption_columns != [
            (0, "jti", "TEXT", 0, None, 1),
            (1, "retain_until", "INTEGER", 1, None, 0),
            (2, "executor_request_sha256", "TEXT", 1, None, 0),
            (3, "github_run_id", "INTEGER", 1, None, 0),
            (4, "github_run_attempt", "INTEGER", 1, None, 0),
            (5, "status", "TEXT", 1, None, 0),
        ]:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        indexes = connection.execute(
            "PRAGMA index_list(consumptions)"
        ).fetchmany(4)
        by_name = {row[1]: row for row in indexes}
        if set(by_name) != {
            "replay_expiry_idx", "sqlite_autoindex_consumptions_1",
            "sqlite_autoindex_consumptions_2",
        }:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        if (
            by_name["replay_expiry_idx"][2:] != (0, "c", 0)
            or by_name["sqlite_autoindex_consumptions_1"][2:] != (1, "pk", 0)
            or by_name["sqlite_autoindex_consumptions_2"][2:] != (1, "u", 0)
        ):
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        expiry_columns = connection.execute(
            "PRAGMA index_info(replay_expiry_idx)"
        ).fetchmany(3)
        primary_columns = connection.execute(
            "PRAGMA index_info(sqlite_autoindex_consumptions_1)"
        ).fetchmany(2)
        run_columns = connection.execute(
            "PRAGMA index_info(sqlite_autoindex_consumptions_2)"
        ).fetchmany(3)
        if [row[2] for row in expiry_columns] != ["retain_until", "jti"]:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        if [row[2] for row in primary_columns] != ["jti"]:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)
        if [row[2] for row in run_columns] != ["github_run_id", "github_run_attempt"]:
            raise ReplayUnavailableError(_GENERIC_UNAVAILABLE)


__all__ = ["PRODUCTION_REPLAY_DATABASE", "SQLiteReplayGuard"]
