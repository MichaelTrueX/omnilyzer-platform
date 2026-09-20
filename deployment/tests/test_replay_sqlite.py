from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from deployment.identity import ReplayError, ReplayGuard, ReplayUnavailableError
from deployment.replay_sqlite import (
    APPLICATION_ID,
    CONSUMPTIONS_SQL,
    DATABASE_MODE,
    DATABASE_SIZE_LIMIT,
    DEFAULT_BUSY_TIMEOUT_MS,
    DEFAULT_MAXIMUM_ENTRIES,
    DIRECTORY_MODE,
    EXPIRY_INDEX_SQL,
    JOURNAL_SIZE_LIMIT,
    MAXIMUM_ENTRIES,
    MAX_PAGE_COUNT,
    METADATA_SQL,
    PAGE_SIZE,
    PRODUCTION_REPLAY_DATABASE,
    SQLITE_INTEGER_MAX,
    USER_VERSION,
    SQLiteReplayGuard,
)


HASH_A = "a" * 64
HASH_B = "b" * 64
NOW = 2_000_000_000
GENERIC_UNAVAILABLE = "replay storage is unavailable"
GENERIC_REPLAY = "replay request is not accepted"


def process_consume(path: str, uid: int, gid: int, gate, results) -> None:
    guard = SQLiteReplayGuard(
        path, expected_directory_uid=uid, expected_directory_gid=gid,
        busy_timeout_ms=1000, current_time=lambda: NOW,
    )
    gate.wait()
    try:
        guard.consume(
            "process-jti", expires_at=NOW + 100,
            request_hash=HASH_A, run_id=700, run_attempt=1,
        )
        results.put("winner")
    except ReplayError as error:
        results.put("replay" if type(error) is ReplayError else "unavailable")


class ConnectionProxy:
    def __init__(
        self, connection: sqlite3.Connection, *,
        fail_contains: str | None = None, rollback_failure: bool = False,
        close_failure: bool = False,
    ) -> None:
        self.connection = connection
        self.fail_contains = fail_contains
        self.rollback_failure = rollback_failure
        self.close_failure = close_failure

    def execute(self, sql, parameters=()):
        if self.rollback_failure and sql == "ROLLBACK":
            raise sqlite3.OperationalError("synthetic-rollback-marker")
        if self.fail_contains and self.fail_contains in sql:
            raise sqlite3.OperationalError("synthetic-storage-marker")
        return self.connection.execute(sql, parameters)

    def close(self):
        self.connection.close()
        if self.close_failure:
            raise sqlite3.OperationalError("synthetic-close-marker")

    def enable_load_extension(self, enabled):
        return self.connection.enable_load_extension(enabled)


class ReplayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="task014-replay-")
        self.directory = Path(self.temporary.name)
        self.directory.chmod(DIRECTORY_MODE)
        self.path = self.directory / "replay.sqlite3"
        self.now = NOW
        self.guard = self.make_guard()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_guard(self, **updates) -> SQLiteReplayGuard:
        values = {
            "expected_directory_uid": os.getuid(),
            "expected_directory_gid": os.getgid(),
            "current_time": lambda: self.now,
        }
        values.update(updates)
        return SQLiteReplayGuard(self.path, **values)

    def initialize(self) -> None:
        self.guard.initialize()

    def consume(
        self, jti: str = "jti-1", *, expires_at: int = NOW + 100,
        request_hash: str = HASH_A, run_id: int = 1, run_attempt: int = 1,
        guard: SQLiteReplayGuard | None = None,
    ) -> None:
        (guard or self.guard).consume(
            jti, expires_at=expires_at, request_hash=request_hash,
            run_id=run_id, run_attempt=run_attempt,
        )

    def direct(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def unavailable(self, operation, *sensitive: str) -> None:
        with self.assertRaises(ReplayUnavailableError) as captured:
            operation()
        self.assertEqual(type(captured.exception), ReplayUnavailableError)
        self.assertEqual(str(captured.exception), GENERIC_UNAVAILABLE)
        for marker in sensitive:
            self.assertNotIn(marker, str(captured.exception))

    def replay(self, operation) -> None:
        with self.assertRaises(ReplayError) as captured:
            operation()
        self.assertEqual(type(captured.exception), ReplayError)
        self.assertEqual(str(captured.exception), GENERIC_REPLAY)


class InitializationAndFilesystemTests(ReplayTestCase):
    def test_construction_performs_no_filesystem_action_and_production_is_untouched(self) -> None:
        missing = self.directory / "missing" / "replay.sqlite3"
        with (
            patch("deployment.replay_sqlite.os.lstat") as lstat,
            patch("deployment.replay_sqlite.os.scandir") as scandir,
            patch("deployment.replay_sqlite.os.open") as open_file,
            patch("deployment.replay_sqlite.sqlite3.connect") as connect,
        ):
            SQLiteReplayGuard(
                missing, expected_directory_uid=os.getuid(),
                expected_directory_gid=os.getgid(),
            )
            SQLiteReplayGuard(
                PRODUCTION_REPLAY_DATABASE,
                expected_directory_uid=0, expected_directory_gid=0,
            )
        for mocked in (lstat, scandir, open_file, connect):
            mocked.assert_not_called()
        self.assertEqual(
            str(PRODUCTION_REPLAY_DATABASE),
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
        )

    def test_configuration_is_closed_and_bounded(self) -> None:
        for path in ("relative/replay.sqlite3", self.directory / "other.sqlite3"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                SQLiteReplayGuard(path, expected_directory_uid=0, expected_directory_gid=0)
        for field, value in (
            ("expected_directory_uid", -1), ("expected_directory_gid", True),
            ("maximum_entries", 0), ("maximum_entries", 10_001),
            ("busy_timeout_ms", 0), ("busy_timeout_ms", 1001),
        ):
            values = {"expected_directory_uid": 0, "expected_directory_gid": 0}
            values[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                SQLiteReplayGuard(self.path, **values)
        guard = SQLiteReplayGuard(
            self.path, expected_directory_uid=os.getuid(),
            expected_directory_gid=os.getgid(),
        )
        self.assertEqual(guard._maximum_entries, DEFAULT_MAXIMUM_ENTRIES)
        self.assertEqual(guard._busy_timeout_ms, DEFAULT_BUSY_TIMEOUT_MS)

    def test_missing_directory_fails_without_creation(self) -> None:
        path = self.directory / "missing" / "replay.sqlite3"
        guard = SQLiteReplayGuard(
            path, expected_directory_uid=os.getuid(),
            expected_directory_gid=os.getgid(), current_time=lambda: NOW,
        )
        self.unavailable(guard.initialize)
        self.assertFalse(path.parent.exists())

    def test_initialization_creates_exact_schema_metadata_modes_and_pragmas(self) -> None:
        self.initialize()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o770)
        file_status = self.path.stat()
        self.assertEqual(stat.S_IMODE(file_status.st_mode), 0o660)
        self.assertEqual((file_status.st_uid, file_status.st_gid, file_status.st_nlink), (os.getuid(), os.getgid(), 1))
        with self.direct() as connection:
            self.assertEqual(connection.execute("PRAGMA application_id").fetchone(), (APPLICATION_ID,))
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (USER_VERSION,))
            self.assertEqual(connection.execute("PRAGMA page_size").fetchone(), (PAGE_SIZE,))
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone(), ("delete",))
            self.assertEqual(connection.execute("SELECT * FROM metadata").fetchall(), [(1, 1, NOW)])
            master = connection.execute("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
            sql = {name: value for name, value in master}
            self.assertEqual(sql["metadata"], METADATA_SQL)
            self.assertEqual(sql["consumptions"], CONSUMPTIONS_SQL)
            self.assertEqual(sql["replay_expiry_idx"], EXPIRY_INDEX_SQL)

    def test_initialization_refuses_existing_empty_or_malformed_database(self) -> None:
        for content in (b"", b"not sqlite"):
            with self.subTest(content=content):
                self.path.write_bytes(content)
                self.path.chmod(DATABASE_MODE)
                before = self.path.read_bytes()
                self.unavailable(self.guard.initialize)
                self.assertEqual(self.path.read_bytes(), before)
                self.path.unlink()

    def test_wrong_directory_mode_uid_and_gid_fail(self) -> None:
        self.directory.chmod(0o750)
        self.unavailable(self.guard.initialize)
        self.directory.chmod(DIRECTORY_MODE)
        self.unavailable(self.make_guard(expected_directory_uid=os.getuid() + 1).initialize)
        self.unavailable(self.make_guard(expected_directory_gid=os.getgid() + 1).initialize)

    def test_directory_and_database_symlinks_fail(self) -> None:
        real = self.directory / "real"
        real.mkdir(mode=DIRECTORY_MODE)
        link = self.directory / "linked"
        link.symlink_to(real, target_is_directory=True)
        linked_guard = SQLiteReplayGuard(
            link / "replay.sqlite3", expected_directory_uid=os.getuid(),
            expected_directory_gid=os.getgid(), current_time=lambda: NOW,
        )
        self.unavailable(linked_guard.initialize)
        link.unlink()
        real.rmdir()
        target = self.directory.parent / (self.directory.name + "-target")
        target.write_bytes(b"")
        self.path.symlink_to(target)
        try:
            self.unavailable(self.guard.initialize)
        finally:
            target.unlink()

    def test_wrong_database_mode_and_hard_link_fail(self) -> None:
        self.initialize()
        self.path.chmod(0o666)
        self.unavailable(lambda: self.consume())
        self.path.chmod(DATABASE_MODE)
        alias = self.directory.parent / (self.directory.name + "-alias")
        os.link(self.path, alias)
        try:
            self.unavailable(lambda: self.consume())
        finally:
            alias.unlink()

    def test_unexpected_wal_shm_and_bad_journal_entries_fail(self) -> None:
        self.initialize()
        for suffix in ("unexpected", "replay.sqlite3-wal", "replay.sqlite3-shm"):
            extra = self.directory / suffix
            extra.write_bytes(b"")
            with self.subTest(suffix=suffix):
                self.unavailable(lambda: self.consume())
            extra.unlink()
        journal = self.directory / "replay.sqlite3-journal"
        journal.write_bytes(b"synthetic")
        journal.chmod(0o666)
        self.unavailable(lambda: self.consume())

    def test_database_size_bound_fails_before_sqlite_open(self) -> None:
        self.path.touch(mode=DATABASE_MODE)
        self.path.chmod(DATABASE_MODE)
        with self.path.open("r+b") as stream:
            stream.truncate(DATABASE_SIZE_LIMIT + 1)
        with patch("deployment.replay_sqlite.sqlite3.connect") as connect:
            self.unavailable(lambda: self.consume())
            connect.assert_not_called()


class SchemaAndIntegrityTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()

    def mutate(self, sql: str, parameters=()) -> None:
        with self.direct() as connection:
            connection.execute(sql, parameters)

    def test_wrong_application_id_and_user_version_fail_without_repair(self) -> None:
        for pragma in ("application_id=1", "user_version=2"):
            with self.subTest(pragma=pragma):
                self.mutate(f"PRAGMA {pragma}")
                before = self.path.read_bytes()
                self.unavailable(lambda: self.consume())
                self.assertEqual(self.path.read_bytes(), before)
                if pragma.startswith("application"):
                    self.mutate(f"PRAGMA application_id={APPLICATION_ID}")
                else:
                    self.mutate(f"PRAGMA user_version={USER_VERSION}")

    def test_missing_or_changed_table_fails(self) -> None:
        self.mutate("DROP TABLE metadata")
        self.unavailable(lambda: self.consume())
        self.tearDown(); self.setUp()
        self.mutate("ALTER TABLE metadata RENAME COLUMN last_seen_epoch TO changed_epoch")
        self.unavailable(lambda: self.consume())

    def test_missing_or_changed_expiry_index_fails(self) -> None:
        self.mutate("DROP INDEX replay_expiry_idx")
        self.unavailable(lambda: self.consume())
        self.tearDown(); self.setUp()
        self.mutate("DROP INDEX replay_expiry_idx")
        self.mutate("CREATE INDEX replay_expiry_idx ON consumptions(jti, retain_until)")
        self.unavailable(lambda: self.consume())

    def test_missing_unique_run_constraint_fails(self) -> None:
        with self.direct() as connection:
            connection.execute("PRAGMA writable_schema=ON")
            connection.execute(
                "UPDATE sqlite_master SET sql=replace(sql, '    UNIQUE(github_run_id, github_run_attempt)\n', '') WHERE name='consumptions'"
            )
            version = connection.execute("PRAGMA schema_version").fetchone()[0]
            connection.execute(f"PRAGMA schema_version={version + 1}")
        self.unavailable(lambda: self.consume())

    def test_extra_table_index_view_and_trigger_fail(self) -> None:
        statements = (
            "CREATE TABLE extra(value INTEGER)",
            "CREATE INDEX extra_index ON consumptions(status)",
            "CREATE VIEW extra_view AS SELECT jti FROM consumptions",
            "CREATE TRIGGER extra_trigger AFTER INSERT ON consumptions BEGIN SELECT 1; END",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.mutate(statement)
                self.unavailable(lambda: self.consume())
                self.tearDown(); self.setUp()

    def test_malformed_metadata_and_stored_values_fail(self) -> None:
        self.mutate("DELETE FROM metadata")
        self.unavailable(lambda: self.consume())
        self.tearDown(); self.setUp()
        self.consume()
        with self.direct() as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute("UPDATE consumptions SET status='retryable'")
        self.unavailable(lambda: self.consume("jti-2", run_id=2))

    def test_partial_truncated_and_integrity_corruption_fail_without_repair(self) -> None:
        data = self.path.read_bytes()
        self.path.write_bytes(data[: PAGE_SIZE + 100])
        self.path.chmod(DATABASE_MODE)
        before = self.path.read_bytes()
        self.unavailable(lambda: self.consume())
        self.assertEqual(self.path.read_bytes(), before)
        self.tearDown(); self.setUp()
        with self.path.open("r+b") as stream:
            stream.seek(0)
            byte = stream.read(1)
            stream.seek(0)
            stream.write(bytes([byte[0] ^ 0xFF]))
        before = self.path.read_bytes()
        self.unavailable(lambda: self.consume())
        self.assertEqual(self.path.read_bytes(), before)


class ConsumptionTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()

    def test_structurally_implements_replay_guard_and_first_consume_stores_exact_binding(self) -> None:
        self.assertTrue(hasattr(ReplayGuard, "consume"))
        self.consume()
        with self.direct() as connection:
            self.assertEqual(
                connection.execute("SELECT * FROM consumptions").fetchone(),
                ("jti-1", NOW + 130, HASH_A, 1, 1, "consumed"),
            )

    def test_duplicate_jti_and_changed_binding_are_definite_replay(self) -> None:
        self.consume()
        self.replay(lambda: self.consume())
        self.replay(lambda: self.consume(request_hash=HASH_B, run_id=2))

    def test_duplicate_run_attempt_rejects_another_jti_but_new_attempt_passes(self) -> None:
        self.consume()
        self.replay(lambda: self.consume("jti-2", run_id=1, run_attempt=1))
        self.consume("jti-2", run_id=1, run_attempt=2)

    def test_replay_survives_new_object_and_subprocess(self) -> None:
        self.consume()
        other = self.make_guard()
        self.replay(lambda: self.consume(guard=other))
        code = """
import os, sys
from deployment.identity import ReplayError, ReplayUnavailableError
from deployment.replay_sqlite import SQLiteReplayGuard
g=SQLiteReplayGuard(sys.argv[1], expected_directory_uid=os.getuid(), expected_directory_gid=os.getgid(), current_time=lambda: 2000000000)
try:
 g.consume('jti-1', expires_at=2000000100, request_hash='a'*64, run_id=1, run_attempt=1)
except ReplayUnavailableError:
 raise SystemExit(18)
except ReplayError:
 raise SystemExit(17)
raise SystemExit(1)
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.path)], cwd=Path(__file__).parents[2],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_only_closed_nonsensitive_fields_exist(self) -> None:
        self.consume("safe-jti")
        with self.direct() as connection:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(consumptions)")]
        self.assertEqual(columns, [
            "jti", "retain_until", "executor_request_sha256",
            "github_run_id", "github_run_attempt", "status",
        ])
        raw = self.path.read_bytes().lower()
        for marker in (b"jwt", b"bearer", b"claims", b"credential", b"response", b"canonical request"):
            self.assertNotIn(marker, raw)

    def test_invalid_inputs_fail_before_database_access(self) -> None:
        invalid = (
            lambda: self.consume("../jti"),
            lambda: self.consume(request_hash="A" * 64),
            lambda: self.consume(request_hash="a" * 65),
            lambda: self.consume(run_id=True),
            lambda: self.consume(run_id=0),
            lambda: self.consume(run_id=SQLITE_INTEGER_MAX + 1),
            lambda: self.consume(run_attempt=-1),
            lambda: self.consume(expires_at=True),
            lambda: self.consume(expires_at=-1),
            lambda: self.consume(expires_at=SQLITE_INTEGER_MAX),
        )
        with patch.object(self.guard, "_connect", wraps=self.guard._connect) as connect:
            for operation in invalid:
                with self.subTest(operation=operation):
                    self.unavailable(operation)
            connect.assert_not_called()

    def test_already_expired_retention_fails_without_row(self) -> None:
        self.replay(lambda: self.consume(expires_at=NOW - 31))
        with self.direct() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM consumptions").fetchone(), (0,))


class ConcurrencyTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()

    def test_one_winner_across_threads_and_all_losers_are_replay(self) -> None:
        barrier = threading.Barrier(12)
        def attempt() -> str:
            guard = self.make_guard()
            barrier.wait()
            try:
                self.consume("thread-jti", run_id=600, guard=guard)
                return "winner"
            except ReplayError as error:
                return "replay" if type(error) is ReplayError else "unavailable"
        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(12)))
        self.assertEqual(outcomes.count("winner"), 1)
        self.assertEqual(outcomes.count("replay"), 11)

    def test_one_winner_across_processes_and_all_losers_are_replay(self) -> None:
        context = multiprocessing.get_context("fork")
        gate = context.Event()
        results = context.Queue()
        processes = [
            context.Process(
                target=process_consume,
                args=(str(self.path), os.getuid(), os.getgid(), gate, results),
            )
            for _ in range(6)
        ]
        for process in processes:
            process.start()
        gate.set()
        outcomes = [results.get(timeout=5) for _ in processes]
        for process in processes:
            process.join(timeout=5)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(outcomes.count("winner"), 1)
        self.assertEqual(outcomes.count("replay"), 5)

    def test_held_immediate_lock_times_out_without_partial_row(self) -> None:
        locked = self.direct()
        locked.isolation_level = None
        locked.execute("BEGIN IMMEDIATE")
        guard = self.make_guard(busy_timeout_ms=50)
        started = time.monotonic()
        try:
            self.unavailable(lambda: self.consume("locked-jti", run_id=50, guard=guard))
        finally:
            locked.execute("ROLLBACK")
            locked.close()
        self.assertLess(time.monotonic() - started, 1.0)
        with self.direct() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM consumptions").fetchone(), (0,))


class ExpiryCapacityAndClockTests(ReplayTestCase):
    def test_expiry_is_inclusive_then_cleanup_allows_reuse(self) -> None:
        self.initialize()
        self.consume(expires_at=NOW - 30)
        self.replay(lambda: self.consume(expires_at=NOW - 30))
        self.now += 1
        self.consume(expires_at=NOW + 100)

    def test_capacity_fails_closed_and_expiry_frees_capacity(self) -> None:
        self.guard = self.make_guard(maximum_entries=2)
        self.initialize()
        self.consume("jti-a", expires_at=NOW + 100, run_id=1)
        self.consume("jti-b", expires_at=NOW + 100, run_id=2)
        self.unavailable(lambda: self.consume("jti-c", run_id=3))
        self.now += 131
        self.consume("jti-c", expires_at=NOW + 300, run_id=3)
        with self.direct() as connection:
            self.assertEqual(connection.execute("SELECT jti FROM consumptions").fetchall(), [("jti-c",)])

    def test_cleanup_order_and_global_bound_are_fixed(self) -> None:
        source = Path(__file__).parents[1].joinpath("replay_sqlite.py").read_text()
        self.assertIn("ORDER BY retain_until, jti LIMIT ?", source)
        self.assertIn("(effective_time, MAXIMUM_ENTRIES)", source)
        self.assertEqual(MAXIMUM_ENTRIES, 10_000)

    def test_executing_rows_survive_expiry_count_toward_capacity_and_finish_late(self) -> None:
        self.guard = self.make_guard(maximum_entries=1)
        self.initialize()
        self.consume("executing-jti", expires_at=NOW - 30, run_id=1)
        self.guard.begin_execution(
            "executing-jti", request_hash=HASH_A, run_id=1, run_attempt=1,
        )
        self.now += 1
        self.unavailable(lambda: self.consume("other-jti", run_id=2))
        self.guard.finish_execution(
            "executing-jti", request_hash=HASH_A, run_id=1, run_attempt=1,
        )
        self.consume("other-jti", expires_at=NOW + 100, run_id=2)

    def test_durable_clock_watermark_never_decreases_and_survives_instances(self) -> None:
        self.initialize()
        self.consume()
        self.now += 20
        self.consume("jti-2", run_id=2)
        other = self.make_guard()
        self.now -= 10
        self.consume("jti-3", run_id=3, guard=other)
        with self.direct() as connection:
            self.assertEqual(connection.execute("SELECT last_seen_epoch FROM metadata").fetchone(), (NOW + 20,))

    def test_small_rollback_does_not_resurrect_deleted_jti(self) -> None:
        self.initialize()
        self.now = NOW - 10
        self.consume("old-jti", expires_at=NOW - 30, run_id=1)
        self.now = NOW + 1
        self.consume("cleanup-jti", expires_at=NOW + 100, run_id=2)
        self.now = NOW - 20
        self.replay(lambda: self.consume("old-jti", expires_at=NOW - 30, run_id=1))

    def test_rollback_beyond_skew_and_invalid_clocks_fail_closed(self) -> None:
        self.initialize()
        self.consume()
        self.now -= 31
        self.unavailable(lambda: self.consume("jti-2", run_id=2))
        for value in (True, 1.5, -1, SQLITE_INTEGER_MAX + 1):
            guard = self.make_guard(current_time=lambda value=value: value)
            with self.subTest(value=value):
                self.unavailable(lambda: self.consume("jti-3", run_id=3, guard=guard))
        guard = self.make_guard(current_time=lambda: (_ for _ in ()).throw(RuntimeError("clock-marker")))
        self.unavailable(lambda: self.consume("jti-4", run_id=4, guard=guard), "clock-marker")

    def test_forward_jump_performs_bounded_cleanup(self) -> None:
        self.initialize()
        for number in range(5):
            self.consume(f"jti-{number}", expires_at=NOW + number, run_id=number + 1)
        self.now += 100
        self.consume("future-jti", expires_at=NOW + 200, run_id=10)
        with self.direct() as connection:
            self.assertEqual(connection.execute("SELECT jti FROM consumptions").fetchall(), [("future-jti",)])


class LifecycleTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()

    def begin(self, **updates) -> None:
        values = {"jti": "jti-1", "request_hash": HASH_A, "run_id": 1, "run_attempt": 1}
        values.update(updates)
        self.guard.begin_execution(**values)

    def finish(self, **updates) -> None:
        values = {"jti": "jti-1", "request_hash": HASH_A, "run_id": 1, "run_attempt": 1}
        values.update(updates)
        self.guard.finish_execution(**values)

    def status(self) -> tuple[int, str]:
        with self.direct() as connection:
            return connection.execute("SELECT count(*), status FROM consumptions").fetchone()

    def test_closed_lifecycle_succeeds_once_without_create_or_delete(self) -> None:
        self.consume()
        self.begin()
        self.assertEqual(self.status(), (1, "executing"))
        self.replay(self.begin)
        self.finish()
        self.assertEqual(self.status(), (1, "finished"))
        self.replay(self.finish)

    def test_begin_rejects_missing_wrong_binding_and_finished(self) -> None:
        self.replay(self.begin)
        self.consume()
        for updates in (
            {"jti": "other"}, {"request_hash": HASH_B},
            {"run_id": 2}, {"run_attempt": 2},
        ):
            with self.subTest(updates=updates):
                self.replay(lambda updates=updates: self.begin(**updates))
        self.begin(); self.finish()
        self.replay(self.begin)

    def test_finish_rejects_missing_wrong_binding_consumed_and_finished(self) -> None:
        self.replay(self.finish)
        self.consume()
        self.replay(self.finish)
        self.begin()
        for updates in (
            {"jti": "other"}, {"request_hash": HASH_B},
            {"run_id": 2}, {"run_attempt": 2},
        ):
            with self.subTest(updates=updates):
                self.replay(lambda updates=updates: self.finish(**updates))
        self.finish()
        self.replay(self.finish)

    def test_transitions_preserve_unique_bindings(self) -> None:
        self.consume()
        self.begin(); self.finish()
        self.replay(lambda: self.consume("jti-2", run_id=1, run_attempt=1))


class FailureAndRedactionTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()

    def proxy_failure(self, **proxy_options) -> None:
        real_connect = sqlite3.connect
        def connect(*args, **kwargs):
            return ConnectionProxy(real_connect(*args, **kwargs), **proxy_options)
        with patch("deployment.replay_sqlite.sqlite3.connect", side_effect=connect):
            self.unavailable(
                lambda: self.consume("sensitive-jti", request_hash=HASH_B, run_id=987654),
                "synthetic", str(self.path), "sensitive-jti", HASH_B, "987654", "INSERT",
            )

    def test_open_read_only_and_io_failures_are_generic(self) -> None:
        with patch("deployment.replay_sqlite.sqlite3.connect", side_effect=sqlite3.OperationalError("open-marker")):
            self.unavailable(lambda: self.consume(), "open-marker", str(self.path))
        self.proxy_failure(fail_contains="BEGIN IMMEDIATE")

    def test_disk_full_commit_and_rollback_failures_are_generic_without_partial_row(self) -> None:
        self.proxy_failure(fail_contains="COMMIT")
        with self.direct() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM consumptions").fetchone(), (0,))
        self.proxy_failure(fail_contains="INSERT INTO consumptions", rollback_failure=True)

    def test_close_failure_is_generic(self) -> None:
        self.proxy_failure(close_failure=True)

    def test_page_limit_delete_journal_and_no_wal_are_enforced(self) -> None:
        self.consume()
        source = Path(__file__).parents[1].joinpath("replay_sqlite.py").read_text()
        self.assertEqual(PAGE_SIZE * MAX_PAGE_COUNT, DATABASE_SIZE_LIMIT)
        self.assertIn("PRAGMA journal_mode=DELETE", source)
        self.assertNotIn("journal_mode=WAL", source)
        self.assertIn("PRAGMA synchronous=FULL", source)
        self.assertIn("PRAGMA trusted_schema=OFF", source)
        self.assertIn("PRAGMA foreign_keys=ON", source)
        self.assertIn("PRAGMA temp_store=MEMORY", source)


class CorrectiveFilesystemTests(ReplayTestCase):
    def assert_traversal_close_failure_leaks_no_descriptor(
        self, *, after_real_close: bool,
    ) -> None:
        real_open = os.open
        real_close = os.close
        opened: list[int] = []
        failed = False

        def record_open(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        def fail_first_close(descriptor):
            nonlocal failed
            if not failed:
                failed = True
                if after_real_close:
                    real_close(descriptor)
                raise OSError("traversal-close-marker")
            return real_close(descriptor)

        with (
            patch("deployment.replay_sqlite.os.open", side_effect=record_open),
            patch("deployment.replay_sqlite.os.close", side_effect=fail_first_close),
        ):
            self.unavailable(self.guard.initialize, "traversal-close-marker")
        self.assertFalse(self.path.exists())
        for descriptor in set(opened):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_traversal_close_failure_before_close_leaks_no_descriptor(self) -> None:
        self.assert_traversal_close_failure_leaks_no_descriptor(
            after_real_close=False,
        )

    def test_traversal_close_failure_after_close_leaks_no_descriptor(self) -> None:
        self.assert_traversal_close_failure_leaks_no_descriptor(
            after_real_close=True,
        )

    def test_ancestor_directory_symlink_is_rejected(self) -> None:
        real = self.directory / "real"
        authority = real / "authority"
        authority.mkdir(parents=True, mode=DIRECTORY_MODE)
        authority.chmod(DIRECTORY_MODE)
        link = self.directory / "linked-root"
        link.symlink_to(real, target_is_directory=True)
        guard = SQLiteReplayGuard(
            link / "authority" / "replay.sqlite3",
            expected_directory_uid=os.getuid(),
            expected_directory_gid=os.getgid(), current_time=lambda: NOW,
        )
        self.unavailable(guard.initialize)
        self.assertFalse((authority / "replay.sqlite3").exists())

    def test_database_symlink_operation_reaches_file_boundary(self) -> None:
        self.initialize()
        outside = self.directory.parent / (self.directory.name + "-database")
        self.path.rename(outside)
        self.path.symlink_to(outside)
        try:
            with patch("deployment.replay_sqlite.sqlite3.connect") as connect:
                self.unavailable(lambda: self.consume())
                connect.assert_not_called()
        finally:
            self.path.unlink()
            outside.rename(self.path)

    def test_wrong_configured_uid_and_gid_fail_each_operation(self) -> None:
        self.initialize()
        for guard in (
            self.make_guard(expected_directory_uid=os.getuid() + 1),
            self.make_guard(expected_directory_gid=os.getgid() + 1),
        ):
            with self.subTest(guard=guard):
                self.unavailable(lambda guard=guard: self.consume(guard=guard))

    def test_database_specific_uid_mismatch_fails_closed(self) -> None:
        self.initialize()
        real_stat = os.stat

        def wrong_uid(path, *args, **kwargs):
            value = real_stat(path, *args, **kwargs)
            if path == "replay.sqlite3" and kwargs.get("dir_fd") is not None:
                fields = list(value)
                fields[4] = value.st_uid + 1
                return os.stat_result(fields)
            return value

        with patch("deployment.replay_sqlite.os.stat", side_effect=wrong_uid):
            self.unavailable(lambda: self.consume())

    def test_database_specific_gid_mismatch_fails_closed(self) -> None:
        self.initialize()
        real_stat = os.stat

        def wrong_gid(path, *args, **kwargs):
            value = real_stat(path, *args, **kwargs)
            if path == "replay.sqlite3" and kwargs.get("dir_fd") is not None:
                fields = list(value)
                fields[5] = value.st_gid + 1
                return os.stat_result(fields)
            return value

        with patch("deployment.replay_sqlite.os.stat", side_effect=wrong_gid):
            self.unavailable(lambda: self.consume())

    def test_oversized_rollback_journal_fails_before_sqlite_open(self) -> None:
        self.initialize()
        journal = self.directory / "replay.sqlite3-journal"
        journal.touch(mode=DATABASE_MODE)
        journal.chmod(DATABASE_MODE)
        with journal.open("r+b") as stream:
            stream.truncate(JOURNAL_SIZE_LIMIT + 1)
        with patch("deployment.replay_sqlite.sqlite3.connect") as connect:
            self.unavailable(lambda: self.consume())
            connect.assert_not_called()
        self.assertTrue(journal.exists())

    def test_rollback_journal_symlink_and_hardlink_fail(self) -> None:
        self.initialize()
        outside = self.directory.parent / (self.directory.name + "-journal")
        outside.write_bytes(b"journal")
        outside.chmod(DATABASE_MODE)
        journal = self.directory / "replay.sqlite3-journal"
        try:
            journal.symlink_to(outside)
            self.unavailable(lambda: self.consume())
            journal.unlink()
            os.link(outside, journal)
            self.unavailable(lambda: self.consume())
        finally:
            if journal.exists() or journal.is_symlink():
                journal.unlink()
            outside.unlink()

    def test_nonregular_database_fails_before_sqlite_open(self) -> None:
        self.initialize()
        self.path.unlink()
        self.path.mkdir(mode=DATABASE_MODE)
        try:
            with patch("deployment.replay_sqlite.sqlite3.connect") as connect:
                self.unavailable(lambda: self.consume())
                connect.assert_not_called()
        finally:
            self.path.chmod(DIRECTORY_MODE)

    def test_directory_replacement_after_open_is_detected(self) -> None:
        authority = self.directory / "authority"
        authority.mkdir(mode=DIRECTORY_MODE)
        path = authority / "replay.sqlite3"
        guard = SQLiteReplayGuard(
            path, expected_directory_uid=os.getuid(),
            expected_directory_gid=os.getgid(), current_time=lambda: NOW,
        )
        guard.initialize()
        saved = self.directory / "saved-authority"
        real_open = guard._open_directory

        def replace_after_open():
            descriptor = real_open()
            authority.rename(saved)
            authority.mkdir(mode=DIRECTORY_MODE)
            return descriptor

        try:
            with patch.object(guard, "_open_directory", side_effect=replace_after_open):
                self.unavailable(lambda: guard.consume(
                    "race-jti", expires_at=NOW + 100, request_hash=HASH_A,
                    run_id=10, run_attempt=1,
                ))
        finally:
            authority.rmdir()
            saved.rename(authority)

    def test_database_replacement_after_validation_is_detected(self) -> None:
        self.initialize()
        alternate_root = Path(tempfile.mkdtemp(prefix="task014-alternate-"))
        alternate_root.chmod(DIRECTORY_MODE)
        alternate = alternate_root / "replay.sqlite3"
        alternate_guard = SQLiteReplayGuard(
            alternate, expected_directory_uid=os.getuid(),
            expected_directory_gid=os.getgid(), current_time=lambda: NOW,
        )
        alternate_guard.initialize()
        saved = self.directory.parent / (self.directory.name + "-saved-db")
        real_connect = self.guard._connect

        def replace_before_connect(directory_descriptor):
            self.path.rename(saved)
            alternate.rename(self.path)
            return real_connect(directory_descriptor)

        try:
            with patch.object(self.guard, "_connect", side_effect=replace_before_connect):
                self.unavailable(lambda: self.consume("race-jti", run_id=10))
        finally:
            if self.path.exists():
                self.path.unlink()
            saved.rename(self.path)
            alternate_root.rmdir()


class CorrectiveInitializationTests(ReplayTestCase):
    def assert_failed_initialization_is_not_accepted(self, operation) -> None:
        self.unavailable(operation)
        if self.path.exists():
            self.assertNotEqual(stat.S_IMODE(self.path.stat().st_mode), DATABASE_MODE)
        self.unavailable(lambda: self.consume("residue-jti", run_id=99))

    def test_database_fsync_failure_quarantines_state(self) -> None:
        real_fsync = os.fsync
        calls = 0

        def fail_first(descriptor):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("fsync-marker")
            return real_fsync(descriptor)

        with patch("deployment.replay_sqlite.os.fsync", side_effect=fail_first):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)

    def test_database_mode_is_independent_of_restrictive_umask(self) -> None:
        prior = os.umask(0o077)
        try:
            self.guard.initialize()
        finally:
            os.umask(prior)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), DATABASE_MODE)

    def test_database_chmod_failure_quarantines_state(self) -> None:
        real_fchmod = os.fchmod
        calls = 0

        def fail_first(descriptor, mode):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("chmod-marker")
            return real_fchmod(descriptor, mode)

        with patch("deployment.replay_sqlite.os.fchmod", side_effect=fail_first):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)

    def test_database_ownership_validation_failure_quarantines_state(self) -> None:
        with patch.object(
            self.guard, "_validate_file_status",
            side_effect=ReplayUnavailableError(GENERIC_UNAVAILABLE),
        ):
            self.unavailable(self.guard.initialize)
        if self.path.exists():
            self.assertNotEqual(stat.S_IMODE(self.path.stat().st_mode), DATABASE_MODE)
        self.unavailable(lambda: self.consume("residue-jti", run_id=99))

    def test_directory_fsync_failure_quarantines_state(self) -> None:
        real_fsync = os.fsync
        failed = False

        def fail_directory(descriptor):
            nonlocal failed
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not failed:
                failed = True
                raise OSError("directory-fsync-marker")
            return real_fsync(descriptor)

        with patch("deployment.replay_sqlite.os.fsync", side_effect=fail_directory):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)

    def test_unlink_failure_leaves_truncated_non_authoritative_residue(self) -> None:
        real_fsync = os.fsync
        calls = 0

        def fail_first_fsync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("initial-fsync-marker")
            return real_fsync(descriptor)

        with (
            patch("deployment.replay_sqlite.os.fsync", side_effect=fail_first_fsync),
            patch("deployment.replay_sqlite.os.unlink", side_effect=OSError("unlink-marker")),
        ):
            self.unavailable(self.guard.initialize)
        self.assertTrue(self.path.exists())
        self.assertEqual(self.path.stat().st_size, 0)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0)
        self.unavailable(lambda: self.consume("residue-jti", run_id=99))

    def test_schema_creation_failure_quarantines_state(self) -> None:
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):
            return ConnectionProxy(
                real_connect(*args, **kwargs), fail_contains="CREATE TABLE metadata",
            )

        with patch("deployment.replay_sqlite.sqlite3.connect", side_effect=connect):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)

    def test_initialization_commit_failure_quarantines_state(self) -> None:
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):
            return ConnectionProxy(real_connect(*args, **kwargs), fail_contains="COMMIT")

        with patch("deployment.replay_sqlite.sqlite3.connect", side_effect=connect):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)

    def test_initialization_close_failure_quarantines_state(self) -> None:
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):
            return ConnectionProxy(real_connect(*args, **kwargs), close_failure=True)

        with patch("deployment.replay_sqlite.sqlite3.connect", side_effect=connect):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)

    def test_initialization_database_descriptor_close_failure_poison_state(self) -> None:
        real_close = os.close
        failed = False

        def fail_regular_descriptor(descriptor):
            nonlocal failed
            if not failed and stat.S_ISREG(os.fstat(descriptor).st_mode):
                failed = True
                raise OSError("descriptor-close-marker")
            return real_close(descriptor)

        with patch("deployment.replay_sqlite.os.close", side_effect=fail_regular_descriptor):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)

    def test_close_failure_after_real_database_close_quarantines_named_state(self) -> None:
        real_close = os.close
        failed = False

        def close_then_fail(descriptor):
            nonlocal failed
            if not failed and stat.S_ISREG(os.fstat(descriptor).st_mode):
                failed = True
                real_close(descriptor)
                raise OSError("post-close-marker")
            return real_close(descriptor)

        with patch("deployment.replay_sqlite.os.close", side_effect=close_then_fail):
            self.assert_failed_initialization_is_not_accepted(self.guard.initialize)


class CorrectiveSQLitePolicyTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()

    def test_connection_reporting_truncate_journal_mode_is_rejected(self) -> None:
        real_connect = sqlite3.connect

        class OneRow:
            def fetchone(self):
                return ("truncate",)

        class JournalProxy(ConnectionProxy):
            def execute(self, sql, parameters=()):
                if sql == "PRAGMA journal_mode":
                    return OneRow()
                return super().execute(sql, parameters)

        with patch(
            "deployment.replay_sqlite.sqlite3.connect",
            side_effect=lambda *args, **kwargs: JournalProxy(
                real_connect(*args, **kwargs)
            ),
        ):
            self.unavailable(lambda: self.consume())

    def test_actual_wal_journal_mode_is_rejected(self) -> None:
        with self.direct() as connection:
            self.assertEqual(
                connection.execute("PRAGMA journal_mode=WAL").fetchone(),
                ("wal",),
            )
        self.unavailable(lambda: self.consume())

    def test_every_operation_applies_required_connection_pragmas(self) -> None:
        observed: list[str] = []
        real_connect = sqlite3.connect

        class RecordingProxy(ConnectionProxy):
            def execute(self, sql, parameters=()):
                observed.append(sql)
                return super().execute(sql, parameters)

        def connect(*args, **kwargs):
            return RecordingProxy(real_connect(*args, **kwargs))

        with patch("deployment.replay_sqlite.sqlite3.connect", side_effect=connect):
            self.consume()
            self.guard.begin_execution(
                "jti-1", request_hash=HASH_A, run_id=1, run_attempt=1,
            )
            self.guard.finish_execution(
                "jti-1", request_hash=HASH_A, run_id=1, run_attempt=1,
            )
        for required in (
            "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON",
            "PRAGMA trusted_schema=OFF", "PRAGMA temp_store=MEMORY",
            "PRAGMA busy_timeout=1000", "PRAGMA max_page_count=4096",
        ):
            self.assertEqual(observed.count(required), 3)

    def test_extension_loading_is_disabled_before_schema_queries(self) -> None:
        events: list[str] = []
        real_connect = sqlite3.connect

        class OrderingProxy(ConnectionProxy):
            def enable_load_extension(self, enabled):
                events.append(f"extension:{enabled}")
                return super().enable_load_extension(enabled)

            def execute(self, sql, parameters=()):
                events.append(sql)
                return super().execute(sql, parameters)

        def connect(*args, **kwargs):
            return OrderingProxy(real_connect(*args, **kwargs))

        with patch("deployment.replay_sqlite.sqlite3.connect", side_effect=connect):
            self.consume()
        self.assertEqual(events[0], "extension:False")
        self.assertGreater(events.index("PRAGMA integrity_check"), 0)

    def test_extension_disable_failure_closes_connection(self) -> None:
        real_connect = sqlite3.connect
        closed = False

        class ExtensionFailureProxy(ConnectionProxy):
            def enable_load_extension(self, enabled):
                raise sqlite3.OperationalError("extension-marker")

            def close(self):
                nonlocal closed
                closed = True
                return super().close()

        with patch(
            "deployment.replay_sqlite.sqlite3.connect",
            side_effect=lambda *args, **kwargs: ExtensionFailureProxy(
                real_connect(*args, **kwargs)
            ),
        ):
            self.unavailable(lambda: self.consume(), "extension-marker")
        self.assertTrue(closed)


class CorrectiveSemanticsTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()

    def test_unproven_integrity_error_is_unavailable(self) -> None:
        real_connect = sqlite3.connect

        class IntegrityProxy(ConnectionProxy):
            def execute(self, sql, parameters=()):
                if sql.startswith("INSERT INTO consumptions"):
                    raise sqlite3.IntegrityError("integrity-marker")
                return super().execute(sql, parameters)

        with patch(
            "deployment.replay_sqlite.sqlite3.connect",
            side_effect=lambda *args, **kwargs: IntegrityProxy(
                real_connect(*args, **kwargs)
            ),
        ):
            self.unavailable(lambda: self.consume(), "integrity-marker")

    def test_rollback_failure_overrides_definite_duplicate(self) -> None:
        self.consume()
        real_connect = sqlite3.connect

        with patch(
            "deployment.replay_sqlite.sqlite3.connect",
            side_effect=lambda *args, **kwargs: ConnectionProxy(
                real_connect(*args, **kwargs), rollback_failure=True,
            ),
        ):
            self.unavailable(lambda: self.consume())

    def test_begin_after_retention_expiry_is_replay(self) -> None:
        self.consume(expires_at=NOW - 30)
        self.now += 1
        self.replay(lambda: self.guard.begin_execution(
            "jti-1", request_hash=HASH_A, run_id=1, run_attempt=1,
        ))

    def test_begin_at_retention_boundary_succeeds(self) -> None:
        self.consume(expires_at=NOW - 30)
        self.guard.begin_execution(
            "jti-1", request_hash=HASH_A, run_id=1, run_attempt=1,
        )

    def test_clock_is_sampled_once_for_each_public_operation(self) -> None:
        calls = 0

        def clock():
            nonlocal calls
            calls += 1
            return NOW

        guard = self.make_guard(current_time=clock)
        self.path.unlink()
        guard.initialize()
        self.assertEqual(calls, 1)
        guard.validate()
        self.assertEqual(calls, 1)
        guard.consume(
            "clock-jti", expires_at=NOW + 100, request_hash=HASH_A,
            run_id=90, run_attempt=1,
        )
        self.assertEqual(calls, 2)
        guard.begin_execution(
            "clock-jti", request_hash=HASH_A, run_id=90, run_attempt=1,
        )
        self.assertEqual(calls, 3)
        guard.finish_execution(
            "clock-jti", request_hash=HASH_A, run_id=90, run_attempt=1,
        )
        self.assertEqual(calls, 4)

    def test_concurrent_consumes_never_exceed_capacity(self) -> None:
        self.path.unlink()
        guard = self.make_guard(maximum_entries=2)
        guard.initialize()
        barrier = threading.Barrier(10)

        def contender(number):
            local = self.make_guard(maximum_entries=2)
            barrier.wait()
            try:
                local.consume(
                    f"capacity-{number}", expires_at=NOW + 100,
                    request_hash=f"{number:064x}", run_id=number + 1,
                    run_attempt=1,
                )
                return "success"
            except ReplayUnavailableError:
                return "unavailable"

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(contender, range(10)))
        self.assertEqual(results.count("success"), 2)
        self.assertEqual(results.count("unavailable"), 8)
        with self.direct() as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM consumptions").fetchone(),
                (2,),
            )

    def test_full_ten_thousand_row_cleanup_bound(self) -> None:
        rows = [
            (f"cleanup-{number:05d}", NOW - 1, f"{number:064x}", number + 1, 1)
            for number in range(MAXIMUM_ENTRIES)
        ]
        with self.direct() as connection:
            connection.executemany(
                "INSERT INTO consumptions VALUES(?, ?, ?, ?, ?, 'finished')",
                rows,
            )
        self.consume(
            "after-cleanup", expires_at=NOW + 100,
            request_hash=HASH_A, run_id=MAXIMUM_ENTRIES + 1,
        )
        with self.direct() as connection:
            self.assertEqual(
                connection.execute("SELECT jti FROM consumptions").fetchall(),
                [("after-cleanup",)],
            )

    def test_public_surface_has_no_reset_retry_delete_or_enumeration(self) -> None:
        public = {
            name for name in dir(SQLiteReplayGuard)
            if not name.startswith("_")
        }
        self.assertEqual(
            public,
            {"initialize", "validate", "consume", "begin_execution", "finish_execution"},
        )

    def test_maximum_configuration_bound_is_accepted(self) -> None:
        guard = self.make_guard(
            maximum_entries=MAXIMUM_ENTRIES, busy_timeout_ms=1000,
        )
        self.assertEqual(guard._maximum_entries, MAXIMUM_ENTRIES)
        self.assertEqual(guard._busy_timeout_ms, 1000)


class StoredValueCorruptionTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()
        self.consume()


def _stored_corruption_test(column: str, value: object):
    def test(self):
        with self.direct() as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                f"UPDATE consumptions SET {column} = ?", (value,),
            )
        self.unavailable(lambda: self.consume("corruption-probe", run_id=200))
    return test


for _name, _column, _value in (
    ("jti", "jti", "../unsafe"),
    ("retention", "retain_until", -1),
    ("hash", "executor_request_sha256", "A" * 64),
    ("run_id", "github_run_id", 0),
    ("run_attempt", "github_run_attempt", 0),
    ("status", "status", "retryable"),
):
    setattr(
        StoredValueCorruptionTests,
        f"test_malformed_stored_{_name}_fails_closed",
        _stored_corruption_test(_column, _value),
    )


class IndependentConfigurationBoundaryTests(ReplayTestCase):
    pass


def _configuration_test(updates: dict[str, object], path=None):
    def test(self):
        values = {"expected_directory_uid": 0, "expected_directory_gid": 0}
        values.update(updates)
        with self.assertRaises(ValueError):
            SQLiteReplayGuard(path or self.path, **values)
    return test


for _name, _updates, _path in (
    ("relative_path", {}, "relative/replay.sqlite3"),
    ("wrong_filename", {}, "/tmp/not-replay.sqlite"),
    ("dot_component", {}, "/tmp/./replay.sqlite3"),
    ("dotdot_component", {}, "/tmp/child/../replay.sqlite3"),
    ("repeated_separator", {}, "/tmp//replay.sqlite3"),
    ("double_leading_separator", {}, "//tmp/replay.sqlite3"),
    ("nul_path", {}, "/tmp/replay.sqlite3\x00"),
    ("bytes_path", {}, b"/tmp/replay.sqlite3"),
    ("uid_bool", {"expected_directory_uid": True}, None),
    ("uid_negative", {"expected_directory_uid": -1}, None),
    ("uid_overflow", {"expected_directory_uid": 2**32 - 1}, None),
    ("gid_bool", {"expected_directory_gid": True}, None),
    ("gid_negative", {"expected_directory_gid": -1}, None),
    ("gid_overflow", {"expected_directory_gid": 2**32 - 1}, None),
    ("entries_bool", {"maximum_entries": True}, None),
    ("entries_zero", {"maximum_entries": 0}, None),
    ("entries_over_max", {"maximum_entries": 10_001}, None),
    ("timeout_bool", {"busy_timeout_ms": True}, None),
    ("timeout_zero", {"busy_timeout_ms": 0}, None),
    ("timeout_over_max", {"busy_timeout_ms": 1_001}, None),
    ("noncallable_clock", {"current_time": 1}, None),
):
    setattr(
        IndependentConfigurationBoundaryTests,
        f"test_rejects_{_name}",
        _configuration_test(_updates, _path),
    )


class IndependentInputBoundaryTests(ReplayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.initialize()


def _input_test(field: str, value: object):
    def test(self):
        values = {
            "jti": "boundary-jti", "expires_at": NOW + 100,
            "request_hash": HASH_A, "run_id": 1, "run_attempt": 1,
        }
        values[field] = value
        with patch.object(self.guard, "_connect", wraps=self.guard._connect) as connect:
            self.unavailable(lambda: self.guard.consume(**values))
            connect.assert_not_called()
    return test


for _name, _field, _value in (
    ("jti_empty", "jti", ""),
    ("jti_nonstring", "jti", 1),
    ("jti_too_long", "jti", "a" * 129),
    ("jti_unicode", "jti", "aé"),
    ("jti_separator", "jti", "a/b"),
    ("jti_dotdot", "jti", "a..b"),
    ("expiry_bool", "expires_at", True),
    ("expiry_float", "expires_at", 1.0),
    ("expiry_negative", "expires_at", -1),
    ("expiry_overflow", "expires_at", SQLITE_INTEGER_MAX),
    ("hash_nonstring", "request_hash", None),
    ("hash_empty", "request_hash", ""),
    ("hash_short", "request_hash", "a" * 63),
    ("hash_long", "request_hash", "a" * 65),
    ("hash_uppercase", "request_hash", "A" * 64),
    ("hash_nonhex", "request_hash", "g" * 64),
    ("run_bool", "run_id", True),
    ("run_float", "run_id", 1.0),
    ("run_zero", "run_id", 0),
    ("run_negative", "run_id", -1),
    ("run_overflow", "run_id", SQLITE_INTEGER_MAX + 1),
    ("attempt_bool", "run_attempt", True),
    ("attempt_float", "run_attempt", 1.0),
    ("attempt_zero", "run_attempt", 0),
    ("attempt_negative", "run_attempt", -1),
    ("attempt_overflow", "run_attempt", SQLITE_INTEGER_MAX + 1),
):
    setattr(
        IndependentInputBoundaryTests,
        f"test_rejects_{_name}_before_database_access",
        _input_test(_field, _value),
    )


if __name__ == "__main__":
    unittest.main()
