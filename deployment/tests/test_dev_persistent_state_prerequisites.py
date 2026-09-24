"""C31C closed persistent-state prerequisite tests."""

import ast
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import gzip
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

import deployment.audit as audit
import deployment.dev_host_provisioning_plan as plan
import deployment.dev_persistent_state_prerequisites as module
import deployment.executor_service_config as c17
import deployment.privileged_host_runtime as c30
import deployment.replay_sqlite as replay
import deployment.state_store as state_store
from deployment.deployment_operation import _snapshot_state, _updated_state
from deployment.state import DeploymentState, MigrationState
from deployment.tests.fixtures import event, state
from deployment.tests.test_executor_service_config import configuration_values


ERROR = "DEV persistent state prerequisites are unavailable"
NOW = 2_000_000_000


class FakeRuntime:
    def __init__(self, resources):
        self.resources = {item.path: item for item in resources}
        self.calls = []

    def create_required_directory(self, path):
        item = self.resources[path]
        target = Path(path)
        if target.exists():
            status = target.stat()
            if (
                not target.is_dir()
                or stat.S_IMODE(status.st_mode) != item.mode
                or (status.st_uid, status.st_gid) != (item.uid, item.gid)
            ):
                raise c30.HostRuntimeError("DEV privileged host operation is unavailable")
            outcome = "unchanged"
        else:
            target.mkdir(mode=item.mode)
            target.chmod(item.mode)
            outcome = "created"
        self.calls.append(path)
        return c30.HostMutationEvidence("directory", path, outcome)


class Sandbox:
    def __init__(self):
        self.state_temporary = tempfile.TemporaryDirectory(prefix="task014-c31c-state-")
        self.replay_temporary = tempfile.TemporaryDirectory(prefix="task014-c31c-replay-")
        self.audit_temporary = tempfile.TemporaryDirectory(prefix="task014-c31c-audit-")
        self.state_directory = Path(self.state_temporary.name)
        self.replay_directory = Path(self.replay_temporary.name)
        self.audit_directory = Path(self.audit_temporary.name)
        self.configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        self.value = module.DevPersistentStatePrerequisites(
            configuration=self.configuration,
        )
        original = object.__getattribute__(self.value, "_authority")
        uid, gid = os.getuid(), os.getgid()
        resources = (
            dataclasses.replace(
                original.state_directory, path=str(self.state_directory),
                uid=uid, gid=gid,
            ),
            dataclasses.replace(
                original.state_file, path=str(self.state_directory / "state.json"),
                uid=uid, gid=gid,
            ),
            dataclasses.replace(
                original.replay_directory, path=str(self.replay_directory),
                uid=uid, gid=gid,
            ),
            dataclasses.replace(
                original.replay_database,
                path=str(self.replay_directory / "replay.sqlite3"), uid=uid, gid=gid,
            ),
            dataclasses.replace(
                original.audit_directory, path=str(self.audit_directory),
                uid=uid, gid=gid,
            ),
            dataclasses.replace(
                original.audit_file, path=str(self.audit_directory / "events.jsonl"),
                uid=uid, gid=gid,
            ),
        )
        self.runtime = FakeRuntime((resources[0], resources[2], resources[4]))
        authority = dataclasses.replace(
            original, runtime=self.runtime,
            state_directory=resources[0], state_file=resources[1],
            replay_directory=resources[2], replay_database=resources[3],
            audit_directory=resources[4], audit_file=resources[5],
            replay_clock=lambda: NOW,
        )
        object.__setattr__(self.value, "_authority", authority)
        self.authority = authority
        self.state_directory.chmod(0o700)
        self.replay_directory.chmod(0o770)
        self.audit_directory.chmod(0o700)

    def close(self):
        self.state_temporary.cleanup()
        self.replay_temporary.cleanup()
        self.audit_temporary.cleanup()

    def store(self):
        return module._state_store(self.authority)

    def guard(self):
        return module._replay_guard(self.authority)


class InitialStateTests(unittest.TestCase):
    def test_a_zero_input_deterministic_exact_initial_state(self):
        parameters = inspect.signature(module.dev_initial_state).parameters
        self.assertEqual(tuple(parameters), ())
        first = module.dev_initial_state()
        second = module.dev_initial_state()
        self.assertEqual(first, second)
        self.assertEqual(len(first.canonical_bytes), 492)
        self.assertEqual(
            first.sha256,
            "1267be5bd7f29db9e89289ad9bfc6e13b210641e8407cab8a52e9c08fde17f3f",
        )
        self.assertEqual(first.canonical_bytes, first.state.canonical_bytes())
        self.assertEqual(
            DeploymentState.from_dict(json.loads(first.canonical_bytes)), first.state,
        )
        self.assertEqual(first.state.updated_at, "1970-01-01T00:00:00Z")
        self.assertEqual(first.state.event_id, "bootstrap-initial-state-v1")
        self.assertEqual(
            (first.state.active_release, first.state.previous_release,
             first.state.candidate_release),
            (None, None, None),
        )
        self.assertEqual(
            first.state.migration_state,
            MigrationState("none", None, None, True),
        )

    def test_b_evidence_cannot_override_bootstrap_authority(self):
        exact = module.dev_initial_state()
        for values in (
            (dataclasses.replace(exact.state, event_id="caller"), exact.canonical_bytes,
             exact.sha256),
            (exact.state, exact.canonical_bytes + b" ", exact.sha256),
            (exact.state, exact.canonical_bytes, "0" * 64),
        ):
            with self.subTest(values=values[2]):
                with self.assertRaisesRegex(ValueError, "evidence is invalid"):
                    module.DevInitialStateEvidence(*values)

    def test_c_bootstrap_is_fresh_and_first_checkpoint_replaces_sentinels(self):
        initial = module.dev_initial_state().state
        self.assertEqual(_snapshot_state(initial, fresh=True), initial)
        updated = _updated_state(
            initial, updated_at="2026-09-20T12:00:00Z",
            event_id="c8:" + "a" * 64 + ":promotion-started",
        )
        self.assertNotEqual(updated.updated_at, initial.updated_at)
        self.assertNotEqual(updated.event_id, initial.event_id)


class StatePrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.close)

    def test_d_absent_state_created_exact_fsynced_and_store_loads(self):
        state_path = self.sandbox.state_directory / "state.json"
        with patch.object(module._os, "fsync", wraps=os.fsync) as fsync:
            evidence = self.sandbox.value.initialize_deployment_state()
        self.assertEqual(evidence.outcome, "initialized")
        status = state_path.stat()
        self.assertEqual((stat.S_IMODE(status.st_mode), status.st_nlink), (0o600, 1))
        self.assertEqual((status.st_uid, status.st_gid), (os.getuid(), os.getgid()))
        self.assertEqual(state_path.read_bytes(), module.dev_initial_state().canonical_bytes)
        self.assertEqual(self.sandbox.store().load(), module.dev_initial_state().state)
        self.assertGreaterEqual(fsync.call_count, 2)

    def test_e_exact_initial_is_unchanged_and_genuine_state_is_preserved(self):
        first = self.sandbox.value.initialize_deployment_state()
        before = (self.sandbox.state_directory / "state.json").stat()
        second = self.sandbox.value.initialize_deployment_state()
        after = (self.sandbox.state_directory / "state.json").stat()
        self.assertEqual((first.outcome, second.outcome), ("initialized", "unchanged"))
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))

        existing = state(previous=False)
        self.sandbox.store().save(existing)
        raw = (self.sandbox.state_directory / "state.json").read_bytes()
        evidence = self.sandbox.value.initialize_deployment_state()
        self.assertEqual(evidence.outcome, "existing")
        self.assertEqual((self.sandbox.state_directory / "state.json").read_bytes(), raw)

    def test_f_malformed_symlink_hardlink_mode_and_residue_fail_without_repair(self):
        path = self.sandbox.state_directory / "state.json"
        scenarios = ("malformed", "symlink", "hardlink", "mode", "residue")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                for item in tuple(self.sandbox.state_directory.iterdir()):
                    item.unlink()
                if scenario == "malformed":
                    path.write_bytes(b"malformed\n"); path.chmod(0o600)
                elif scenario == "symlink":
                    outside = self.sandbox.state_directory / "outside"
                    outside.write_bytes(module.dev_initial_state().canonical_bytes)
                    path.symlink_to(outside)
                elif scenario == "hardlink":
                    path.write_bytes(module.dev_initial_state().canonical_bytes); path.chmod(0o600)
                    os.link(path, self.sandbox.state_directory / "other")
                elif scenario == "mode":
                    path.write_bytes(module.dev_initial_state().canonical_bytes); path.chmod(0o644)
                else:
                    (self.sandbox.state_directory / ".state.json.tmp").write_bytes(b"residue")
                before = {item.name: item.lstat() for item in self.sandbox.state_directory.iterdir()}
                with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                    self.sandbox.value.initialize_deployment_state()
                after = {item.name: item.lstat() for item in self.sandbox.state_directory.iterdir()}
                self.assertEqual(set(before), set(after))

    def test_g_wrong_ownership_and_partial_failure_fail_closed(self):
        original = self.sandbox.authority
        wrong_file = dataclasses.replace(original.state_file, uid=os.getuid() + 1)
        object.__setattr__(
            self.sandbox.value, "_authority",
            dataclasses.replace(original, state_file=wrong_file),
        )
        with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
            self.sandbox.value.initialize_deployment_state()
        self.assertFalse((self.sandbox.state_directory / "state.json").exists())
        object.__setattr__(self.sandbox.value, "_authority", original)
        with patch.object(module._store, "_write_all", side_effect=OSError):
            with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                self.sandbox.value.initialize_deployment_state()
        self.assertFalse((self.sandbox.state_directory / "state.json").exists())

    def test_g2_uncertain_cleanup_never_removes_a_substituted_state(self):
        configuration = module._state_configuration(self.sandbox.authority)
        path = self.sandbox.state_directory / "state.json"
        path.write_bytes(b"partial")
        path.chmod(0o600)
        status = path.stat()
        identity = (status.st_dev, status.st_ino)
        replacement = self.sandbox.state_directory / "replacement"
        replacement.write_bytes(b"unrelated")
        replacement.chmod(0o600)
        os.replace(replacement, path)
        directory = os.open(self.sandbox.state_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(OSError):
                module._cleanup_created_state(configuration, directory, identity)
            self.assertEqual(path.read_bytes(), b"unrelated")
        finally:
            os.close(directory)

    def test_h_concurrent_initializers_do_not_reset_or_corrupt(self):
        second = module.DevPersistentStatePrerequisites(
            configuration=self.sandbox.configuration,
        )
        object.__setattr__(second, "_authority", self.sandbox.authority)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda value: self._initialize_result(value),
                (self.sandbox.value, second),
            ))
        self.assertIn("initialized", results)
        self.assertTrue(set(results) <= {"initialized", "unchanged", "error"})
        self.assertEqual(self.sandbox.store().load(), module.dev_initial_state().state)

    @staticmethod
    def _initialize_result(value):
        try:
            return value.initialize_deployment_state().outcome
        except module.PersistentStatePrerequisiteError:
            return "error"


class ReplayAndAuditTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.close)

    def test_recovery_replay_requires_exact_initial_store_without_writes(self):
        path = self.sandbox.replay_directory / "replay.sqlite3"
        guard = self.sandbox.guard()
        guard.initialize()
        before = path.read_bytes()
        module._verify_initial_replay(self.sandbox.authority)
        self.assertEqual(path.read_bytes(), before)
        guard.consume(
            "consumed-jti", expires_at=NOW + 100,
            request_hash="a" * 64, run_id=1, run_attempt=1,
        )
        before = path.read_bytes()
        with self.assertRaises(OSError):
            module._verify_initial_replay(self.sandbox.authority)
        self.assertEqual(path.read_bytes(), before)
        with __import__("sqlite3").connect(path) as connection:
            connection.execute("DROP TABLE consumptions")
        before = path.read_bytes()
        with self.assertRaises(OSError):
            module._verify_initial_replay(self.sandbox.authority)
        self.assertEqual(path.read_bytes(), before)

    def test_i_replay_initializes_once_with_clock_and_validates_read_only(self):
        with patch.object(replay.SQLiteReplayGuard, "initialize", wraps=self.sandbox.guard().initialize) as initialize:
            first = self.sandbox.value.initialize_replay()
        self.assertEqual(first.outcome, "initialized")
        self.assertEqual(initialize.call_count, 1)
        path = self.sandbox.replay_directory / "replay.sqlite3"
        with __import__("sqlite3").connect(path) as connection:
            self.assertEqual(
                connection.execute("SELECT last_seen_epoch FROM metadata").fetchone(),
                (NOW,),
            )
        self.sandbox.guard().consume(
            "preserved-jti", expires_at=NOW + 100,
            request_hash="a" * 64, run_id=1, run_attempt=1,
        )
        before = path.read_bytes()
        second = self.sandbox.value.initialize_replay()
        self.assertEqual(second.outcome, "existing")
        self.sandbox.guard().validate()
        with __import__("sqlite3").connect(path) as connection:
            self.assertEqual(
                connection.execute("SELECT jti FROM consumptions").fetchall(),
                [("preserved-jti",)],
            )
        self.assertEqual(path.read_bytes(), before)

    def test_j_replay_malformed_symlink_and_hardlink_are_never_replaced(self):
        path = self.sandbox.replay_directory / "replay.sqlite3"
        for scenario in ("malformed", "symlink", "hardlink"):
            with self.subTest(scenario=scenario):
                for item in tuple(self.sandbox.replay_directory.iterdir()):
                    item.unlink()
                if scenario == "malformed":
                    path.write_bytes(b"malformed"); path.chmod(0o660)
                elif scenario == "symlink":
                    outside = self.sandbox.replay_directory / "outside"
                    outside.write_bytes(b"outside"); path.symlink_to(outside)
                else:
                    path.write_bytes(b"malformed"); path.chmod(0o660)
                    os.link(path, self.sandbox.replay_directory / "other")
                before = {item.name: item.lstat() for item in self.sandbox.replay_directory.iterdir()}
                with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                    self.sandbox.value.initialize_replay()
                self.assertEqual(
                    set(before), {item.name for item in self.sandbox.replay_directory.iterdir()},
                )

    def test_j2_replay_initialization_failure_is_not_retried(self):
        with patch.object(
            replay.SQLiteReplayGuard, "_configure_initial",
            side_effect=OSError("synthetic"),
        ) as configure:
            with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                self.sandbox.value.initialize_replay()
        self.assertEqual(configure.call_count, 1)
        self.assertFalse((self.sandbox.replay_directory / "replay.sqlite3").exists())

    def test_k_pristine_audit_leaves_file_absent_and_first_real_append_works(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        evidence = self.sandbox.value.prepare_audit()
        self.assertEqual((evidence.outcome, evidence.entry_count), ("pristine", 0))
        self.assertFalse(path.exists())
        sink = audit.FilesystemAuditSink(path)
        sink.append(event("dev", event_type="promotion_succeeded"))
        before = path.read_bytes()
        existing = self.sandbox.value.prepare_audit()
        self.assertEqual((existing.outcome, existing.entry_count), ("existing", 1))
        self.assertEqual(path.read_bytes(), before)

    def test_l_existing_and_rotated_audit_history_is_preserved(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        sink = audit.FilesystemAuditSink(path, rotate_bytes=1024)
        first = event("dev", event_type="promotion_succeeded")
        sink.append(first)
        raw = first.to_dict(); raw["event_id"] = "event-dev-two"
        raw["timestamp"] = "2026-09-08T00:00:01Z"
        sink.append(audit.AuditEvent.from_dict(raw))
        before = {item.name: item.read_bytes() for item in self.sandbox.audit_directory.iterdir()}
        self.assertTrue(any(name.startswith("events.jsonl.") for name in before))
        evidence = self.sandbox.value.prepare_audit()
        after = {item.name: item.read_bytes() for item in self.sandbox.audit_directory.iterdir()}
        self.assertEqual(evidence.outcome, "existing")
        self.assertEqual(before, after)

    def test_l2_audit_validation_consumes_the_retained_current_descriptor(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        audit.FilesystemAuditSink(path).append(
            event("dev", event_type="promotion_succeeded"),
        )
        replacement = self.sandbox.state_directory / "replacement"
        replacement.write_bytes(b"malformed replacement\n")
        replacement.chmod(0o600)
        held = self.sandbox.state_directory / "held"
        original_reader = module._read_audit_descriptor

        def swap_while_reading(descriptor, name, expected):
            os.replace(path, held)
            os.replace(replacement, path)
            try:
                return original_reader(descriptor, name, expected)
            finally:
                os.replace(path, replacement)
                os.replace(held, path)

        before = path.read_bytes()
        # Ignore timestamp changes caused by rename so this test isolates the
        # content source: even with that secondary defense removed, bytes come
        # from the retained inode rather than the temporary pathname target.
        stable_fingerprint = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size,
        )
        with patch.object(module, "_file_fingerprint", side_effect=stable_fingerprint), \
             patch.object(module, "_read_audit_descriptor", side_effect=swap_while_reading):
            self.assertEqual(self.sandbox.value.prepare_audit().outcome, "existing")
        self.assertEqual(path.read_bytes(), before)

    def test_l3_temporary_valid_path_cannot_hide_malformed_retained_bytes(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        audit.FilesystemAuditSink(path).append(
            event("dev", event_type="promotion_succeeded"),
        )
        valid = self.sandbox.state_directory / "valid"
        valid.write_bytes(path.read_bytes())
        valid.chmod(0o600)
        path.write_bytes(b"{\n")
        held = self.sandbox.state_directory / "held"
        original_reader = module._read_audit_descriptor

        def swap_while_reading(descriptor, name, expected):
            os.replace(path, held)
            os.replace(valid, path)
            try:
                return original_reader(descriptor, name, expected)
            finally:
                os.replace(path, valid)
                os.replace(held, path)

        with patch.object(module, "_read_audit_descriptor", side_effect=swap_while_reading):
            with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                self.sandbox.value.prepare_audit()
        self.assertEqual(path.read_bytes(), b"{\n")

    def test_l4_compressed_rotation_validation_is_descriptor_bound(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        audit.FilesystemAuditSink(path).append(
            event("dev", event_type="promotion_succeeded"),
        )
        rotation = self.sandbox.audit_directory / "events.jsonl.20260908T000000Z.aaaaaaaaaaaa.gz"
        rotation.write_bytes(gzip.compress(path.read_bytes(), mtime=0))
        rotation.chmod(0o600)
        path.unlink()
        replacement = self.sandbox.state_directory / "replacement.gz"
        replacement.write_bytes(b"not gzip")
        replacement.chmod(0o600)
        held = self.sandbox.state_directory / "held.gz"
        original_reader = module._read_audit_descriptor

        def swap_while_reading(descriptor, name, expected):
            os.replace(rotation, held)
            os.replace(replacement, rotation)
            try:
                return original_reader(descriptor, name, expected)
            finally:
                os.replace(rotation, replacement)
                os.replace(held, rotation)

        before = rotation.read_bytes()
        # As above, isolate descriptor-bound gzip consumption from the stronger
        # production timestamp fingerprint that also detects this rename.
        stable_fingerprint = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size,
        )
        with patch.object(module, "_file_fingerprint", side_effect=stable_fingerprint), \
             patch.object(module, "_read_audit_descriptor", side_effect=swap_while_reading):
            self.assertEqual(self.sandbox.value.prepare_audit().outcome, "existing")
        self.assertEqual(rotation.read_bytes(), before)

    def test_l5_audit_validation_rechecks_descriptor_and_named_identity(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        audit.FilesystemAuditSink(path).append(
            event("dev", event_type="promotion_succeeded"),
        )
        original_reader = module._read_audit_descriptor

        def mutate_opened_identity(descriptor, name, expected):
            os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1))
            return original_reader(descriptor, name, expected)

        with patch.object(module, "_read_audit_descriptor", side_effect=mutate_opened_identity):
            with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                self.sandbox.value.prepare_audit()

        second = event("dev", event_type="promotion_succeeded").to_dict()
        second["event_id"] = "event-dev-two"
        second["timestamp"] = "2026-09-08T00:00:01Z"
        audit.FilesystemAuditSink(path).append(audit.AuditEvent.from_dict(second))
        replacement = self.sandbox.state_directory / "replacement"
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        held = self.sandbox.state_directory / "held"

        def substitute_named_identity(descriptor, name, expected):
            raw = original_reader(descriptor, name, expected)
            os.replace(path, held)
            os.replace(replacement, path)
            return raw

        try:
            with patch.object(
                module, "_read_audit_descriptor",
                side_effect=substitute_named_identity,
            ):
                with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                    self.sandbox.value.prepare_audit()
        finally:
            if held.exists():
                if path.exists():
                    os.replace(path, replacement)
                os.replace(held, path)

    def test_l6_c31c_never_calls_pathname_history_validation(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        audit.FilesystemAuditSink(path).append(
            event("dev", event_type="promotion_succeeded"),
        )
        with patch.object(
            audit.FilesystemAuditSink, "_validate_history",
            side_effect=AssertionError("pathname reopen"),
        ) as pathname_validator, patch.object(
            audit.FilesystemAuditSink, "_files",
            side_effect=AssertionError("pathname listing"),
        ) as pathname_files, patch.object(
            audit.FilesystemAuditSink, "_read",
            side_effect=AssertionError("pathname read"),
        ) as pathname_reader:
            self.assertEqual(self.sandbox.value.prepare_audit().outcome, "existing")
        for pathname_method in (pathname_validator, pathname_files, pathname_reader):
            pathname_method.assert_not_called()

    def test_l7_malformed_compressed_history_is_rejected_without_mutation(self):
        rotation = (
            self.sandbox.audit_directory
            / "events.jsonl.20260908T000000Z.aaaaaaaaaaaa.gz"
        )
        rotation.write_bytes(b"not a gzip stream")
        rotation.chmod(0o600)
        before = rotation.read_bytes()
        with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
            self.sandbox.value.prepare_audit()
        self.assertEqual(rotation.read_bytes(), before)

    def test_m_unsafe_audit_entries_fail_without_history_mutation(self):
        path = self.sandbox.audit_directory / "events.jsonl"
        for scenario in ("unknown", "symlink", "mode"):
            with self.subTest(scenario=scenario):
                for item in tuple(self.sandbox.audit_directory.iterdir()):
                    item.unlink()
                if scenario == "unknown":
                    (self.sandbox.audit_directory / "unknown").write_bytes(b"x")
                elif scenario == "symlink":
                    outside = self.sandbox.audit_directory / "outside"
                    outside.write_bytes(b"x"); path.symlink_to(outside)
                else:
                    path.write_bytes(b""); path.chmod(0o644)
                before = {item.name: item.lstat() for item in self.sandbox.audit_directory.iterdir()}
                with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                    self.sandbox.value.prepare_audit()
                self.assertEqual(set(before), {item.name for item in self.sandbox.audit_directory.iterdir()})

    def test_m2_conflicting_persistent_directory_metadata_is_not_repaired(self):
        for directory, operation in (
            (self.sandbox.state_directory, self.sandbox.value.initialize_deployment_state),
            (self.sandbox.replay_directory, self.sandbox.value.initialize_replay),
            (self.sandbox.audit_directory, self.sandbox.value.prepare_audit),
        ):
            with self.subTest(directory=directory):
                expected = stat.S_IMODE(directory.stat().st_mode)
                directory.chmod(0o777)
                with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR):
                    operation()
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)
                directory.chmod(expected)

    def test_n_read_only_combined_verification(self):
        self.sandbox.value.initialize_deployment_state()
        self.sandbox.value.initialize_replay()
        self.sandbox.value.prepare_audit()
        before = self._tree_bytes()
        evidence = self.sandbox.value.verify_persistent_prerequisites()
        self.assertEqual(tuple(item.outcome for item in evidence), (
            "verified-initial", "verified", "pristine",
        ))
        self.assertEqual(before, self._tree_bytes())

    def _tree_bytes(self):
        result = {}
        for root in (self.sandbox.state_directory, self.sandbox.replay_directory,
                     self.sandbox.audit_directory):
            for path in root.iterdir():
                result[str(path)] = path.read_bytes()
        return result


class BoundaryTests(unittest.TestCase):
    def test_o_public_api_inertness_fixed_errors_and_no_arbitrary_authority(self):
        self.assertEqual(module._AUDIT_PATH,
                         "/var/lib/omnilyzer/deployment/audit/events.jsonl")
        self.assertEqual(module._AUDIT_DIRECTORY,
                         "/var/lib/omnilyzer/deployment/audit")
        self.assertEqual(module.__all__, (
            "PersistentStatePrerequisiteError", "DevInitialStateEvidence",
            "PersistentPrerequisiteEvidence", "dev_initial_state",
            "DevPersistentStatePrerequisites",
        ))
        self.assertEqual(
            {name for name in vars(module) if not name.startswith("_")},
            set(module.__all__),
        )
        methods = {
            name for name, value in vars(module.DevPersistentStatePrerequisites).items()
            if callable(value) and not name.startswith("_")
        }
        self.assertEqual(methods, {
            "initialize_deployment_state", "initialize_replay", "prepare_audit",
            "verify_persistent_prerequisites",
        })
        with self.assertRaisesRegex(ValueError, "evidence is invalid"):
            module.PersistentPrerequisiteEvidence(
                "/var/lib/omnilyzer/deployment/audit/events.jsonl",
                "audit_history", "existing", 0,
            )
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        with patch.object(os, "open", side_effect=AssertionError), \
             patch.object(socket, "socket", side_effect=AssertionError):
            importlib.reload(module)
            module.dev_initial_state()
            module.DevPersistentStatePrerequisites(configuration=configuration)
        with self.assertRaises(TypeError):
            module.DevPersistentStatePrerequisites(configuration=object())
        value = module.DevPersistentStatePrerequisites(configuration=configuration)
        authority = object.__getattribute__(value, "_authority")
        self.assertEqual(dataclasses.astuple(authority.audit_directory), (
            module._AUDIT_DIRECTORY, "directory", 0o700,
            configuration.executor_uid, configuration.executor_gid,
            "must-exist-before-activation",
        ))
        self.assertEqual(dataclasses.astuple(authority.audit_file), (
            module._AUDIT_PATH, "regular_file", 0o600,
            configuration.executor_uid, configuration.executor_gid,
            "may-be-created-on-first-audit-append",
        ))
        with self.assertRaises(TypeError):
            value.initialize_replay(path="/tmp/escape")
        sandbox = Sandbox()
        try:
            with patch.object(module, "_initialize_replay", side_effect=ValueError("secret")):
                with self.assertRaisesRegex(module.PersistentStatePrerequisiteError, ERROR) as caught:
                    sandbox.value.initialize_replay()
            self.assertNotIn("secret", str(caught.exception))
        finally:
            sandbox.close()

    def test_p_control_exceptions_and_static_nonactivation_boundary(self):
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        sandbox = Sandbox()
        try:
            with patch.object(module, "_initialize_state", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    sandbox.value.initialize_deployment_state()
        finally:
            sandbox.close()
        source = Path(module.__file__).read_text()
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertFalse(imports & {"socket", "urllib", "http", "requests"})
        for marker in ("systemctl", "docker", "sudo", "reset(", "repair("):
            self.assertNotIn(marker, source.lower())

    def test_q_plan_steps_19_to_21_are_c31c_and_other_steps_unchanged(self):
        rows = plan._STEP_ROWS
        self.assertEqual(rows[18:21], (
            (19, "establish-initial-deployment-state-prerequisites", "C31C"),
            (20, "initialize-replay-under-existing-lifecycle", "C31C"),
            (21, "establish-audit-prerequisites-preserving-history", "C31C"),
        ))
        self.assertEqual(tuple(row[0] for row in rows), tuple(range(1, 23)))
        self.assertEqual(rows[21], (
            22, "verify-post-provision-convergence-and-integrity", "C31D",
        ))


if __name__ == "__main__":
    unittest.main()
