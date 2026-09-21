"""deployment/tests/test_state_store.py — hostile C10 state-store tests.

Purpose: validate ``deployment/state_store.py`` against the authoritative
``deployment/state.py`` model without ever touching the fixed production path.
"""

from __future__ import annotations

from dataclasses import replace
import fcntl
import inspect
import json
import math
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

import deployment.state_store as store_module
from deployment.deployment_operation import DevDeploymentOperation
from deployment.state import DeploymentState, MigrationState
from deployment.state_store import (
    MAX_STATE_BYTES,
    PRODUCTION_DEV_STATE_PATH,
    STATE_STORE_UNAVAILABLE_MESSAGE,
    FilesystemDeploymentStateStore,
    StateStoreUnavailableError,
)
from deployment.tests.fixtures import state


def _hold_directory_lock(path: str, ready: object, release: object) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        ready.set()  # type: ignore[attr-defined]
        if not release.wait(5):  # type: ignore[attr-defined]
            raise RuntimeError("process coordination failed")
    finally:
        os.close(descriptor)


class Sandbox:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.path = self.directory / "state.json"
        self.path.write_bytes(state().canonical_bytes())
        self.path.chmod(0o600)

    def close(self) -> None:
        self.temporary.cleanup()

    def store(self) -> FilesystemDeploymentStateStore:
        value = FilesystemDeploymentStateStore(
            expected_owner_uid=os.getuid(), expected_group_gid=os.getgid(),
        )
        configuration = store_module._build_configuration(
            path=str(self.path), owner_uid=os.getuid(), group_gid=os.getgid(),
            owned_start=1,
        )
        object.__setattr__(value, "_configuration", configuration)
        return value


class StateStoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.close)
        self.store = self.sandbox.store()

    def unavailable(self, operation: object, marker: str | None = None) -> StateStoreUnavailableError:
        with self.assertRaisesRegex(
            StateStoreUnavailableError,
            f"^{STATE_STORE_UNAVAILABLE_MESSAGE}$",
        ) as caught:
            operation()  # type: ignore[operator]
        if marker is not None:
            self.assertNotIn(marker, str(caught.exception))
        return caught.exception


class ApiAndInertnessTests(StateStoreTestCase):
    def test_public_contract_and_c8_compatibility(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(FilesystemDeploymentStateStore).parameters),
            ("expected_owner_uid", "expected_group_gid"),
        )
        self.assertEqual(
            tuple(inspect.signature(FilesystemDeploymentStateStore.load).parameters),
            ("self",),
        )
        self.assertEqual(
            tuple(inspect.signature(FilesystemDeploymentStateStore.save).parameters),
            ("self", "state"),
        )
        public = {
            name for name, value in vars(FilesystemDeploymentStateStore).items()
            if not name.startswith("_") and callable(value)
        }
        self.assertEqual(public, {"load", "save"})
        state_store_parameter = inspect.signature(DevDeploymentOperation).parameters["state_store"]
        self.assertEqual(state_store_parameter.kind, inspect.Parameter.KEYWORD_ONLY)

    def test_import_and_construction_are_inert(self) -> None:
        with (
            patch.object(store_module.os, "open", side_effect=AssertionError("open-marker")),
            patch.object(store_module.os, "stat", side_effect=AssertionError("stat-marker")),
            patch.object(store_module.fcntl, "flock", side_effect=AssertionError("lock-marker")),
        ):
            value = FilesystemDeploymentStateStore(
                expected_owner_uid=1, expected_group_gid=2,
            )
        self.assertIsInstance(value, FilesystemDeploymentStateStore)

    def test_fixed_path_and_no_activation_or_maintenance_api(self) -> None:
        self.assertEqual(
            PRODUCTION_DEV_STATE_PATH,
            "/var/lib/omnilyzer/deployment/dev/state.json",
        )
        signature = inspect.signature(FilesystemDeploymentStateStore)
        self.assertNotIn("path", signature.parameters)
        production = FilesystemDeploymentStateStore(
            expected_owner_uid=2001, expected_group_gid=2002,
        )
        self.assertEqual(
            object.__getattribute__(production, "_configuration").owned_start, 4,
        )
        forbidden = {
            "initialize", "repair", "reset", "delete", "create", "migrate",
            "enumerate", "status", "chmod", "chown", "unlink", "temporary",
        }
        self.assertTrue(forbidden.isdisjoint(vars(FilesystemDeploymentStateStore)))

    def test_configuration_exact_integers_and_immutability(self) -> None:
        for identity in (0, store_module.MAX_IDENTITY_VALUE):
            self.assertIsInstance(
                FilesystemDeploymentStateStore(
                    expected_owner_uid=identity, expected_group_gid=identity,
                ),
                FilesystemDeploymentStateStore,
            )
        child = type("IntChild", (int,), {})(1)
        for field in ("expected_owner_uid", "expected_group_gid"):
            for invalid in (True, False, -1, 2**32 - 1, 1.0, "1", child, None):
                values = {"expected_owner_uid": 1, "expected_group_gid": 2}
                values[field] = invalid
                with self.subTest(field=field, invalid=repr(invalid)), self.assertRaisesRegex(
                    TypeError, "^deployment state store configuration is invalid$",
                ):
                    FilesystemDeploymentStateStore(**values)  # type: ignore[arg-type]
        with self.assertRaises(AttributeError):
            self.store._configuration = None  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            del self.store._configuration

    def test_required_linux_controls_fail_construction_without_io(self) -> None:
        with patch.object(store_module.os, "O_NOFOLLOW", None):
            with self.assertRaises(TypeError):
                FilesystemDeploymentStateStore(
                    expected_owner_uid=1, expected_group_gid=2,
                )
        with patch.object(store_module.fcntl, "LOCK_NB", None):
            with self.assertRaises(TypeError):
                FilesystemDeploymentStateStore(
                    expected_owner_uid=1, expected_group_gid=2,
                )

    def test_module_function_replacement_after_construction_cannot_redirect(self) -> None:
        with (
            patch.object(store_module, "_open_chain", side_effect=AssertionError("redirect")),
            patch.object(store_module, "_read_validated_state", side_effect=AssertionError("redirect")),
            patch.object(store_module, "_state_mapping", side_effect=AssertionError("redirect")),
            patch.object(store_module, "_entries", side_effect=AssertionError("redirect")),
            patch.object(store_module, "_unavailable", side_effect=AssertionError("redirect")),
            patch.object(store_module, "DeploymentState", object),
            patch.object(store_module, "MigrationState", object),
            patch.object(store_module.os, "open", side_effect=AssertionError("redirect")),
        ):
            loaded = self.store.load()
            self.store.save(state(candidate=True))
        self.assertIs(type(loaded), DeploymentState)

    def test_module_entry_replacement_cannot_hide_residue_after_construction(self) -> None:
        residue = self.sandbox.directory / "unexpected"
        residue.write_bytes(b"residue")
        residue.chmod(0o600)
        with patch.object(
            store_module, "_entries",
            return_value=frozenset({"state.json"}),
        ):
            self.unavailable(self.store.load)

    def test_inflight_module_entry_replacement_cannot_hide_residue(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_open = configuration.open_file
        residue = self.sandbox.directory / "unexpected"
        changed = False
        def mutate(path: object, flags: int, *args: object, **kwargs: object) -> object:
            nonlocal changed
            result = real_open(path, flags, *args, **kwargs)
            if not changed and path == self.sandbox.directory.name:
                changed = True
                residue.write_bytes(b"residue")
                residue.chmod(0o600)
                store_module._entries = lambda *arguments: frozenset({"state.json"})  # type: ignore[assignment]
            return result
        object.__setattr__(self.store, "_configuration", replace(
            configuration, open_file=mutate,
        ))
        original = store_module._entries
        try:
            self.unavailable(self.store.load)
        finally:
            store_module._entries = original


class LoadFilesystemTests(StateStoreTestCase):
    def test_valid_canonical_state_returns_exact_base(self) -> None:
        loaded = self.store.load()
        self.assertIs(type(loaded), DeploymentState)
        self.assertIs(type(loaded.migration_state), MigrationState)
        self.assertEqual(loaded, state())

    def test_missing_directory_and_state_fail_without_initialization(self) -> None:
        missing_directory = self.sandbox.directory / "missing" / "state.json"
        first = FilesystemDeploymentStateStore(
            expected_owner_uid=os.getuid(), expected_group_gid=os.getgid(),
        )
        object.__setattr__(first, "_configuration", store_module._build_configuration(
            path=str(missing_directory), owner_uid=os.getuid(), group_gid=os.getgid(),
            owned_start=1,
        ))
        self.unavailable(first.load)
        self.assertFalse(missing_directory.parent.exists())
        self.sandbox.path.unlink()
        self.unavailable(self.store.load)
        self.assertFalse(self.sandbox.path.exists())

    def test_symlink_and_non_directory_ancestor_reject(self) -> None:
        real = self.sandbox.directory / "real"
        real.mkdir(mode=0o700)
        target = real / "state.json"
        target.write_bytes(state().canonical_bytes())
        target.chmod(0o600)
        linked = self.sandbox.directory / "linked"
        linked.symlink_to(real, target_is_directory=True)
        for name in ("linked", "plain"):
            if name == "plain":
                (self.sandbox.directory / name).write_bytes(b"x")
            value = self.sandbox.store()
            object.__setattr__(value, "_configuration", store_module._build_configuration(
                path=str(self.sandbox.directory / name / "state.json"),
                owner_uid=os.getuid(), group_gid=os.getgid(), owned_start=1,
            ))
            with self.subTest(name=name):
                self.unavailable(value.load)

    def test_symlink_nonregular_hardlink_and_wrong_file_mode_reject(self) -> None:
        outside = self.sandbox.directory.parent / (self.sandbox.directory.name + "-outside")
        original = self.sandbox.path.read_bytes()
        self.sandbox.path.unlink()
        outside.write_bytes(original)
        outside.chmod(0o600)
        try:
            self.sandbox.path.symlink_to(outside)
            self.unavailable(self.store.load)
            self.sandbox.path.unlink()
            self.sandbox.path.mkdir(mode=0o700)
            self.unavailable(self.store.load)
            self.sandbox.path.rmdir()
            self.sandbox.path.write_bytes(original)
            self.sandbox.path.chmod(0o600)
            hardlink = self.sandbox.directory / "other"
            os.link(self.sandbox.path, hardlink)
            self.unavailable(self.store.load)
            hardlink.unlink()
            self.sandbox.path.chmod(0o640)
            self.unavailable(self.store.load)
        finally:
            if self.sandbox.path.is_symlink():
                self.sandbox.path.unlink()
            if outside.exists():
                outside.unlink()

    def test_wrong_directory_mode_owner_group_and_file_owner_group_reject(self) -> None:
        self.sandbox.directory.chmod(0o750)
        self.unavailable(self.store.load)
        self.sandbox.directory.chmod(0o700)
        configuration = object.__getattribute__(self.store, "_configuration")
        real_fstat = configuration.fstat
        for field in (4, 5):
            def hostile_fstat(fd: int, field: int = field) -> object:
                value = real_fstat(fd)
                fields = list(value)
                fields[field] += 1
                return os.stat_result(fields)
            object.__setattr__(self.store, "_configuration", replace(configuration, fstat=hostile_fstat))
            with self.subTest(field=field):
                self.unavailable(self.store.load)
        object.__setattr__(self.store, "_configuration", configuration)

    def test_mode_constant_replacement_cannot_weaken_captured_policy(self) -> None:
        self.sandbox.path.chmod(0o640)
        with patch.object(store_module, "STATE_FILE_MODE", 0o640):
            self.unavailable(self.store.load)
        self.sandbox.path.chmod(0o600)

        self.sandbox.directory.chmod(0o750)
        with patch.object(store_module, "STATE_DIRECTORY_MODE", 0o750):
            self.unavailable(self.store.load)
        self.sandbox.directory.chmod(0o700)

        configuration = object.__getattribute__(self.store, "_configuration")
        real_open = configuration.open_file
        creation_modes: list[int] = []
        def observe_create(path: object, flags: int, *args: object, **kwargs: object) -> object:
            if path == configuration.temporary_name:
                creation_modes.append(args[0])
            return real_open(path, flags, *args, **kwargs)
        object.__setattr__(self.store, "_configuration", replace(
            configuration, open_file=observe_create,
        ))
        with patch.object(store_module, "STATE_FILE_MODE", 0o666):
            self.store.save(state(candidate=True))
        self.assertEqual(creation_modes, [0o600])

    def test_inflight_mode_constant_replacement_cannot_weaken_policy(self) -> None:
        self.sandbox.path.chmod(0o640)
        configuration = object.__getattribute__(self.store, "_configuration")
        real_open = configuration.open_file
        changed = False
        original_file_mode = store_module.STATE_FILE_MODE
        original_directory_mode = store_module.STATE_DIRECTORY_MODE
        def mutate(path: object, flags: int, *args: object, **kwargs: object) -> object:
            nonlocal changed
            result = real_open(path, flags, *args, **kwargs)
            if not changed:
                changed = True
                store_module.STATE_FILE_MODE = 0o640
                store_module.STATE_DIRECTORY_MODE = 0o777
            return result
        object.__setattr__(self.store, "_configuration", replace(
            configuration, open_file=mutate,
        ))
        try:
            self.unavailable(self.store.load)
        finally:
            store_module.STATE_FILE_MODE = original_file_mode
            store_module.STATE_DIRECTORY_MODE = original_directory_mode

    def test_empty_oversized_invalid_utf8_and_truncated_json_reject(self) -> None:
        for payload in (b"", b"x" * (MAX_STATE_BYTES + 1), b"\xff", b'{"schema_version":'):
            self.sandbox.path.write_bytes(payload)
            self.sandbox.path.chmod(0o600)
            with self.subTest(size=len(payload)):
                self.unavailable(self.store.load)

    def test_duplicate_nonstandard_noncanonical_and_schema_drift_reject(self) -> None:
        valid = state().to_dict()
        canonical = state().canonical_bytes()
        duplicate = canonical[:-2] + b',"stage":"dev"}\n'
        nan = canonical.replace(b'"schema_version":1', b'"schema_version":NaN')
        noncanonical = json.dumps(valid, indent=2).encode() + b"\n"
        unknown = dict(valid)
        unknown["unknown"] = True
        for payload in (duplicate, nan, noncanonical, json.dumps(unknown).encode()):
            self.sandbox.path.write_bytes(payload)
            self.sandbox.path.chmod(0o600)
            with self.subTest(payload=payload[:40]):
                self.unavailable(self.store.load)

    def test_short_reads_complete_but_zero_malformed_excessive_reads_reject(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_read = configuration.read
        def short(fd: int, size: int) -> object:
            return real_read(fd, min(size, 32))
        object.__setattr__(self.store, "_configuration", replace(configuration, read=short))
        self.assertEqual(self.store.load(), state())
        for read in (
            lambda fd, size: bytearray(b"x"),
            lambda fd, size: b"x" * (size + 1),
            lambda fd, size: b"x",
        ):
            object.__setattr__(self.store, "_configuration", replace(configuration, read=read))
            self.unavailable(self.store.load)

    def test_file_or_directory_replacement_during_load_rejects(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_read = configuration.read
        replaced = self.sandbox.directory / "replacement"
        def replace_file(fd: int, size: int) -> object:
            if not replaced.exists():
                replaced.write_bytes(state(candidate=True).canonical_bytes())
                replaced.chmod(0o600)
                os.replace(replaced, self.sandbox.path)
            return real_read(fd, size)
        object.__setattr__(self.store, "_configuration", replace(configuration, read=replace_file))
        self.unavailable(self.store.load)

        authority = self.sandbox.directory / "authority"
        authority.mkdir(mode=0o700)
        authority_state = authority / "state.json"
        authority_state.write_bytes(state().canonical_bytes())
        authority_state.chmod(0o600)
        value = FilesystemDeploymentStateStore(
            expected_owner_uid=os.getuid(), expected_group_gid=os.getgid(),
        )
        authority_configuration = store_module._build_configuration(
            path=str(authority_state), owner_uid=os.getuid(), group_gid=os.getgid(),
            owned_start=1,
        )
        authority_read = authority_configuration.read
        saved = self.sandbox.directory / "saved-authority"
        changed = False
        def replace_directory(fd: int, size: int) -> object:
            nonlocal changed
            if not changed:
                changed = True
                authority.rename(saved)
                authority.mkdir(mode=0o700)
                replacement = authority / "state.json"
                replacement.write_bytes(state().canonical_bytes())
                replacement.chmod(0o600)
            return authority_read(fd, size)
        object.__setattr__(value, "_configuration", replace(
            authority_configuration, read=replace_directory,
        ))
        self.unavailable(value.load)

    def test_directory_residue_created_during_read_prevents_load(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_read = configuration.read
        residue = self.sandbox.directory / ".state.json.tmp"
        created = False

        def add_residue(descriptor: int, size: int) -> object:
            nonlocal created
            if not created:
                created = True
                residue.write_bytes(b"residue")
                residue.chmod(0o600)
            return real_read(descriptor, size)

        object.__setattr__(
            self.store, "_configuration", replace(configuration, read=add_residue),
        )
        self.unavailable(self.store.load)
        self.assertTrue(residue.exists())

    def test_inheritable_descriptor_is_rejected(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        object.__setattr__(self.store, "_configuration", replace(
            configuration, get_inheritable=lambda fd: True,
        ))
        self.unavailable(self.store.load)

    def test_preexisting_temporary_or_other_residue_rejects(self) -> None:
        for name in (".state.json.tmp", "unexpected"):
            residue = self.sandbox.directory / name
            residue.write_bytes(b"marker")
            residue.chmod(0o600)
            with self.subTest(name=name):
                self.unavailable(self.store.load)
            residue.unlink()


class SaveAndDurabilityTests(StateStoreTestCase):
    def test_save_canonical_round_trip_and_temp_absence(self) -> None:
        target = state(candidate=True)
        self.assertIsNone(self.store.save(target))
        self.assertEqual(self.sandbox.path.read_bytes(), target.canonical_bytes())
        self.assertEqual(self.store.load(), target)
        self.assertFalse((self.sandbox.directory / ".state.json.tmp").exists())
        metadata = self.sandbox.path.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)

    def test_nonstate_subclass_and_hostile_nested_values_reject_before_io(self) -> None:
        class StateChild(DeploymentState):
            pass
        class TextChild(str):
            def __eq__(self, other: object) -> bool:
                raise AssertionError("equality-marker")
        invalid = [None, object(), StateChild(**state().__dict__)]
        hostile = state()
        object.__setattr__(hostile, "event_id", TextChild("state-1"))
        invalid.append(hostile)
        configuration = object.__getattribute__(self.store, "_configuration")
        def no_open(*args: object, **kwargs: object) -> object:
            raise AssertionError("filesystem-marker")
        for value in invalid:
            object.__setattr__(self.store, "_configuration", replace(configuration, open_file=no_open))
            with self.subTest(value=type(value).__name__):
                self.unavailable(lambda value=value: self.store.save(value))  # type: ignore[arg-type]

    def test_shadowed_serialization_conversion_iteration_and_deepcopy_are_not_used(self) -> None:
        value = state(candidate=True)
        def hostile(*args: object, **kwargs: object) -> object:
            raise AssertionError("serialization-marker")
        object.__setattr__(value, "to_dict", hostile)
        object.__setattr__(value, "canonical_bytes", hostile)
        object.__setattr__(value, "__iter__", hostile)
        object.__setattr__(value, "__deepcopy__", hostile)
        self.assertIsNone(self.store.save(value))
        self.assertEqual(self.store.load().candidate_slot, "green")

    def test_mutation_between_repeated_snapshots_rejects_before_filesystem(self) -> None:
        value = state(candidate=True)
        configuration = object.__getattribute__(self.store, "_configuration")
        calls = 0
        real = configuration.canonicalizer
        def mutate(mapping: object) -> bytes:
            nonlocal calls
            calls += 1
            result = real(mapping)
            if calls == 1:
                object.__setattr__(value, "event_id", "mutated-event")
            return result
        def no_open(*args: object, **kwargs: object) -> object:
            raise AssertionError("filesystem-marker")
        object.__setattr__(self.store, "_configuration", replace(
            configuration, canonicalizer=mutate, open_file=no_open,
        ))
        self.unavailable(lambda: self.store.save(value))

    def test_preexisting_temporary_residue_preserves_original(self) -> None:
        original = self.sandbox.path.read_bytes()
        temporary = self.sandbox.directory / ".state.json.tmp"
        temporary.write_bytes(b"residue")
        temporary.chmod(0o600)
        self.unavailable(lambda: self.store.save(state(candidate=True)))
        self.assertEqual(self.sandbox.path.read_bytes(), original)
        self.assertEqual(temporary.read_bytes(), b"residue")

    def test_partial_writes_complete_and_order_fsync_before_replace_then_directory(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_write, real_fsync, real_replace = (
            configuration.write, configuration.fsync, configuration.replace,
        )
        events: list[tuple[str, int | None]] = []
        def partial(fd: int, value: object) -> int:
            return real_write(fd, bytes(value)[:32])
        def sync(fd: int) -> None:
            events.append(("fsync", fd))
            real_fsync(fd)
        def replace_file(*args: object, **kwargs: object) -> None:
            events.append(("replace", None))
            real_replace(*args, **kwargs)
        object.__setattr__(self.store, "_configuration", replace(
            configuration, write=partial, fsync=sync, replace=replace_file,
        ))
        self.assertIsNone(self.store.save(state(candidate=True)))
        replace_index = events.index(("replace", None))
        self.assertEqual(events[replace_index - 1][0], "fsync")
        self.assertEqual(events[replace_index + 1][0], "fsync")

    def test_temporary_creation_is_exclusive_nofollow_cloexec_and_owner_only(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_open = configuration.open_file
        observed: list[tuple[int, int]] = []
        def inspect_open(path: object, flags: int, *args: object, **kwargs: object) -> object:
            if path == ".state.json.tmp":
                observed.append((flags, args[0]))
            return real_open(path, flags, *args, **kwargs)
        object.__setattr__(self.store, "_configuration", replace(
            configuration, open_file=inspect_open,
        ))
        self.store.save(state(candidate=True))
        self.assertEqual(len(observed), 1)
        flags, mode = observed[0]
        for required in (os.O_CREAT, os.O_EXCL, os.O_NOFOLLOW, os.O_CLOEXEC):
            self.assertEqual(flags & required, required)
        self.assertEqual(mode, 0o600)

    def test_zero_excessive_and_malformed_writes_preserve_original_and_cleanup(self) -> None:
        original = self.sandbox.path.read_bytes()
        configuration = object.__getattribute__(self.store, "_configuration")
        writers = (
            lambda fd, value: 0,
            lambda fd, value: True,
            lambda fd, value: len(value) + 1,
            lambda fd, value: 1,
        )
        for writer in writers:
            object.__setattr__(self.store, "_configuration", replace(configuration, write=writer))
            with self.subTest(writer=writer):
                self.unavailable(lambda: self.store.save(state(candidate=True)))
                self.assertEqual(self.sandbox.path.read_bytes(), original)
                self.assertFalse((self.sandbox.directory / ".state.json.tmp").exists())

    def test_open_write_fsync_and_replace_failures_preserve_original_before_replace(self) -> None:
        original = self.sandbox.path.read_bytes()
        configuration = object.__getattribute__(self.store, "_configuration")
        real_open = configuration.open_file
        cases: list[tuple[str, object]] = []
        def fail_temp_open(path: object, flags: int, *args: object, **kwargs: object) -> object:
            if path == ".state.json.tmp":
                raise OSError("open-injected-marker")
            return real_open(path, flags, *args, **kwargs)
        cases.append(("open_file", fail_temp_open))
        cases.append(("write", lambda fd, value: (_ for _ in ()).throw(OSError("write-marker"))))
        real_fsync = configuration.fsync
        cases.append(("fsync", lambda fd: (_ for _ in ()).throw(OSError("fsync-marker"))))
        cases.append(("replace", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("replace-marker"))))
        for field, operation in cases:
            kwargs = {field: operation}
            object.__setattr__(self.store, "_configuration", replace(configuration, **kwargs))
            with self.subTest(field=field):
                self.unavailable(lambda: self.store.save(state(candidate=True)), "marker")
                self.assertEqual(self.sandbox.path.read_bytes(), original)

    def test_postreplacement_directory_fsync_failure_reports_uncertainty(self) -> None:
        target = state(candidate=True)
        configuration = object.__getattribute__(self.store, "_configuration")
        real_fsync = configuration.fsync
        real_replace = configuration.replace
        replaced = False
        def observe_replace(*args: object, **kwargs: object) -> None:
            nonlocal replaced
            real_replace(*args, **kwargs)
            replaced = True
        def fail_after(fd: int) -> None:
            if replaced:
                raise OSError("durability-injected-marker")
            real_fsync(fd)
        object.__setattr__(self.store, "_configuration", replace(
            configuration, replace=observe_replace, fsync=fail_after,
        ))
        self.unavailable(lambda: self.store.save(target), "durability-injected-marker")
        self.assertEqual(self.sandbox.path.read_bytes(), target.canonical_bytes())

    def test_postreplacement_verification_failure_reports_uncertainty(self) -> None:
        target = state(candidate=True)
        configuration = object.__getattribute__(self.store, "_configuration")
        real_replace, real_read = configuration.replace, configuration.read
        replaced = False
        def observe(*args: object, **kwargs: object) -> None:
            nonlocal replaced
            real_replace(*args, **kwargs)
            replaced = True
        def fail_verification(fd: int, size: int) -> object:
            if replaced:
                raise OSError("verify-injected-marker")
            return real_read(fd, size)
        object.__setattr__(self.store, "_configuration", replace(
            configuration, replace=observe, read=fail_verification,
        ))
        self.unavailable(lambda: self.store.save(target), "verify-injected-marker")
        self.assertEqual(self.sandbox.path.read_bytes(), target.canonical_bytes())

    def test_substituted_temporary_cleanup_target_is_not_removed(self) -> None:
        original = self.sandbox.path.read_bytes()
        configuration = object.__getattribute__(self.store, "_configuration")
        real_write = configuration.write
        temporary = self.sandbox.directory / ".state.json.tmp"
        saved = self.sandbox.directory / "saved-temp"
        changed = False
        def substitute(fd: int, value: object) -> int:
            nonlocal changed
            if not changed:
                changed = True
                temporary.rename(saved)
                temporary.write_bytes(b"substituted")
                temporary.chmod(0o600)
                raise OSError("substitution-marker")
            return real_write(fd, value)
        object.__setattr__(self.store, "_configuration", replace(configuration, write=substitute))
        self.unavailable(lambda: self.store.save(state(candidate=True)))
        self.assertEqual(self.sandbox.path.read_bytes(), original)
        self.assertEqual(temporary.read_bytes(), b"substituted")

    def test_existing_state_must_be_canonical_before_save(self) -> None:
        original = json.dumps(state().to_dict(), indent=2).encode()
        self.sandbox.path.write_bytes(original)
        self.sandbox.path.chmod(0o600)
        self.unavailable(lambda: self.store.save(state(candidate=True)))
        self.assertEqual(self.sandbox.path.read_bytes(), original)


class CoordinationCleanupAndErrorTests(StateStoreTestCase):
    def test_nonblocking_lock_contention_fails_closed(self) -> None:
        descriptor = os.open(self.sandbox.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(fcntl.flock, descriptor, fcntl.LOCK_UN)
        self.unavailable(self.store.load)

    def test_separate_process_lock_contention_fails_without_waiting(self) -> None:
        context = multiprocessing.get_context("fork")
        ready = context.Event()
        release = context.Event()
        process = context.Process(
            target=_hold_directory_lock,
            args=(str(self.sandbox.directory), ready, release),
        )
        process.start()
        try:
            self.assertTrue(ready.wait(5))
            self.unavailable(self.store.load)
        finally:
            release.set()
            process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)
        self.assertEqual(process.exitcode, 0)

    def test_reentrant_and_separate_instance_thread_contention(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_read = configuration.read
        entered = threading.Event()
        release = threading.Event()
        def blocked(fd: int, size: int) -> object:
            entered.set()
            if not release.wait(5):
                raise AssertionError("coordination-marker")
            return real_read(fd, size)
        object.__setattr__(self.store, "_configuration", replace(configuration, read=blocked))
        results: list[object] = []
        thread = threading.Thread(target=lambda: results.append(self.store.load()))
        thread.start()
        self.assertTrue(entered.wait(5))
        other = self.sandbox.store()
        self.unavailable(other.load)
        self.unavailable(self.store.load)
        release.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)

    def test_reentrant_call_from_read_is_rejected_without_deadlock(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_read = configuration.read
        nested: list[BaseException] = []
        called = False
        def reenter(fd: int, size: int) -> object:
            nonlocal called
            if not called:
                called = True
                try:
                    self.store.load()
                except BaseException as error:
                    nested.append(error)
            return real_read(fd, size)
        object.__setattr__(self.store, "_configuration", replace(configuration, read=reenter))
        self.assertEqual(self.store.load(), state())
        self.assertEqual(len(nested), 1)
        self.assertIsInstance(nested[0], StateStoreUnavailableError)

    def test_lock_unlock_close_and_scan_cleanup_failures_are_generic(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        real_flock, real_close = configuration.flock, configuration.close_file
        def unlock_failure(fd: int, operation: int) -> object:
            if operation == configuration.lock_unlock:
                raise OSError("unlock-injected-marker")
            return real_flock(fd, operation)
        object.__setattr__(self.store, "_configuration", replace(configuration, flock=unlock_failure))
        self.unavailable(self.store.load, "unlock-injected-marker")
        object.__setattr__(self.store, "_configuration", replace(
            configuration, close_file=lambda fd: (real_close(fd), "bad")[1],
        ))
        self.unavailable(self.store.load)

    def test_control_flow_exceptions_preserved_and_resources_released(self) -> None:
        for error_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            configuration = object.__getattribute__(self.store, "_configuration")
            def interrupt(fd: int, size: int, error_type: type[BaseException] = error_type) -> object:
                raise error_type("control-marker")
            object.__setattr__(self.store, "_configuration", replace(configuration, read=interrupt))
            with self.subTest(error_type=error_type), self.assertRaises(error_type):
                self.store.load()
            object.__setattr__(self.store, "_configuration", configuration)
            self.assertEqual(self.store.load(), state())

    def test_scan_cleanup_cannot_replace_control_flow_exceptions(self) -> None:
        for error_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(error_type=error_type):
                store = self.sandbox.store()
                configuration = object.__getattribute__(store, "_configuration")

                class Iterator:
                    def __iter__(self):
                        return self

                    def __next__(self):
                        raise error_type("primary-control-marker")

                    def close(self):
                        raise OSError("scan-cleanup-marker")

                object.__setattr__(
                    store, "_configuration",
                    replace(configuration, scandir=lambda _descriptor: Iterator()),
                )
                with self.assertRaises(error_type) as caught:
                    store.load()
                self.assertEqual(str(caught.exception), "primary-control-marker")

    def test_generic_error_redacts_all_sensitive_markers(self) -> None:
        markers = (
            PRODUCTION_DEV_STATE_PATH, ".state.json.tmp", "uid=1", "gid=2",
            "inode=3", "sha256:" + "a" * 64, "release-0.14.2",
            "dependency-injected-marker",
        )
        configuration = object.__getattribute__(self.store, "_configuration")
        def fail(*args: object, **kwargs: object) -> object:
            raise OSError(" ".join(markers))
        object.__setattr__(self.store, "_configuration", replace(configuration, open_file=fail))
        error = self.unavailable(self.store.load)
        self.assertEqual(str(error), STATE_STORE_UNAVAILABLE_MESSAGE)
        for marker in markers:
            self.assertNotIn(marker, str(error))

    def test_error_boundary_is_captured_against_module_replacement(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        object.__setattr__(self.store, "_configuration", replace(
            configuration,
            open_file=lambda *args, **kwargs: (_ for _ in ()).throw(OSError("cause-marker")),
        ))
        with (
            patch.object(store_module, "_unavailable", side_effect=AssertionError("factory-marker")),
            patch.object(store_module, "STATE_STORE_UNAVAILABLE_MESSAGE", "message-marker"),
            patch.object(store_module, "StateStoreUnavailableError", RuntimeError),
        ):
            self.unavailable(self.store.load, "marker")

    def test_production_path_is_never_accessed_by_tests(self) -> None:
        configuration = object.__getattribute__(self.store, "_configuration")
        self.assertNotEqual(configuration.path, PRODUCTION_DEV_STATE_PATH)
        self.assertTrue(configuration.path.startswith(self.sandbox.temporary.name + "/"))


if __name__ == "__main__":
    unittest.main()
