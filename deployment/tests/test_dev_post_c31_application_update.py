"""C32D exact-generation and disposable interrupted-update attack tests."""

from contextlib import ExitStack
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import deployment.application_manifest as c26
import deployment.dev_post_c31_application_update as update
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]


class EvidenceTests(unittest.TestCase):
    def test_exact_pinned_git_generations_and_added_once(self):
        previous, target, blobs = update._evidence()
        self.assertEqual((previous.reviewed_commit, target.reviewed_commit),
                         (update.PREDECESSOR, update.TARGET))
        self.assertEqual((len(previous.entries), len(target.entries)), (28, 31))
        self.assertEqual(tuple(path for path in c26._paths() if path not in c26._predecessor_paths()),
                         update._ADDED)
        self.assertEqual(len(set(blobs)), 31)
        self.assertEqual(hashlib.sha256(previous.canonical_bytes()).hexdigest(), update.PREDECESSOR_C26)
        self.assertEqual(hashlib.sha256(target.canonical_bytes()).hexdigest(), update.TARGET_C26)
        self.assertNotEqual(dict(update._git_blobs(update.PREDECESSOR,
                             c26._predecessor_paths()))["deployment/broker.py"], blobs["deployment/broker.py"])

    def test_wrong_lineage_manifest_and_source_set_fail_closed(self):
        for name, value in (("PREDECESSOR", "a" * 40), ("TARGET", "b" * 40),
                            ("PREDECESSOR_C26", "0" * 64), ("TARGET_C26", "0" * 64)):
            with self.subTest(name=name), patch.object(update, name, value), self.assertRaises(Exception):
                update._evidence()
        with patch.object(c26, "_paths", return_value=c26._paths() + ("deployment/unreviewed.py",)):
            with self.assertRaises(Exception):
                update._evidence()
        with self.assertRaises(ValueError):
            c26.DevApplicationManifest(
                "canonical-relative-file-set-v1", "sha256", update.TARGET,
                tuple(c26.ApplicationManifestEntry(path, "a" * 64, "0644")
                      for path in (*c26._paths()[:-1], "deployment/unreviewed.py")),
            )

    def test_no_activation_or_host_operation_in_repository_contract(self):
        self.assertEqual(tuple(inspect.signature(update.update_post_c31_application).parameters), ())
        self.assertEqual(tuple(inspect.signature(update.qualify_post_c31_update).parameters), ())
        source = (ROOT / "deployment/dev_post_c31_application_update.py").read_text()
        for forbidden in ("socket.socket", ".bind(", ".listen(", "systemctl", "docker",
                          "https://", "http://", "subprocess.Popen", "__main__",
                          "initialize_deployment_state", "initialize_replay", "prepare_audit"):
            self.assertNotIn(forbidden, source)
        workflow = (ROOT / ".github/workflows/platform-promote.yml").read_text()
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("environment: task014-dev", workflow)
        self.assertIs(json.loads((ROOT / "deployment/environments/dev.json").read_text())
                      ["activation"]["deployment_enabled"], False)
        self.assertEqual(update.CHANGED, (
            "deployment/broker.py", "deployment/broker_integration.py",
            "deployment/oidc_verifier.py", "deployment/release_consumer.py",
        ))


class ApplicationUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "app"
        self.config = Path(self.temporary.name) / "config" / "executor.json"
        self.root.mkdir(mode=0o755)
        self.config.parent.mkdir(mode=0o750)
        self.config.parent.chmod(0o750)
        self.old = {}
        self.new = {}
        old_entries = []
        new_entries = []
        for path in c26._paths():
            old = ("old:" + path).encode()
            new = ("new:" + path).encode() if path in update.CHANGED else old
            self.new[path] = new
            new_entries.append(c26.ApplicationManifestEntry(path, hashlib.sha256(new).hexdigest(), "0644"))
            if path in c26._predecessor_paths():
                self.old[path] = old
                old_entries.append(c26.ApplicationManifestEntry(path, hashlib.sha256(old).hexdigest(), "0644"))
                target = self.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(old)
                target.chmod(0o644)
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
        self.previous = c26.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", update.PREDECESSOR, tuple(old_entries))
        self.target = c26.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", update.TARGET, tuple(new_entries))
        self.configuration = DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit=update.PREDECESSOR))
        self.old_raw = self.configuration.canonical_bytes()
        self.target_raw = DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit=update.TARGET)).canonical_bytes()
        self.config.write_bytes(self.old_raw)
        self.config.chmod(0o640)
        self.patches = ExitStack()
        for name, value in (("APP_ROOT", str(self.root)), ("CONFIG", str(self.config)),
                            ("APP_UID", os.getuid()), ("APP_GID", os.getgid()),
                            ("CONFIG_UID", os.getuid()),
                            ("PREDECESSOR_C17", hashlib.sha256(self.old_raw).hexdigest())):
            self.patches.enter_context(patch.object(update, name, value))
        self.addCleanup(self.patches.close)

    def inspect(self):
        return update._inspect(self.previous, self.target, self.new, self.old_raw, self.target_raw)

    def advance(self):
        state = self.inspect()
        if state.replaced_count < len(update.CHANGED):
            update._advance_application(self.previous, self.target, self.new,
                                        self.old_raw, self.target_raw, state)
        elif not state.configuration_current:
            update._advance_configuration(self.previous, self.target, self.new,
                                          self.old_raw, self.target_raw, state)

    def test_exact_predecessor_and_fixed_prefix_then_c17_last(self):
        self.assertEqual(update._configuration()[0].reviewed_commit, update.PREDECESSOR)
        self.assertEqual(self.inspect().replaced_count, 0)
        for index, path in enumerate(update.CHANGED, 1):
            self.advance()
            self.assertEqual(self.inspect().replaced_count, index)
            self.assertEqual((self.root / path).read_bytes(), self.new[path])
            self.assertEqual(self.config.read_bytes(), self.old_raw)
        self.advance()
        self.assertTrue(self.inspect().configuration_current)
        self.assertEqual(self.config.read_bytes(), self.target_raw)
        self.assertEqual(update._configuration()[0].reviewed_commit, update.PREDECESSOR)

    def test_read_only_qualification_requires_c31d_or_partial_nonapp(self):
        class Evidence:
            python_environment = type("PythonEvidence", (), {"payload_manifest_sha256": update.PYTHON_MANIFEST})()
            persistent_prerequisites = tuple(type("Persistent", (), {"outcome": outcome})()
                                             for outcome in ("verified-initial", "verified", "pristine"))
        with patch.object(update, "_evidence", return_value=(self.previous, self.target, self.new)), \
             patch.object(update.c31d, "DevPostProvisionEvidence", Evidence), \
             patch.object(update.c31d, "qualify_dev_provisioned_host", return_value=Evidence()) as full:
            state = update.qualify_post_c31_update()
            self.assertEqual(state.replaced_count, 0)
            full.assert_called_once()
            self.advance()
            with patch.object(update, "_qualify_non_application") as partial:
                self.assertEqual(update.qualify_post_c31_update().replaced_count, 1)
                partial.assert_called_once()
        with patch.object(update, "_evidence", return_value=(self.previous, self.target, self.new)), \
             patch.object(update, "_qualify_non_application", side_effect=OSError):
            with self.assertRaises(update.PostC31UpdateError):
                update.qualify_post_c31_update()

    def test_wrong_c17_and_config_metadata_rejected(self):
        with patch.object(update, "PREDECESSOR_C17", "0" * 64), self.assertRaises(OSError):
            update._configuration()
        self.config.write_bytes(b"{}")
        with self.assertRaises(Exception):
            update._configuration()
        self.config.write_bytes(self.old_raw)
        self.config.chmod(0o600)
        with self.assertRaises(OSError):
            self.inspect()

    def test_wrong_application_owner_and_group_rejected(self):
        original = os.fstat
        class ChangedStatus:
            def __init__(self, status, field):
                self.status = status
                self.field = field
            def __getattr__(self, name):
                value = getattr(self.status, name)
                return value + 1 if name == self.field else value
        for field in ("st_uid", "st_gid"):
            def changed(fd):
                status = original(fd)
                if os.readlink(f"/proc/self/fd/{fd}").endswith("/broker.py"):
                    return ChangedStatus(status, field)
                return status
            with self.subTest(field=field), patch.object(update.os, "fstat", side_effect=changed):
                with self.assertRaises(OSError):
                    self.inspect()

    def test_changed_missing_extra_symlink_hardlink_mode_and_type_rejected(self):
        path = self.root / c26._predecessor_paths()[0]
        for mutation in ("changed", "missing", "extra", "symlink", "hardlink", "mode", "type"):
            with self.subTest(mutation=mutation):
                original = path.read_bytes()
                extra = self.root / "deployment/unreviewed.py"
                linked = self.root / "deployment/link.py"
                try:
                    if mutation == "changed": path.write_bytes(b"wrong")
                    if mutation == "missing": path.unlink()
                    if mutation == "extra": extra.write_bytes(b"extra")
                    if mutation == "symlink":
                        path.unlink(); path.symlink_to(self.root / c26._predecessor_paths()[1])
                    if mutation == "hardlink": os.link(path, linked)
                    if mutation == "mode": path.chmod(0o600)
                    if mutation == "type":
                        path.unlink(); path.mkdir()
                    with self.assertRaises(OSError):
                        self.inspect()
                finally:
                    if path.is_dir() and not path.is_symlink(): path.rmdir()
                    elif path.exists() or path.is_symlink(): path.unlink()
                    path.write_bytes(original); path.chmod(0o644)
                    if extra.exists(): extra.unlink()
                    if linked.exists(): linked.unlink()

    def test_nonprefix_and_staged_mismatch_rejected(self):
        second = update.CHANGED[1]
        (self.root / second).write_bytes(self.new[second])
        (self.root / second).chmod(0o644)
        with self.assertRaises(OSError): self.inspect()
        (self.root / second).unlink()
        stage = self.root / "deployment" / update._APP_STAGE
        stage.write_bytes(b"wrong")
        stage.chmod(0o600)
        with self.assertRaises(OSError): self.inspect()

    def test_no_rollback_after_c17_commit(self):
        for _ in range(len(update.CHANGED) + 1): self.advance()
        self.assertTrue(self.inspect().configuration_current)
        first = update.CHANGED[0]
        (self.root / first).write_bytes(self.old[first])
        (self.root / first).chmod(0o644)
        with self.assertRaises(OSError): self.inspect()

    def test_full_operation_uses_fixed_state_and_no_host_entrypoint(self):
        with patch.object(update, "_evidence", return_value=(self.previous, self.target, self.new)), \
             patch.object(update, "_qualify_state", side_effect=lambda *args: self.inspect()) as qualify, \
             patch.object(update.os, "geteuid", return_value=0), \
             patch.object(update.os, "getegid", return_value=0), \
             patch.object(update.c31, "_acquire_process_lock", return_value=object()), \
             patch.object(update.c31, "_release_process_lock") as release:
            state = update.update_post_c31_application()
        self.assertTrue(state.configuration_current)
        self.assertEqual(qualify.call_count, len(update.CHANGED) + 2)
        release.assert_called_once()
        self.assertEqual(self.config.read_bytes(), self.target_raw)

    def test_public_update_rejects_unprivileged_invocation_before_lock(self):
        with patch.object(update.os, "geteuid", return_value=1), \
             patch.object(update.c31, "_acquire_process_lock") as acquire:
            with self.assertRaises(update.PostC31UpdateError):
                update.update_post_c31_application()
            acquire.assert_not_called()

    def test_configuration_stage_mismatch_and_interrupted_rename(self):
        for _ in update.CHANGED: self.advance()
        stage = self.config.parent / update._CONFIG_STAGE
        stage.write_bytes(b"wrong")
        stage.chmod(0o600)
        with self.assertRaises(OSError): self.inspect()
        stage.unlink()
        with patch.object(update.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError): self.advance()
        self.assertEqual(self.inspect().configuration_stage_length, len(self.target_raw))
        self.advance()
        self.assertTrue(self.inspect().configuration_current)

    def test_replace_failure_retains_exact_stage_and_resumes(self):
        with patch.object(update.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError): self.advance()
        state = self.inspect()
        self.assertEqual((state.replaced_count, state.application_stage_length),
                         (0, len(self.new[update.CHANGED[0]])))
        self.advance()
        self.assertEqual(self.inspect().replaced_count, 1)

    def test_file_fsync_and_directory_fsync_fail_closed_then_retry(self):
        original = os.fsync
        with patch.object(update.os, "fsync", side_effect=OSError("file sync failed")):
            with self.assertRaises(OSError): self.advance()
        self.assertEqual(self.inspect().replaced_count, 0)
        self.advance()
        self.assertEqual(self.inspect().replaced_count, 1)
        calls = 0
        def fail_directory(fd):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("directory sync failed")
            return original(fd)
        with patch.object(update.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError): self.advance()
        self.assertEqual(self.inspect().replaced_count, 2)
        self.advance()
        self.assertEqual(self.inspect().replaced_count, 3)


if __name__ == "__main__":
    unittest.main()
