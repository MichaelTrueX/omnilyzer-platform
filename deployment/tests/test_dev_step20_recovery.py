"""Exact prefix recovery for the pinned e386 C25 transition."""

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from deployment import application_manifest as c26
from deployment import dev_step20_recovery as recovery
from deployment import dev_host_provisioning_mechanics as mechanics
from deployment.application_source_set import DevApplicationSourceSet
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values


class ApplicationPrefixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="c31-step20-app-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "app"
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        self.old = {}
        self.new = {}
        old_entries = []
        new_entries = []
        for source in DevApplicationSourceSet().files:
            path = source.repository_path
            old = ("old:" + path).encode()
            new = ("new:" + path).encode() if path in recovery.CHANGED else old
            self.old[path], self.new[path] = old, new
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.parent.chmod(0o755)
            target.write_bytes(old)
            target.chmod(0o644)
            old_entries.append(c26.ApplicationManifestEntry(path, hashlib.sha256(old).hexdigest(), "0644"))
            new_entries.append(c26.ApplicationManifestEntry(path, hashlib.sha256(new).hexdigest(), "0644"))
        for directory in self.root.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        self.previous = c26.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", recovery.PREDECESSOR,
            tuple(old_entries),
        )
        self.current = c26.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", "a" * 40,
            tuple(new_entries),
        )
        self.patches = ExitStack()
        self.patches.enter_context(patch.object(recovery, "APP_ROOT", str(self.root)))
        self.patches.enter_context(patch.object(recovery, "APP_UID", os.getuid()))
        self.patches.enter_context(patch.object(recovery, "APP_GID", os.getgid()))
        self.addCleanup(self.patches.close)

    def test_each_completed_replacement_is_an_exact_resumable_prefix(self):
        real_replace = os.replace
        for stop_after in range(1, len(recovery.CHANGED) + 1):
            with self.subTest(stop_after=stop_after):
                if stop_after > 1:
                    # Rebuild the old state for each independent crash point.
                    for path, payload in self.old.items():
                        target = self.root / path
                        target.write_bytes(payload)
                        target.chmod(0o644)
                count = 0

                def interrupt(*args, **kwargs):
                    nonlocal count
                    real_replace(*args, **kwargs)
                    count += 1
                    if count == stop_after:
                        raise OSError("simulated crash after rename")

                with patch.object(recovery.os, "replace", side_effect=interrupt):
                    with self.assertRaises(OSError):
                        recovery._migrate_application_bytes(self.previous, self.current, self.new)
                observed = recovery.inspect_application(self.previous, self.current, self.new)
                self.assertEqual((observed.replaced_count, observed.stage_length),
                                 (stop_after, None))
                self.assertEqual(recovery._migrate_application_bytes(self.previous, self.current, self.new),
                                 "migrated" if stop_after < len(recovery.CHANGED) else "retained-exact")
                self.assertEqual(recovery.inspect_application(self.previous, self.current, self.new).replaced_count,
                                 len(recovery.CHANGED))

    def test_failed_directory_sync_after_each_rename_is_retried_first(self):
        real_replace, real_fsync = os.replace, os.fsync
        deployment = self.root / "deployment"
        deployment_identity = (deployment.stat().st_dev, deployment.stat().st_ino)
        for stop_after in range(1, len(recovery.CHANGED) + 1):
            with self.subTest(stop_after=stop_after):
                stage = self.root / recovery.STAGE_RELATIVE
                if stage.exists():
                    stage.unlink()
                for path, payload in self.old.items():
                    target = self.root / path
                    target.write_bytes(payload)
                    target.chmod(0o644)
                replacements = 0

                def replace_then_fail_sync(*args, **kwargs):
                    nonlocal replacements
                    real_replace(*args, **kwargs)
                    replacements += 1

                def interrupted_sync(descriptor):
                    if (replacements == stop_after
                        and (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                        == deployment_identity):
                        raise OSError("directory sync failed after rename")
                    return real_fsync(descriptor)

                with patch.object(recovery.os, "replace", side_effect=replace_then_fail_sync), \
                     patch.object(recovery.os, "fsync", side_effect=interrupted_sync):
                    with self.assertRaises(OSError):
                        recovery._migrate_application_bytes(self.previous, self.current, self.new)
                self.assertEqual(recovery.inspect_application(
                    self.previous, self.current, self.new).replaced_count, stop_after)

                prefix_synced = False

                def retry_sync(descriptor):
                    nonlocal prefix_synced
                    if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == deployment_identity:
                        prefix_synced = True
                    return real_fsync(descriptor)

                def next_replace(*args, **kwargs):
                    self.assertTrue(prefix_synced, "previous rename was not synced first")
                    return real_replace(*args, **kwargs)

                with patch.object(recovery.os, "fsync", side_effect=retry_sync), \
                     patch.object(recovery.os, "replace", side_effect=next_replace):
                    outcome = recovery._migrate_application_bytes(
                        self.previous, self.current, self.new)
                self.assertTrue(prefix_synced, "final prefix returned without sync")
                self.assertEqual(outcome, "retained-exact" if stop_after == len(recovery.CHANGED)
                                 else "migrated")

    def test_partial_stage_is_exact_prefix_and_resumable(self):
        from deployment import dev_host_provisioning_mechanics as mechanics
        real_write = mechanics._write_all

        def partial(descriptor, payload):
            os.write(descriptor, payload[:5])
            raise OSError("simulated interrupted write")

        with patch.object(mechanics, "_write_all", side_effect=partial):
            with self.assertRaises(OSError):
                recovery._migrate_application_bytes(self.previous, self.current, self.new)
        state = recovery.inspect_application(self.previous, self.current, self.new)
        self.assertEqual((state.replaced_count, state.stage_length, state.stage_mode),
                         (0, 5, 0o600))
        self.assertEqual(recovery._migrate_application_bytes(self.previous, self.current, self.new), "migrated")

    def test_read_only_application_inspection_never_syncs_or_replaces(self):
        with patch.object(recovery.os, "fsync", side_effect=AssertionError("mutation")) as sync, \
             patch.object(recovery.os, "replace", side_effect=AssertionError("mutation")) as replace_file:
            self.assertEqual(recovery.inspect_application(
                self.previous, self.current, self.new).replaced_count, 0)
        sync.assert_not_called()
        replace_file.assert_not_called()

    def test_foreign_stage_and_unexpected_application_entries_fail_closed(self):
        stage = self.root / recovery.STAGE_RELATIVE
        stage.write_bytes(b"foreign")
        stage.chmod(0o600)
        with self.assertRaises(OSError):
            recovery.inspect_application(self.previous, self.current, self.new)
        stage.unlink()
        extra = self.root / "deployment" / "unlisted.py"
        extra.write_bytes(b"unexpected")
        with self.assertRaises(OSError):
            recovery.inspect_application(self.previous, self.current, self.new)

    def test_symlink_and_hardlink_substitution_block_migration(self):
        target = self.root / recovery.CHANGED[0]
        original = target.read_bytes()
        target.unlink()
        target.symlink_to(self.root / recovery.CHANGED[1])
        with self.assertRaises(OSError):
            recovery._migrate_application_bytes(self.previous, self.current, self.new)
        target.unlink()
        target.write_bytes(original)
        target.chmod(0o644)
        alias = self.root / "deployment" / "alias"
        os.link(target, alias)
        try:
            with self.assertRaises(OSError):
                recovery._migrate_application_bytes(self.previous, self.current, self.new)
        finally:
            alias.unlink()


class ReplayDirectoryMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="c31-step20-replay-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "authority"
        self.directory.mkdir(mode=0o770)
        self.directory.chmod(0o770)
        self.patches = ExitStack()
        self.patches.enter_context(patch.object(recovery, "REPLAY_DIRECTORY", str(self.directory)))
        self.patches.enter_context(patch.object(recovery, "REPLAY_UID", os.getuid()))
        self.addCleanup(self.patches.close)

    def test_exact_old_to_setgid_is_idempotent(self):
        self.assertEqual(recovery.inspect_replay_directory(os.getgid()), "old")
        identity = (self.directory.stat().st_dev, self.directory.stat().st_ino)
        self.assertEqual(recovery.migrate_replay_directory(os.getgid()), "migrated")
        status = self.directory.stat()
        self.assertEqual((status.st_dev, status.st_ino), identity)
        self.assertEqual(stat.S_IMODE(status.st_mode), 0o2770)
        self.assertEqual(recovery.migrate_replay_directory(os.getgid()), "retained-exact")

    def test_failure_after_chmod_is_exact_new_state_on_rerun(self):
        real_fchmod = os.fchmod

        def interrupt(descriptor, mode):
            real_fchmod(descriptor, mode)
            raise OSError("interrupted after exact mode transition")

        with patch.object(recovery.os, "fchmod", side_effect=interrupt):
            with self.assertRaises(OSError):
                recovery.migrate_replay_directory(os.getgid())
        self.assertEqual(recovery.inspect_replay_directory(os.getgid()), "current")
        self.assertEqual(recovery.migrate_replay_directory(os.getgid()), "retained-exact")

    def test_failed_mode_sync_is_retried_before_replay_initialization(self):
        with patch.object(recovery.os, "fsync", side_effect=OSError("interrupted sync")):
            with self.assertRaises(OSError):
                recovery.migrate_replay_directory(os.getgid())
        self.assertEqual(recovery.inspect_replay_directory(os.getgid()), "current")
        with patch.object(recovery.os, "fsync", wraps=os.fsync) as sync:
            self.assertEqual(recovery.migrate_replay_directory(os.getgid()),
                             "retained-exact")
        self.assertEqual(sync.call_count, 2)

    def test_third_mode_wrong_gid_and_old_mode_residue_are_rejected(self):
        self.directory.chmod(0o1770)
        with self.assertRaises(OSError):
            recovery.migrate_replay_directory(os.getgid())
        self.directory.chmod(0o770)
        with self.assertRaises(OSError):
            recovery.migrate_replay_directory(os.getgid() + 1)
        (self.directory / "unexpected").write_bytes(b"poison")
        with self.assertRaises(OSError):
            recovery.migrate_replay_directory(os.getgid())


class PinnedManifestTests(unittest.TestCase):
    def test_exact_predecessor_and_commit_only_current_c17_pass_binding(self):
        predecessor = DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit=recovery.PREDECESSOR))
        current = replace(predecessor, reviewed_commit="a" * 40)
        pinned = hashlib.sha256(predecessor.canonical_bytes()).hexdigest()
        with patch.object(recovery, "PREDECESSOR_C17", pinned):
            self.assertIsNone(recovery.verify_current_c17(predecessor))
            self.assertIsNone(recovery.verify_current_c17(current))
            self.assertEqual(recovery.classify_installed_c17(
                current, predecessor.canonical_bytes()), "predecessor")
            self.assertEqual(recovery.classify_installed_c17(
                current, current.canonical_bytes()), "current")
            with self.assertRaises(OSError):
                recovery.classify_installed_c17(current, b"{}")

    def test_modified_current_c17_is_rejected_before_git_or_mutation(self):
        predecessor = DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit=recovery.PREDECESSOR))
        current = replace(predecessor, reviewed_commit="a" * 40)
        pinned = hashlib.sha256(predecessor.canonical_bytes()).hexdigest()
        manifest = c26.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", current.reviewed_commit,
            tuple(c26.ApplicationManifestEntry(item.repository_path, "b" * 64, "0644")
                  for item in DevApplicationSourceSet().files),
        )
        changed = replace(current, broker_uid=current.broker_uid + 100)
        with patch.object(recovery, "PREDECESSOR_C17", pinned), \
             patch.object(mechanics, "_run_git", side_effect=OSError) as git:
            with self.assertRaises(OSError):
                recovery.manifests(str(Path(__file__).resolve().parents[2]), changed, manifest)
            git.assert_not_called()

    def test_public_migration_derives_bytes_from_pinned_git_only(self):
        configuration = object()
        manifest = object()
        with patch.object(recovery, "manifests", return_value=("old", {}, {"new": b"x"})) as derive, \
             patch.object(recovery, "_migrate_application_bytes", return_value="migrated") as mutate:
            self.assertEqual(recovery.migrate_application("/reviewed/tree", configuration, manifest),
                             "migrated")
        derive.assert_called_once_with("/reviewed/tree", configuration, manifest)
        mutate.assert_called_once_with("old", manifest, {"new": b"x"})

    def test_unrelated_direct_or_indirect_parent_is_rejected_before_blob_read(self):
        commit = "a" * 40
        configuration = DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit=commit))
        predecessor = replace(configuration, reviewed_commit=recovery.PREDECESSOR)
        pin = patch.object(recovery, "PREDECESSOR_C17",
                           hashlib.sha256(predecessor.canonical_bytes()).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        manifest = c26.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", commit,
            tuple(c26.ApplicationManifestEntry(item.repository_path, "b" * 64, "0644")
                  for item in DevApplicationSourceSet().files),
        )
        repository = str(Path(__file__).resolve().parents[2])
        for parent in ("b" * 40, "b" * 40 + "\nparent " + "c" * 40):
            raw = ("tree " + "c" * 40 + "\nparent " + parent + "\n\nmessage").encode()
            with self.subTest(parent=parent), patch.object(
                mechanics, "_run_git", side_effect=[commit.encode() + b"\n", raw],
            ) as git:
                with self.assertRaises(OSError):
                    recovery.manifests(repository, configuration, manifest)
                self.assertEqual(git.call_count, 2)

        merge = ("tree " + "c" * 40 + "\nparent " + recovery.PREDECESSOR
                 + "\nparent " + "b" * 40 + "\n\nmessage").encode()
        with patch.object(mechanics, "_run_git", side_effect=[
            commit.encode() + b"\n", merge, OSError("later tree read"),
        ]) as git:
            with self.assertRaises(OSError):
                recovery.manifests(repository, configuration, manifest)
            self.assertEqual(git.call_count, 3)

    def test_exact_old_c25_and_only_three_intended_byte_changes(self):
        repository = Path(__file__).resolve().parents[2]
        paths = c26._predecessor_paths()
        owned = []
        try:
            descriptor, chain = mechanics._open_directory(str(repository), owned)
            records = c26._tree(mechanics._run_git(
                descriptor,
                ("ls-tree", "-r", "-z", "--full-tree", recovery.PREDECESSOR,
                 "--", *paths), 16384), paths)
            old_entries = []
            changed = []
            for path, blob in records:
                payload = mechanics._run_git(descriptor, ("cat-file", "blob", blob),
                                             mechanics._MAX_BLOB)
                old_hash = hashlib.sha256(payload).hexdigest()
                old_entries.append(c26.ApplicationManifestEntry(path, old_hash, "0644"))
                installed = mechanics._run_git(descriptor, ("cat-file", "blob",
                    "3ef02a6d61d20df3a1495b290c20807162b65b06:" + path),
                    mechanics._MAX_BLOB)
                if hashlib.sha256(installed).hexdigest() != old_hash:
                    changed.append(path)
            mechanics._revalidate_chain(chain)
        finally:
            mechanics._finish_close(owned)
        previous = c26.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", recovery.PREDECESSOR,
            tuple(old_entries),
        )
        self.assertEqual(hashlib.sha256(previous.canonical_bytes()).hexdigest(),
                         recovery.PREDECESSOR_C26)
        self.assertEqual(tuple(changed), recovery.CHANGED)
