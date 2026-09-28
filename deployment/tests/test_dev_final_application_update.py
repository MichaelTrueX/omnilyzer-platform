"""C32W root-only migration tests use disposable application/config sandboxes."""

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from deployment import application_manifest as c26
from deployment import dev_host_provisioning_orchestration as c31
from deployment import dev_post_c31_application_update as c32d
from deployment import dev_post_provision_qualification as c31d
from deployment import executor_service_config as c17
from deployment import final_application_generation as frozen
import deployment.dev_final_application_update as module
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]


class _Observed:
    pass


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="task014-c32w-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / "app"
        self.app.mkdir(mode=0o755)
        self.app.chmod(0o755)
        self.config_dir = self.root / "dev"
        self.config_dir.mkdir(mode=0o750)
        self.config_dir.chmod(0o750)
        self.config_path = self.config_dir / "executor.json"
        self.uid, self.gid = os.getuid(), os.getgid()
        self.patches = ExitStack()
        for owner, name, value in (
            (module, "_APP_ROOT", str(self.app)), (module, "_CONFIG", str(self.config_path)),
            (module, "_APP_UID", self.uid), (module, "_APP_GID", self.gid),
            (module, "_CONFIG_UID", self.uid), (c32d, "CONFIG", str(self.config_path)),
            (c32d, "CONFIG_UID", self.uid),
        ):
            self.patches.enter_context(patch.object(owner, name, value))
        self.patches.enter_context(patch.object(c31d, "DevPostProvisionEvidence", _Observed))
        self.patches.enter_context(patch.object(c31d, "qualify_dev_provisioned_host",
                                                return_value=_Observed()))
        self.patches.enter_context(patch.object(c32d, "_qualify_non_application"))
        self.addCleanup(self.patches.close)

    def prepare(self, predecessor=c32d.PREDECESSOR):
        self.previous, self.target, self.blobs, self.plan, self.old_paths = module._evidence(predecessor)
        self.old_blobs = dict(c32d._git_blobs(predecessor,
            tuple(item.path for item in self.previous.entries)))
        for path, raw in self.old_blobs.items():
            destination = self.app / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.parent.chmod(0o755)
            destination.write_bytes(raw)
            destination.chmod(0o644)
        for directory in self.app.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        values = configuration_values(reviewed_commit=predecessor)
        values["executor_gid"] = self.gid
        self.configuration = c17.DevExecutorServiceConfiguration(**values)
        original = replace(self.configuration, reviewed_commit=c32d.PREDECESSOR)
        self.patches.enter_context(patch.object(c32d, "PREDECESSOR_C17",
                                                hashlib.sha256(original.canonical_bytes()).hexdigest()))
        self.config_path.write_bytes(self.configuration.canonical_bytes())
        self.config_path.chmod(0o640)

    def advance_files(self, count):
        for path in self.plan[:count]:
            destination = self.app / path
            destination.write_bytes(self.blobs[path])
            destination.chmod(0o644)

    def inspect(self):
        return module._application_state(self.previous, self.target, self.blobs, self.plan)


class PlanAndSelectionTests(Sandbox):
    def test_both_plans_are_exact_supersets_and_pinned(self):
        for predecessor, old_count, additions, replacements in (
            (c32d.PREDECESSOR, 28, 13, 3), (c32d.TARGET, 31, 10, 6),
        ):
            with self.subTest(predecessor=predecessor):
                previous, target, blobs, plan, old = module._evidence(predecessor)
                self.assertEqual((len(previous.entries), len(target.entries), len(plan)),
                                 (old_count, 41, 16))
                self.assertTrue(old < set(blobs))
                self.assertEqual((sum(path not in old for path in plan),
                                  sum(path in old for path in plan)),
                                 (additions, replacements))
                self.assertEqual(hashlib.sha256(("\n".join(plan) + "\n").encode()).hexdigest(),
                                 frozen.TARGET_PLAN_SHA256)
        with self.assertRaises(OSError):
            module._evidence("a" * 40)

    def test_installed_canonical_config_selects_generation_and_only_commit_changes(self):
        for predecessor in (c32d.PREDECESSOR, c32d.TARGET):
            with self.subTest(predecessor=predecessor):
                self.prepare(predecessor)
                selected, raw, target_raw = module._configuration()
                self.assertEqual(selected.reviewed_commit, predecessor)
                self.assertEqual(raw, selected.canonical_bytes())
                target = c17.parse_canonical_executor_service_configuration(target_raw)
                self.assertEqual({key for key, value in selected.to_dict().items()
                                  if value != target.to_dict()[key]}, {"reviewed_commit"})
                self.assertEqual(target.reviewed_commit, frozen.TARGET_REVIEWED_COMMIT)
                self.assertEqual(selected.runtime_configuration_sha256,
                                 frozen.TARGET_RUNTIME_SHA256)
                self.assertEqual(selected.ingress_file_sha256,
                                 frozen.TARGET_INGRESS_SHA256)

    def test_wrong_config_authority_rejected_before_application_mutation(self):
        self.prepare()
        initial = self.config_path.read_bytes()
        for values in (
            {"reviewed_commit": "a" * 40},
            {"runtime_configuration_sha256": "a" * 64},
            *({"ingress_file_sha256": tuple(
                "a" * 64 if index == changed else value
                for index, value in enumerate(self.configuration.ingress_file_sha256))}
              for changed in range(3)),
        ):
            with self.subTest(values=values):
                forged = replace(self.configuration, **values)
                self.config_path.write_bytes(forged.canonical_bytes())
                with self.assertRaises(OSError):
                    module._configuration()
        self.config_path.write_bytes(initial)


class PrefixAndMutationTests(Sandbox):
    def test_all_exact_prefixes_and_partial_next_stage(self):
        self.prepare()
        for count in range(len(self.plan) + 1):
            with self.subTest(count=count):
                self.assertEqual(self.inspect(), (count, None))
                if count < len(self.plan):
                    payload = self.blobs[self.plan[count]]
                    stage = self.app / "deployment" / module._APP_STAGE
                    stage.write_bytes(payload[:min(17, len(payload))])
                    stage.chmod(0o600)
                    self.assertEqual(self.inspect()[0], count)
                    stage.unlink()
                    self.advance_files(count + 1)

    def test_out_of_order_wrong_stage_extra_symlink_hardlink_and_mode_rejected(self):
        self.prepare()
        first = self.plan[0]
        stage = self.app / "deployment" / module._APP_STAGE
        stage.write_bytes(b"wrong prefix")
        stage.chmod(0o600)
        with self.assertRaises(OSError):self.inspect()
        stage.unlink()
        destination = self.app / self.plan[2]
        destination.write_bytes(self.blobs[self.plan[2]])
        destination.chmod(0o644)
        with self.assertRaises(OSError):self.inspect()
        destination.unlink()
        extra = self.app / "deployment" / "unlisted.py"
        extra.write_bytes(b"x")
        with self.assertRaises(OSError):self.inspect()
        extra.unlink()
        target = self.app / "deployment/broker.py"
        target.chmod(0o600)
        with self.assertRaises(OSError):self.inspect()
        target.chmod(0o644)
        linked = self.root / "linked"
        os.link(target, linked)
        with self.assertRaises(OSError):self.inspect()
        linked.unlink()
        target.unlink()
        target.symlink_to(self.root / "outside")
        with self.assertRaises(OSError):self.inspect()
        target.unlink()
        target.write_bytes(self.old_blobs["deployment/broker.py"])
        target.chmod(0o644)
        self.assertEqual(self.inspect(), (0, None))

    def test_config_generation_mismatch_and_partial_c32d_rejected(self):
        self.prepare(c32d.PREDECESSOR)
        self.config_path.write_bytes(replace(self.configuration,
            reviewed_commit=c32d.TARGET).canonical_bytes())
        selected, raw, target_raw = module._configuration()
        previous, target, blobs, plan, _old = module._evidence(selected.reviewed_commit)
        with self.assertRaises(OSError):
            module._inspect(previous, target, blobs, plan, raw, target_raw)
        self.config_path.write_bytes(self.configuration.canonical_bytes())
        # A partial C32D change is not the first C32W plan step.
        broker = self.app / "deployment/broker.py"
        broker.write_bytes(dict(c32d._git_blobs(c32d.TARGET,
                         ("deployment/broker.py",)))["deployment/broker.py"])
        broker.chmod(0o644)
        with self.assertRaises(OSError):self.inspect()

    def test_new_file_publication_is_exclusive_and_resumable(self):
        self.prepare()
        destination = self.plan[0].split("/", 1)[1]
        payload = self.blobs[self.plan[0]]
        directory = os.open(self.app / "deployment", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, directory)
        original = module._rename_noreplace
        def race(fd, source, target):
            with open(self.app / "deployment" / target, "wb") as output:
                output.write(b"unexpected")
            original(fd, source, target)
        with patch.object(module, "_rename_noreplace", side_effect=race), self.assertRaises(OSError):
            module._write_add_stage(directory, destination, payload, None)
        self.assertEqual((self.app / "deployment" / destination).read_bytes(), b"unexpected")
        (self.app / "deployment" / destination).unlink()
        self.assertEqual(self.inspect()[0], 0)  # exact complete staging payload
        stage = module.c32d._stage(directory, module._APP_STAGE, payload, 0o644,
                                   self.uid, self.gid)
        module._write_add_stage(directory, destination, payload, stage)
        self.assertFalse((self.app / "deployment" / module._APP_STAGE).exists())
        self.assertEqual((self.app / "deployment" / destination).read_bytes(), payload)
        self.assertEqual(self.inspect(), (1, None))

    def test_published_file_does_not_validate_a_replaced_application_directory(self):
        self.prepare()
        raw = self.configuration.canonical_bytes()
        target_raw = replace(self.configuration,
            reviewed_commit=frozen.TARGET_REVIEWED_COMMIT).canonical_bytes()
        state = module._inspect(self.previous, self.target, self.blobs, self.plan,
                                raw, target_raw)
        original = module._write_add_stage
        deployment = self.app / "deployment"
        displaced = self.app / "displaced"
        def replace_directory(*args):
            original(*args)
            deployment.rename(displaced)
            deployment.mkdir(mode=0o755)
            deployment.chmod(0o755)
        with patch.object(module, "_write_add_stage", side_effect=replace_directory), \
             self.assertRaises(OSError):
            module._advance_application(self.previous, self.target, self.blobs,
                self.plan, self.old_paths, raw, target_raw, state)
        self.assertTrue((displaced / self.plan[0].split("/", 1)[1]).is_file())
        self.assertFalse((deployment / self.plan[0].split("/", 1)[1]).exists())

    def test_public_root_lock_and_complete_idempotent_update(self):
        self.prepare(c32d.TARGET)
        with patch.object(module.os, "geteuid", return_value=self.uid), \
             patch.object(c31, "_acquire_process_lock") as acquire, \
             self.assertRaises(module.FinalApplicationUpdateError):
            module.update_final_application()
        acquire.assert_not_called()
        real_lock = c31._acquire_process_lock
        locks = []
        def acquire():
            value = real_lock(str(self.root))
            locks.append(value)
            return value
        with patch.object(module.os, "geteuid", return_value=0), \
             patch.object(module.os, "getegid", return_value=0), \
             patch.object(c31, "_acquire_process_lock", side_effect=acquire):
            final = module.update_final_application()
            self.assertTrue(final.configuration_current)
            self.assertEqual(final.advanced_count, 16)
            self.assertEqual(c17.parse_canonical_executor_service_configuration(
                self.config_path.read_bytes()).reviewed_commit, frozen.TARGET_REVIEWED_COMMIT)
            before = {p: (p.stat().st_ino, p.read_bytes()) for p in self.app.rglob("*") if p.is_file()}
            again = module.update_final_application()
            self.assertEqual(again, final)
            self.assertEqual(before, {p: (p.stat().st_ino, p.read_bytes())
                                      for p in self.app.rglob("*") if p.is_file()})
        self.assertEqual(len(locks), 2)
        self.assertFalse((self.app / "deployment" / module._APP_STAGE).exists())
        self.assertFalse((self.config_dir / module._CONFIG_STAGE).exists())

    def test_c31_complete_migrates_and_config_switch_is_last(self):
        self.prepare(c32d.PREDECESSOR)
        real_lock = c31._acquire_process_lock
        real_replace = os.replace
        events = []
        def replace_after_app(source, destination, **kwargs):
            if destination == "executor.json":
                events.append("config")
                self.assertEqual(self.inspect(), (16, None))
                self.assertEqual(self.config_path.read_bytes(),
                                 self.configuration.canonical_bytes())
            return real_replace(source, destination, **kwargs)
        with patch.object(module.os, "geteuid", return_value=0), \
             patch.object(module.os, "getegid", return_value=0), \
             patch.object(c31, "_acquire_process_lock",
                          side_effect=lambda: real_lock(str(self.root))), \
             patch.object(os, "replace", side_effect=replace_after_app):
            result = module.update_final_application()
        self.assertEqual(events, ["config"])
        self.assertTrue(result.configuration_current)
        self.assertEqual(c17.parse_canonical_executor_service_configuration(
            self.config_path.read_bytes()).reviewed_commit, frozen.TARGET_REVIEWED_COMMIT)

    def test_lock_acquisition_and_release_fail_closed(self):
        self.prepare()
        with patch.object(module.os, "geteuid", return_value=0), \
             patch.object(module.os, "getegid", return_value=0), \
             patch.object(c31, "_acquire_process_lock", side_effect=OSError), \
             self.assertRaises(module.FinalApplicationUpdateError):
            module.update_final_application()
        with patch.object(module.os, "geteuid", return_value=0), \
             patch.object(module.os, "getegid", return_value=0), \
             patch.object(c31, "_acquire_process_lock", return_value=object()), \
             patch.object(c31, "_release_process_lock", side_effect=OSError), \
             patch.object(module, "_load", side_effect=OSError), \
             self.assertRaisesRegex(module.FinalApplicationUpdateError,
                                         "^final DEV application update is unavailable$"):
            module.update_final_application()

    def test_complete_target_config_requires_complete_target_application(self):
        self.prepare()
        self.config_path.write_bytes(replace(self.configuration,
            reviewed_commit=frozen.TARGET_REVIEWED_COMMIT).canonical_bytes())
        with self.assertRaises(module.FinalApplicationUpdateError):
            module.qualify_final_application_update()
        self.advance_files(16)
        state = module.qualify_final_application_update()
        self.assertTrue(state.configuration_current)
        self.assertFalse((self.app / "deployment" / module._APP_STAGE).exists())


if __name__ == "__main__":
    unittest.main()
