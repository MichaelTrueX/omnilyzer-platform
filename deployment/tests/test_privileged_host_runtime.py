"""C30 privileged host-runtime authority and adversarial filesystem tests."""

import ast
import builtins
from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import deployment.executor_service_config as c17
import deployment.host_service_layout as c21
import deployment.host_provisioning_contract as c23
import deployment.installation_contract as c13
import deployment.installation_integrity_contract as c24
import deployment.privileged_host_runtime as module
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]
ERROR = "DEV privileged host operation is unavailable"


def setUpModule():
    """Refresh C30's contract graph after deliberate contract reload tests."""
    importlib.reload(c13)
    importlib.reload(c17)
    importlib.reload(c21)
    importlib.reload(c23)
    importlib.reload(c24)
    importlib.reload(module)


def runtime():
    configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
    return configuration, module.DevPrivilegedHostRuntime(configuration=configuration)


def temporary_authorities(temporary):
    parent = module._DirectoryAuthority(temporary, 0o700, os.getuid(), os.getgid())
    child_path = str(Path(temporary) / "managed")
    child = module._DirectoryAuthority(child_path, 0o750, os.getuid(), os.getgid())
    file = module._FileAuthority(str(Path(child_path) / "reviewed"), 0o640,
                                 os.getuid(), os.getgid())
    return parent, child, file


class PublicBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.configuration, self.runtime = runtime()
        self.authority = object.__getattribute__(self.runtime, "_authority")

    def test_a_exact_public_api_and_method_shapes(self):
        self.assertEqual(module.__all__, (
            "HostRuntimeError", "HostMutationEvidence", "DevPrivilegedHostRuntime"))
        self.assertEqual({name for name in vars(module) if not name.startswith("_")},
                         set(module.__all__))
        self.assertTrue(dataclasses.is_dataclass(module.HostMutationEvidence))
        self.assertTrue(module.HostMutationEvidence.__dataclass_params__.frozen)
        self.assertIn("__slots__", vars(module.HostMutationEvidence))
        self.assertFalse({"trusted", "approved", "ready", "safe"}
                         & {field.name for field in dataclasses.fields(module.HostMutationEvidence)})
        expected = {
            "create_required_group": ("self", "name"),
            "create_required_user": ("self", "name"),
            "create_required_directory": ("self", "path"),
            "install_executor_configuration": ("self",),
            "install_required_asset": ("self", "destination"),
        }
        public = {name for name, value in vars(module.DevPrivilegedHostRuntime).items()
                  if not name.startswith("_") and inspect.isfunction(value)}
        self.assertEqual(public, set(expected))
        for name, parameters in expected.items():
            self.assertEqual(tuple(inspect.signature(
                getattr(module.DevPrivilegedHostRuntime, name)).parameters), parameters)

    def test_b_import_and_construction_are_inert_and_immutable(self):
        with ExitStack() as stack:
            mocked = [stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                      for owner, name in (
                          (subprocess, "run"), (os, "mkdir"), (os, "write"),
                          (os, "replace"), (os, "unlink"), (os, "rmdir"),
                          (os, "fchmod"), (os, "fchown"),
                          (builtins, "open"))]
            module.DevPrivilegedHostRuntime(configuration=self.configuration)
            for item in mocked:
                item.assert_not_called()
        with self.assertRaises(AttributeError):
            self.runtime.anything = object()
        with self.assertRaises(AttributeError):
            del self.runtime._authority

    def test_c_forged_configuration_and_evidence_fail_closed(self):
        forged = object.__new__(c17.DevExecutorServiceConfiguration)
        for field in dataclasses.fields(self.configuration):
            if field.init:
                object.__setattr__(forged, field.name, getattr(self.configuration, field.name))
        object.__setattr__(forged, "stage", "prod")
        with self.assertRaisesRegex(TypeError, "DEV privileged host runtime configuration is invalid"):
            module.DevPrivilegedHostRuntime(configuration=forged)
        for values in (("", "x", "created"), ("group", "x", "unknown")):
            with self.assertRaises(ValueError):
                module.HostMutationEvidence(*values)
        group = self.authority.groups[0]
        forged_result = module.HostMutationEvidence("group", "unrelated", "created")
        with patch.object(module, "_create_group", return_value=forged_result), \
             self.assertRaises(module.HostRuntimeError):
            self.runtime.create_required_group(group.name)

    def test_d_arbitrary_paths_principals_and_assets_are_rejected(self):
        attempts = (
            (self.runtime.create_required_group, "root"),
            (self.runtime.create_required_user, "attacker"),
            (self.runtime.create_required_directory, "/tmp/attacker"),
            (self.runtime.install_required_asset, "/tmp/attacker.service"),
        )
        with patch.object(module._subprocess, "run") as run, \
             patch.object(module._os, "mkdir") as mkdir, \
             patch.object(module._os, "replace") as replace:
            for operation, value in attempts:
                with self.subTest(operation=operation.__name__), \
                     self.assertRaises(module.HostRuntimeError) as caught:
                    operation(value)
                self.assertEqual(str(caught.exception), ERROR)
                self.assertIsNone(caught.exception.__cause__)
            run.assert_not_called(); mkdir.assert_not_called(); replace.assert_not_called()
        for operation, selector in (("shell", None), (lambda: None, None)):
            with self.assertRaises(module.HostRuntimeError):
                self.runtime._perform(operation, selector)

    def test_e_authority_is_exactly_projected_from_c23(self):
        self.assertEqual(tuple(item.name for item in self.authority.groups), (
            "omnilyzer-broker", "omnilyzer-executor", "omnilyzer-replay",
            "omnilyzer-deployment"))
        self.assertEqual(tuple(item.name for item in self.authority.users), (
            "omnilyzer-broker", "omnilyzer-executor"))
        self.assertEqual(self.authority.configuration_file.path,
                         "/etc/omnilyzer/deployment/dev/executor.json")
        self.assertEqual(self.authority.configuration_bytes, self.configuration.canonical_bytes())
        self.assertEqual(tuple(item.destination_path for item in self.authority.assets), (
            "/etc/systemd/system/omnilyzer-deployment-executor.socket",
            "/etc/systemd/system/omnilyzer-deployment-executor.service"))

    def test_f_fixed_errors_and_control_exceptions(self):
        name = self.authority.groups[0].name
        with patch.object(module, "_create_group", side_effect=OSError("host detail")):
            with self.assertRaises(module.HostRuntimeError) as caught:
                self.runtime.create_required_group(name)
            self.assertEqual(str(caught.exception), ERROR)
            self.assertIsNone(caught.exception.__cause__)
        for exception in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with patch.object(module, "_create_group", side_effect=exception):
                with self.assertRaises(exception):
                    self.runtime.create_required_group(name)

    def test_g_configuration_and_asset_installers_bind_exact_inputs(self):
        expected = module.HostMutationEvidence(
            "regular_file", self.authority.configuration_file.path, "unchanged")
        with patch.object(module, "_install_atomic", return_value=expected) as install:
            self.assertEqual(self.runtime.install_executor_configuration(), expected)
        install.assert_called_once_with(
            self.authority.configuration_file, self.authority.configuration_bytes,
            self.authority.directories)

        asset = self.authority.assets[0]
        expected = module.HostMutationEvidence("regular_file", asset.destination_path, "created")
        reviewed = (ROOT / asset.source_path).read_bytes()
        with patch.object(module, "_install_atomic", return_value=expected) as install:
            self.assertEqual(self.runtime.install_required_asset(asset.destination_path), expected)
        requirement, payload, directories = install.call_args.args
        self.assertEqual((requirement.path, requirement.mode,
                          requirement.owner_uid, requirement.group_gid),
                         (asset.destination_path, asset.mode,
                          asset.owner_uid, asset.group_gid))
        self.assertEqual(payload, reviewed)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), asset.sha256)
        self.assertIs(directories, self.authority.directories)

        with patch.object(module, "_read_reviewed_source", side_effect=OSError), \
             patch.object(module, "_install_atomic") as install, \
             self.assertRaises(module.HostRuntimeError) as caught:
            self.runtime.install_required_asset(asset.destination_path)
        self.assertEqual(str(caught.exception), ERROR)
        install.assert_not_called()
        with self.assertRaises(TypeError):
            self.runtime.install_required_asset(asset.destination_path, asset.sha256)


class AccountPrimitiveTests(unittest.TestCase):
    def setUp(self):
        _, self.runtime = runtime()
        self.authority = object.__getattribute__(self.runtime, "_authority")

    def test_h_group_command_is_absolute_closed_and_postvalidated(self):
        requirement = self.authority.groups[0]
        completed = subprocess.CompletedProcess((), 0)
        with patch.object(module, "_group_state", side_effect=("absent", "exact")), \
             patch.object(module._subprocess, "run", return_value=completed) as run:
            evidence = self.runtime.create_required_group(requirement.name)
        self.assertEqual(evidence, module.HostMutationEvidence(
            "group", requirement.name, "created"))
        run.assert_called_once_with(
            ("/usr/sbin/groupadd", "--system", "--gid", str(requirement.gid), requirement.name),
            shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=10, check=False)

    def test_i_user_command_is_absolute_closed_nonlogin_and_postvalidated(self):
        requirement = self.authority.users[0]
        names = {item.gid: item.name for item in self.authority.groups}
        completed = subprocess.CompletedProcess((), 0)
        with patch.object(module, "_user_state", side_effect=("absent", "exact")), \
             patch.object(module._subprocess, "run", return_value=completed) as run:
            evidence = self.runtime.create_required_user(requirement.name)
        self.assertEqual(evidence.outcome, "created")
        run.assert_called_once_with((
            "/usr/sbin/useradd", "--system", "--uid", str(requirement.uid),
            "--gid", names[requirement.primary_gid], "--groups",
            ",".join(names[gid] for gid in requirement.supplementary_gids),
            "--no-user-group", "--no-create-home", "--home-dir", "/nonexistent",
            "--shell", "/usr/sbin/nologin", requirement.name),
            shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=10, check=False)

    def test_j_existing_exact_accounts_are_unchanged_and_commands_do_not_run(self):
        group = self.authority.groups[0]; user = self.authority.users[0]
        with patch.object(module, "_group_state", return_value="exact"), \
             patch.object(module, "_user_state", return_value="exact"), \
             patch.object(module._subprocess, "run") as run:
            self.assertEqual(self.runtime.create_required_group(group.name).outcome, "unchanged")
            self.assertEqual(self.runtime.create_required_user(user.name).outcome, "unchanged")
        run.assert_not_called()

    def test_k_name_uid_and_gid_collisions_fail_before_subprocess(self):
        group = self.authority.groups[0]
        with patch.object(module._grp, "getgrnam", return_value=SimpleNamespace(gr_gid=group.gid)), \
             patch.object(module._grp, "getgrgid", return_value=SimpleNamespace(gr_name="unrelated")), \
             patch.object(module._subprocess, "run") as run:
            with self.assertRaises(module.HostRuntimeError):
                self.runtime.create_required_group(group.name)
        run.assert_not_called()
        user = self.authority.users[0]
        with patch.object(module, "_group_state", return_value="exact"), \
             patch.object(module._pwd, "getpwnam", return_value=SimpleNamespace(
                 pw_uid=user.uid, pw_gid=user.primary_gid, pw_dir="/nonexistent",
                 pw_shell="/usr/sbin/nologin")), \
             patch.object(module._pwd, "getpwuid", return_value=SimpleNamespace(pw_name="unrelated")), \
             patch.object(module._subprocess, "run") as run:
            with self.assertRaises(module.HostRuntimeError):
                self.runtime.create_required_user(user.name)
        run.assert_not_called()


class ReviewedSourceTests(unittest.TestCase):
    def test_l_exact_digest_succeeds_and_changed_bytes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "unit.service"
            reviewed = b"[Service]\nExecStart=/reviewed\n"
            digest = hashlib.sha256(reviewed).hexdigest()
            source.write_bytes(reviewed)
            self.assertEqual(module._read_reviewed_source(str(source), digest), reviewed)
            source.write_bytes(reviewed + b"# changed\n")
            with self.assertRaises(OSError):
                module._read_reviewed_source(str(source), digest)
            source.write_bytes(b"x" * (module._MAX_FILE_BYTES + 1))
            with self.assertRaises(OSError):
                module._read_reviewed_source(str(source), digest)
            for malformed in ("", "A" * 64, "0" * 63, "g" * 64):
                with self.assertRaises(OSError):
                    module._read_reviewed_source(str(source), malformed)

    def test_m_source_and_parent_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); real = root / "real"; real.mkdir()
            source = real / "unit.service"; source.write_bytes(b"reviewed\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            file_link = real / "linked.service"; file_link.symlink_to(source.name)
            parent_link = root / "linked-parent"; parent_link.symlink_to(real, target_is_directory=True)
            for candidate in (file_link, parent_link / source.name):
                with self.subTest(candidate=candidate), self.assertRaises(OSError):
                    module._read_reviewed_source(str(candidate), digest)

    def test_n_source_replacement_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "unit.service"
            replacement = Path(temporary) / "replacement.service"
            reviewed = b"reviewed\n"; source.write_bytes(reviewed)
            replacement.write_bytes(reviewed)
            digest = hashlib.sha256(reviewed).hexdigest()
            read_exact = module._read_exact

            def replace_after_read(descriptor, size):
                payload = read_exact(descriptor, size)
                os.replace(replacement, source)
                return payload

            with patch.object(module, "_read_exact", side_effect=replace_after_read), \
                 self.assertRaises(OSError):
                module._read_reviewed_source(str(source), digest)


class FilesystemPrimitiveTests(unittest.TestCase):
    def test_o_directory_creation_and_exact_existing_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)
            created = module._ensure_directory(child, (parent, child))
            self.assertEqual(created.outcome, "created")
            self.assertEqual(stat.S_IMODE(os.stat(child.path).st_mode), child.mode)
            unchanged = module._ensure_directory(child, (parent, child))
            self.assertEqual(unchanged.outcome, "unchanged")

    def test_p_directory_wrong_type_mode_and_symlink_parent_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)
            Path(child.path).write_bytes(b"wrong")
            with self.assertRaises(OSError):
                module._ensure_directory(child, (parent, child))
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)
            os.mkdir(child.path, 0o755)
            with self.assertRaises(OSError):
                module._ensure_directory(child, (parent, child))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); real = root / "real"; real.mkdir(mode=0o700)
            alias = root / "alias"; alias.symlink_to(real, target_is_directory=True)
            parent = module._DirectoryAuthority(str(alias), 0o700, os.getuid(), os.getgid())
            child = module._DirectoryAuthority(str(alias / "child"), 0o750,
                                               os.getuid(), os.getgid())
            with self.assertRaises(OSError):
                module._ensure_directory(child, (parent, child))

    def test_q_new_directory_failure_cleanup_is_identity_bound_and_nonrecursive(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)
            with patch.object(module._os, "fchmod", side_effect=OSError), \
                 self.assertRaises(OSError):
                module._ensure_directory(child, (parent, child))
            self.assertFalse(Path(child.path).exists())

        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)
            module._ensure_directory(child, (parent, child))
            with patch.object(module, "_revalidate_chain", side_effect=OSError), \
                 patch.object(module._os, "rmdir") as rmdir, self.assertRaises(OSError):
                module._ensure_directory(child, (parent, child))
            rmdir.assert_not_called()
            self.assertTrue(Path(child.path).is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)
            original = Path(child.path + "-original")

            def substitute(*_arguments):
                os.rename(child.path, original)
                os.mkdir(child.path, 0o700)
                raise OSError

            with patch.object(module._os, "fchmod", side_effect=substitute), \
                 self.assertRaises(OSError):
                module._ensure_directory(child, (parent, child))
            self.assertTrue(original.is_dir())
            self.assertTrue(Path(child.path).is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)

            def make_nonempty(*_arguments):
                (Path(child.path) / "attacker-entry").write_bytes(b"x")
                raise OSError

            with patch.object(module._os, "fchmod", side_effect=make_nonempty), \
                 self.assertRaises(OSError):
                module._ensure_directory(child, (parent, child))
            self.assertEqual(tuple(path.name for path in Path(child.path).iterdir()),
                             ("attacker-entry",))

    def test_r_directory_cleanup_failure_is_a_generic_public_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, _ = temporary_authorities(temporary)
            _, runtime_instance = runtime()
            authority = object.__getattribute__(runtime_instance, "_authority")
            object.__setattr__(runtime_instance, "_authority", dataclasses.replace(
                authority, directories=(parent, child)))

            def fail_with_nonempty_directory(*_arguments):
                (Path(child.path) / "entry").write_bytes(b"x")
                raise OSError("host detail")

            with patch.object(module._os, "fchmod", side_effect=fail_with_nonempty_directory), \
                 self.assertRaises(module.HostRuntimeError) as caught:
                runtime_instance.create_required_directory(child.path)
            self.assertEqual(str(caught.exception), ERROR)
            self.assertIsNone(caught.exception.__cause__)

    def test_s_atomic_file_create_unchanged_and_replace(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, file = temporary_authorities(temporary)
            module._ensure_directory(child, (parent, child))
            self.assertEqual(module._install_atomic(file, b"first", (parent, child)).outcome,
                             "created")
            self.assertEqual(module._install_atomic(file, b"first", (parent, child)).outcome,
                             "unchanged")
            self.assertEqual(module._install_atomic(file, b"second", (parent, child)).outcome,
                             "replaced")
            self.assertEqual(Path(file.path).read_bytes(), b"second")
            status = os.stat(file.path)
            self.assertEqual((stat.S_IMODE(status.st_mode), status.st_uid, status.st_gid),
                             (file.mode, file.owner_uid, file.group_gid))

    def test_s2_c17_rename_sync_failure_retries_on_exact_existing_file(self):
        # Route the fixed C17 authority to an isolated directory because this
        # sandbox's / is not root-owned; keep the actual atomic file I/O.
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "executor.json"
            target.write_bytes(b"old")
            target.chmod(0o640)
            requirement = module._FileAuthority(
                module._c17.PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
                0o640, os.getuid(), os.getgid(),
            )
            identity = (os.stat(temporary).st_dev, os.stat(temporary).st_ino)

            def open_fixed_parent(path, _directories, owned):
                self.assertEqual(path, requirement.path)
                descriptor = module._claim(os.open(
                    temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), owned)
                return descriptor, "executor.json", []

            renamed = False
            real_replace, real_fsync = os.replace, os.fsync

            def replace_then_fail(*args, **kwargs):
                nonlocal renamed
                real_replace(*args, **kwargs)
                renamed = True

            def failed_parent_sync(descriptor):
                if renamed and (os.fstat(descriptor).st_dev,
                                os.fstat(descriptor).st_ino) == identity:
                    raise OSError("parent sync failed after C17 rename")
                return real_fsync(descriptor)

            with patch.object(module, "_open_parent", side_effect=open_fixed_parent), \
                 patch.object(module._os, "replace", side_effect=replace_then_fail), \
                 patch.object(module._os, "fsync", side_effect=failed_parent_sync):
                with self.assertRaises(OSError):
                    module._install_atomic(requirement, b"current", ())
            self.assertTrue(renamed)
            self.assertEqual(target.read_bytes(), b"current")

            synced_parent = False

            def retry_sync(descriptor):
                nonlocal synced_parent
                if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == identity:
                    synced_parent = True
                return real_fsync(descriptor)

            with patch.object(module, "_open_parent", side_effect=open_fixed_parent), \
                 patch.object(module._os, "fsync", side_effect=retry_sync), \
                 patch.object(module, "_existing_file", wraps=module._existing_file) as verify:
                result = module._install_atomic(requirement, b"current", ())
            self.assertEqual(result.outcome, "unchanged")
            self.assertTrue(synced_parent, "exact current C17 skipped parent sync")
            self.assertGreaterEqual(verify.call_count, 2)

    def test_t_file_symlink_wrong_type_and_mode_conflicts_fail(self):
        for kind in ("symlink", "directory", "wrong_mode"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                parent, child, file = temporary_authorities(temporary)
                module._ensure_directory(child, (parent, child)); target = Path(file.path)
                if kind == "symlink": target.symlink_to("elsewhere")
                elif kind == "directory": target.mkdir()
                else: target.write_bytes(b"old"); target.chmod(0o600)
                with self.assertRaises(OSError):
                    module._install_atomic(file, b"reviewed", (parent, child))

    def test_u_existing_file_wrong_uid_and_gid_fail(self):
        for field in ("owner_uid", "group_gid"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                parent, child, file = temporary_authorities(temporary)
                module._ensure_directory(child, (parent, child))
                target = Path(file.path); target.write_bytes(b"old"); target.chmod(file.mode)
                values = dataclasses.asdict(file)
                values[field] += 1
                conflicting = module._FileAuthority(**values)
                with self.assertRaises(OSError):
                    module._install_atomic(conflicting, b"reviewed", (parent, child))

    def test_v_failed_atomic_write_removes_only_owned_temporary(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, file = temporary_authorities(temporary)
            module._ensure_directory(child, (parent, child))
            with patch.object(module._os, "write", side_effect=OSError), self.assertRaises(OSError):
                module._install_atomic(file, b"reviewed", (parent, child))
            self.assertFalse(Path(file.path).exists())
            self.assertFalse((Path(child.path) / module._TEMPORARY_NAME).exists())

    def test_w_bounded_payload_and_substitution_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child, file = temporary_authorities(temporary)
            module._ensure_directory(child, (parent, child))
            with self.assertRaises(OSError):
                module._install_atomic(file, b"x" * (module._MAX_FILE_BYTES + 1), (parent, child))
            with patch.object(module._os, "replace", side_effect=OSError), self.assertRaises(OSError):
                module._install_atomic(file, b"reviewed", (parent, child))
            self.assertFalse((Path(child.path) / module._TEMPORARY_NAME).exists())


class StaticBoundaryTests(unittest.TestCase):
    def test_x_no_general_command_path_network_or_activation_authority(self):
        source = Path(module.__file__).read_text(); tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertFalse(imports & {"socket", "urllib", "http", "requests", "venv", "shutil"})
        self.assertNotIn("shell=True", source)
        for forbidden in ("/bin/sh", "/bin/bash", "systemctl", "pip install",
                          "apt install", "daemon-reload"):
            self.assertNotIn(forbidden, source.lower())
        self.assertNotIn("docker_runtime", imports)
        self.assertFalse(hasattr(module.DevPrivilegedHostRuntime, "run"))
        self.assertFalse(hasattr(module.DevPrivilegedHostRuntime, "execute"))
        self.assertFalse(hasattr(module.DevPrivilegedHostRuntime, "write"))
        self.assertFalse(hasattr(module.DevPrivilegedHostRuntime, "copy"))

    def test_y_documented_separation_authority_and_deferrals(self):
        documentation = (ROOT / "deployment/README.md").read_text()
        section = documentation.split("## C30 narrow privileged host runtime", 1)[1]
        for required in (
            "RestrictedPrivilegedExecutor", "DockerRuntimeAdapter", "C29 -> C30 -> C31",
            "C13/C21/C23", "groupadd", "useradd", "a shell",
            "application-tree", "venv", "Live activation remains blocked",
        ):
            self.assertIn(required, section)


if __name__ == "__main__":
    unittest.main()
