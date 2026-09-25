"""C31B closed privileged provisioning-mechanics tests."""

import ast
import builtins
from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

import deployment.application_manifest as c26
from deployment.application_source_set import DevApplicationSourceSet
import deployment.dev_host_provisioning_mechanics as module
import deployment.executor_service_config as c17
import deployment.pip_installer_provenance as c31p
import deployment.pip_installer_qualification as pip_qualification
import deployment.python_environment_qualification as c31a_environment
import deployment.wheelhouse_qualification as c28
from deployment.tests.test_executor_service_config import configuration_values


ERROR = "DEV host provisioning mechanics are unavailable"
ROOT = Path(__file__).resolve().parents[2]


def git(root, *arguments):
    return subprocess.run(
        ("/usr/bin/git", "-C", str(root), *arguments),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        check=True,
    ).stdout


def repository_fixture(parent):
    repository = Path(parent) / "repository"
    repository.mkdir()
    git(repository, "init", "--quiet")
    git(repository, "config", "user.email", "test@example.invalid")
    git(repository, "config", "user.name", "Test")
    for relative in c26._predecessor_paths():
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((relative + "\n").encode())
    lock = ROOT / "deployment/requirements-linux-x86_64-py312.lock"
    target_lock = repository / "deployment/requirements-linux-x86_64-py312.lock"
    target_lock.write_bytes(lock.read_bytes())
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "fixture")
    commit = git(repository, "rev-parse", "HEAD").decode().strip()
    configuration = c17.DevExecutorServiceConfiguration(
        **configuration_values(reviewed_commit=commit),
    )
    paths = c26._predecessor_paths()
    records = c26._tree(git(repository, "ls-tree", "-r", "-z", "--full-tree",
                            commit, "--", *paths), paths)
    assert git(repository, "rev-parse", "HEAD").strip().decode() == commit
    manifest = c26.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", commit,
        tuple(c26.ApplicationManifestEntry(
            relative, hashlib.sha256(git(repository, "cat-file", "blob", oid)).hexdigest(),
            "0644",
        ) for relative, oid in records),
    )
    return repository, configuration, manifest


def temporary_mechanics(configuration, parent):
    value = module.DevHostProvisioningMechanics(configuration=configuration)
    authority = object.__getattribute__(value, "_authority")
    deployment = Path(parent) / "deployment-root"
    application = deployment / "app"
    venv = deployment / "venv"
    deployment.mkdir(mode=0o755)
    application.mkdir(mode=0o755)
    paths = module._Paths(
        str(application), str(venv), str(venv / "bin/python"),
        str(deployment), str(deployment / ".provisioning-inputs"),
        authority.integrity.python_environment_requirement().dependency_lock.path,
    )
    testing = dataclasses.replace(
        authority, paths=paths,
        application_uid=os.getuid(), application_gid=os.getgid(),
        venv_uid=os.getuid(), venv_gid=os.getgid(),
    )
    object.__setattr__(value, "_authority", testing)
    return value, testing, application, venv


class PublicBoundaryTests(unittest.TestCase):
    def test_a_public_api_is_closed_and_construction_is_inert(self):
        self.assertEqual(module.__all__, (
            "ProvisioningMechanicsError", "ApplicationMaterializationEvidence",
            "DevHostProvisioningMechanics",
        ))
        self.assertEqual(
            {name for name in vars(module) if not name.startswith("_")},
            set(module.__all__),
        )
        methods = {
            name for name, value in vars(module.DevHostProvisioningMechanics).items()
            if callable(value) and not name.startswith("_")
        }
        self.assertEqual(methods, {
            "materialize_application_tree", "construct_python_environment",
        })
        self.assertEqual(
            tuple(inspect.signature(
                module.DevHostProvisioningMechanics.materialize_application_tree,
            ).parameters),
            ("self", "repository_root", "application_manifest"),
        )
        self.assertEqual(
            tuple(inspect.signature(
                module.DevHostProvisioningMechanics.construct_python_environment,
            ).parameters),
            ("self", "host_qualification", "repository_root", "wheelhouse_path",
             "pip_installer_staging"),
        )
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        with ExitStack() as stack:
            blockers = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                for owner, name in (
                    (builtins, "open"), (os, "open"), (os, "stat"),
                    (subprocess, "Popen"), (subprocess, "run"),
                    (socket, "socket"),
                )
            ]
            importlib.reload(module)
            module.DevHostProvisioningMechanics(configuration=configuration)
            for blocker in blockers:
                blocker.assert_not_called()

    def test_b_forged_configuration_and_arbitrary_public_authority_rejected(self):
        with self.assertRaises(TypeError):
            module.DevHostProvisioningMechanics(configuration=object())
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        mechanics = module.DevHostProvisioningMechanics(configuration=configuration)
        with self.assertRaises(TypeError):
            mechanics.construct_python_environment(
                host_qualification=object(),
                repository_root="/tmp/repository", wheelhouse_path="/tmp/wheels",
                pip_installer_staging="/tmp/pip", destination="/tmp/escape",
            )
        with self.assertRaises(TypeError):
            mechanics.materialize_application_tree(
                repository_root="/tmp/repository", application_manifest=object(),
                destination="/tmp/escape",
            )
        with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
            mechanics.construct_python_environment(
                host_qualification=object(), repository_root="/tmp/repository",
                wheelhouse_path="/tmp/wheels", pip_installer_staging="/tmp/pip",
            )
        with self.assertRaises(AttributeError):
            mechanics.command = ("/bin/sh",)


class ApplicationMaterializationTests(unittest.TestCase):
    def test_c_exact_blobs_materialize_and_dirty_worktree_is_ignored(self):
        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, manifest = repository_fixture(parent)
            dirty = repository / manifest.entries[0].path
            dirty.write_bytes(b"dirty-working-tree\n")
            mechanics, _authority, application, _venv = temporary_mechanics(
                configuration, parent,
            )
            evidence = mechanics.materialize_application_tree(
                repository_root=str(repository), application_manifest=manifest,
            )
            self.assertEqual(evidence.outcome, "materialized")
            self.assertEqual(evidence.regular_file_count, 28)
            installed = application / manifest.entries[0].path
            self.assertNotEqual(installed.read_bytes(), dirty.read_bytes())
            self.assertEqual(
                hashlib.sha256(installed.read_bytes()).hexdigest(),
                manifest.entries[0].sha256,
            )
            before = tuple((path.relative_to(application), path.lstat())
                           for path in sorted(application.rglob("*")))
            second = mechanics.materialize_application_tree(
                repository_root=str(repository), application_manifest=manifest,
            )
            after = tuple((path.relative_to(application), path.lstat())
                          for path in sorted(application.rglob("*")))
            self.assertEqual(second.outcome, "unchanged")
            self.assertEqual(before, after)

    def test_d_wrong_blob_or_commit_fails_before_destination_mutation(self):
        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, manifest = repository_fixture(parent)
            mechanics, _authority, application, _venv = temporary_mechanics(
                configuration, parent,
            )
            entries = list(manifest.entries)
            entries[0] = c26.ApplicationManifestEntry(entries[0].path, "0" * 64, "0644")
            wrong = c26.DevApplicationManifest(
                manifest.manifest_kind, manifest.digest_algorithm,
                manifest.reviewed_commit, tuple(entries),
            )
            with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
                mechanics.materialize_application_tree(
                    repository_root=str(repository), application_manifest=wrong,
                )
            self.assertEqual(tuple(application.iterdir()), ())
            forged_commit = c26.DevApplicationManifest(
                manifest.manifest_kind, manifest.digest_algorithm,
                "f" * 40, manifest.entries,
            )
            with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
                mechanics.materialize_application_tree(
                    repository_root=str(repository), application_manifest=forged_commit,
                )
            self.assertEqual(tuple(application.iterdir()), ())

    def test_e_extra_symlink_wrong_mode_and_repository_symlink_fail_closed(self):
        scenarios = ("extra", "symlink", "mode")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as parent:
                repository, configuration, manifest = repository_fixture(parent)
                mechanics, _authority, application, _venv = temporary_mechanics(
                    configuration, parent,
                )
                if scenario == "extra":
                    (application / "extra").write_bytes(b"extra")
                else:
                    path = application / "deployment"
                    if scenario == "symlink":
                        path.symlink_to(repository / "deployment", target_is_directory=True)
                    else:
                        path.mkdir(mode=0o700)
                before = tuple(sorted(path.relative_to(application).as_posix()
                                      for path in application.rglob("*")))
                with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
                    mechanics.materialize_application_tree(
                        repository_root=str(repository), application_manifest=manifest,
                    )
                after = tuple(sorted(path.relative_to(application).as_posix()
                                     for path in application.rglob("*")))
                self.assertEqual(before, after)
        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, manifest = repository_fixture(parent)
            mechanics, _authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            alias = Path(parent) / "repository-alias"
            alias.symlink_to(repository, target_is_directory=True)
            with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
                mechanics.materialize_application_tree(
                    repository_root=str(alias), application_manifest=manifest,
                )

    def test_f_wrong_ownership_and_partial_write_cleanup_fail_closed(self):
        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, manifest = repository_fixture(parent)
            mechanics, authority, application, _venv = temporary_mechanics(
                configuration, parent,
            )
            object.__setattr__(
                mechanics, "_authority",
                dataclasses.replace(authority, application_uid=os.getuid() + 1),
            )
            with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
                mechanics.materialize_application_tree(
                    repository_root=str(repository), application_manifest=manifest,
                )
            self.assertEqual(tuple(application.iterdir()), ())

        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, manifest = repository_fixture(parent)
            mechanics, _authority, application, _venv = temporary_mechanics(
                configuration, parent,
            )
            with patch.object(module, "_write_all", side_effect=OSError):
                with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
                    mechanics.materialize_application_tree(
                        repository_root=str(repository), application_manifest=manifest,
                    )
            self.assertEqual(tuple(application.iterdir()), ())

        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, manifest = repository_fixture(parent)
            mechanics, _authority, application, _venv = temporary_mechanics(
                configuration, parent,
            )
            with patch.object(module, "_verify_application", side_effect=OSError):
                with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR):
                    mechanics.materialize_application_tree(
                        repository_root=str(repository), application_manifest=manifest,
                    )
            self.assertEqual(tuple(application.iterdir()), ())


class SnapshotAndProcessTests(unittest.TestCase):
    def test_g_descriptor_copy_uses_opened_bytes_rehashes_and_fsyncs(self):
        with tempfile.TemporaryDirectory() as parent:
            source_path = Path(parent) / "source"
            replacement = Path(parent) / "replacement"
            source_path.write_bytes(b"reviewed")
            replacement.write_bytes(b"attacker0")
            source = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
            destination = Path(parent) / "destination"
            destination.mkdir()
            parent_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
            owned = []
            try:
                os.replace(replacement, source_path)
                digest = hashlib.sha256(b"reviewed").hexdigest()
                with patch.object(module._os, "fsync", wraps=os.fsync) as fsync:
                    descriptor, fingerprint = module._copy_descriptor(
                        source, parent_fd, "captured", 8, digest,
                        os.getuid(), os.getgid(), owned,
                    )
                self.assertEqual((destination / "captured").read_bytes(), b"reviewed")
                self.assertEqual(
                    module._fingerprint(os.fstat(descriptor)), fingerprint,
                )
                self.assertGreaterEqual(fsync.call_count, 2)
            finally:
                module._close(owned)
                os.close(parent_fd)
                os.close(source)

    def test_h_changed_source_digest_and_preexisting_snapshot_are_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            source = Path(parent) / "source"
            source.write_bytes(b"changed")
            source_fd = os.open(source, os.O_RDONLY)
            destination = Path(parent) / "destination"
            destination.mkdir()
            parent_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
            owned = []
            try:
                with self.assertRaises(OSError):
                    module._copy_descriptor(
                        source_fd, parent_fd, "copy", 7,
                        hashlib.sha256(b"reviewed").hexdigest(),
                        os.getuid(), os.getgid(), owned,
                    )
                self.assertFalse((destination / "copy").exists())
            finally:
                module._close(owned); os.close(parent_fd); os.close(source_fd)

        with tempfile.TemporaryDirectory() as parent:
            configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
            _mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            snapshot_root = Path(authority.paths.snapshot_root)
            snapshot_root.mkdir(mode=0o700)
            repository = Path(parent) / "repository"
            repository.mkdir()
            repository_fd = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
            owned = [repository_fd]
            source_owned = []
            try:
                wheel_result = (object(), repository_fd, (), [])
                installer_result = (object(), repository_fd, (repository_fd, "pip.whl", ()), [])
                lock = SimpleNamespace(
                    descriptor=repository_fd, parent=repository_fd, name="lock",
                    fingerprint=(), size=0, sha256="0" * 64,
                )
                with patch.object(module._c28, "_qualify_open", return_value=wheel_result), \
                     patch.object(module._pip_qualification, "_qualify_open",
                                  return_value=installer_result), \
                     patch.object(module, "_open_lock", return_value=lock):
                    with self.assertRaises(OSError):
                        module._prepare_snapshot(
                            authority, repository_fd, "/staging/wheels", "/staging/pip",
                            owned, source_owned, {},
                        )
                self.assertTrue(snapshot_root.is_dir())
            finally:
                module._close(source_owned); module._close(owned)

    def test_i_snapshot_validation_and_cleanup_are_identity_bound(self):
        with tempfile.TemporaryDirectory() as parent:
            configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
            mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            deployment = Path(authority.paths.deployment_root)
            root = deployment / ".provisioning-inputs"
            root.mkdir(mode=0o700)
            directories = []
            files = []
            owned = []
            parent_fd = os.open(deployment, os.O_RDONLY | os.O_DIRECTORY)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            owned.extend((parent_fd, root_fd))
            try:
                directory_map = {}
                for name in module._SNAPSHOT_DIRECTORIES:
                    path = root / name; path.mkdir(mode=0o700)
                    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                    owned.append(descriptor); status = os.fstat(descriptor)
                    directories.append((name, descriptor, (status.st_dev, status.st_ino)))
                    directory_map[name] = descriptor
                payload = b"reviewed"
                path = root / "pip/tool.whl"; path.write_bytes(payload); path.chmod(0o400)
                descriptor = os.open(path, os.O_RDONLY); owned.append(descriptor)
                status = os.fstat(descriptor)
                files.append((directory_map["pip"], "tool.whl", descriptor,
                              module._fingerprint(status), len(payload),
                              hashlib.sha256(payload).hexdigest()))
                root_status = os.fstat(root_fd)
                snapshot = module._Snapshot(
                    parent_fd, root_fd, tuple(directories), tuple(files),
                    (root_status.st_dev, root_status.st_ino),
                    str(path), str(root / "wheels"), str(root / "requirements/lock"),
                )
                module._validate_snapshot(snapshot, authority)
                (root / "unknown").write_bytes(b"unknown")
                with self.assertRaises(OSError):
                    module._cleanup_snapshot(snapshot, authority)
                self.assertTrue(root.exists())
                (root / "unknown").unlink()
                module._cleanup_snapshot(snapshot, authority)
                self.assertFalse(root.exists())
            finally:
                module._close(owned)

    def test_j_substituted_snapshot_root_is_never_removed(self):
        with tempfile.TemporaryDirectory() as parent:
            configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
            _mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            deployment = Path(authority.paths.deployment_root)
            root = deployment / ".provisioning-inputs"; root.mkdir(mode=0o700)
            parent_fd = os.open(deployment, os.O_RDONLY | os.O_DIRECTORY)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            status = os.fstat(root_fd)
            snapshot = module._Snapshot(
                parent_fd, root_fd, (), (), (status.st_dev, status.st_ino),
                str(root / "pip/tool"), str(root / "wheels"), str(root / "requirements/lock"),
            )
            displaced = deployment / "displaced"
            root.rename(displaced); root.mkdir(mode=0o700)
            try:
                with self.assertRaises(OSError):
                    module._cleanup_snapshot(snapshot, authority)
                self.assertTrue(root.exists())
                self.assertTrue(displaced.exists())
            finally:
                os.close(root_fd); os.close(parent_fd)

    def test_k_requirements_lock_is_opened_beneath_repository_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, _manifest = repository_fixture(parent)
            mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            owned = []
            repository_fd = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
            owned.append(repository_fd)
            try:
                lock = module._open_lock(authority, repository_fd, owned)
                self.assertEqual(
                    lock.sha256,
                    "13c7b3f0050f9aff0a94ab324a66276638f8b1b9dd0c62232ec205b24d874d0d",
                )
            finally:
                module._close(owned)
            (repository / "deployment/requirements-linux-x86_64-py312.lock").write_bytes(
                b"forged\n",
            )
            owned = []
            repository_fd = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
            owned.append(repository_fd)
            try:
                with self.assertRaises(OSError):
                    module._open_lock(authority, repository_fd, owned)
            finally:
                module._close(owned)

    def test_l_venv_precondition_accepts_only_absent_or_exact_empty_target(self):
        with tempfile.TemporaryDirectory() as parent:
            configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
            _mechanics, authority, _application, venv = temporary_mechanics(
                configuration, parent,
            )
            module._venv_precondition(authority)
            venv.mkdir(mode=0o755)
            module._venv_precondition(authority)
            (venv / "conflict").write_bytes(b"conflict")
            with self.assertRaises(OSError):
                module._venv_precondition(authority)
            (venv / "conflict").unlink(); venv.rmdir()
            venv.symlink_to(Path(parent) / "elsewhere", target_is_directory=True)
            with self.assertRaises(OSError):
                module._venv_precondition(authority)

    def test_l_c29_exact_empty_venv_evidence_is_accepted(self):
        from deployment.tests.test_dev_host_provisioning_orchestration import (
            fixtures, host_evidence,
        )
        configuration, manifest, _integrity, provisioning, wheels, _installer = fixtures()
        with tempfile.TemporaryDirectory() as parent:
            _mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            host = host_evidence(configuration, manifest, wheels, provisioning)
            managed = tuple(
                dataclasses.replace(
                    item, state="exact", owner_uid=authority.venv_uid,
                    group_gid=authority.venv_gid,
                )
                if item.path == authority.integrity.python_environment_requirement().root
                else item for item in host.managed_paths
            )
            host = dataclasses.replace(host, managed_paths=managed)
            module._validate_host_qualification(authority, host, wheels.wheelhouse_path)

    def test_m_exact_venv_and_pip_argv_environment_and_post_qualification_gate(self):
        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, _manifest = repository_fixture(parent)
            mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            snapshot = SimpleNamespace(
                pip_wheel=authority.paths.snapshot_root + "/pip/pip-26.2.1-py3-none-any.whl",
                wheel_directory=authority.paths.snapshot_root + "/wheels",
                lock_file=authority.paths.snapshot_root + "/requirements/" + module._LOCK_NAME,
            )
            venv, pip = module._python_argv(authority, snapshot)
            self.assertEqual(venv, (
                "/usr/bin/python3.12", "-m", "venv", "--without-pip",
                authority.paths.venv_root,
            ))
            provenance = c31p.DevPipInstallerProvenance()
            self.assertEqual(pip[:5], (
                authority.paths.python_executable, "-I", "-c",
                provenance.invocation.bootstrap_source, snapshot.pip_wheel,
            ))
            self.assertEqual(pip[5:], (
                "install", "--no-input", "--disable-pip-version-check",
                "--no-cache-dir", "--no-index", "--only-binary=:all:",
                "--no-deps", "--require-hashes", "--no-compile",
                "--find-links", snapshot.wheel_directory,
                "--requirement", snapshot.lock_file,
            ))
            self.assertEqual(module._VENV_ENVIRONMENT, {
                "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            })
            self.assertEqual(module._PIP_ENVIRONMENT, {
                **module._VENV_ENVIRONMENT, "PIP_CONFIG_FILE": "/dev/null",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INDEX": "1",
                "PIP_NO_INPUT": "1",
            })

    def test_n_process_boundary_is_fixed_closed_and_hides_failures(self):
        result = SimpleNamespace(returncode=0)
        with patch.object(module._subprocess, "run", return_value=result) as run:
            module._run_process(("/usr/bin/python3.12", "-V"), {"LANG": "C"}, 1.0)
        self.assertEqual(run.call_args.kwargs, {
            "shell": False, "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
            "env": {"LANG": "C"}, "timeout": 1.0, "check": False,
            "close_fds": True, "umask": 0o022,
        })
        for failure in (SimpleNamespace(returncode=1), subprocess.TimeoutExpired(("x",), 1)):
            side_effect = failure if isinstance(failure, BaseException) else None
            return_value = None if side_effect else failure
            with patch.object(module._subprocess, "run", side_effect=side_effect,
                              return_value=return_value):
                with self.assertRaises(OSError):
                    module._run_process(("/usr/bin/python3.12", "-V"), {"LANG": "C"}, 1.0)

    def test_o_public_python_operation_requires_c31a_qualifier_for_success(self):
        with tempfile.TemporaryDirectory() as parent:
            repository, configuration, _manifest = repository_fixture(parent)
            mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            snapshot = SimpleNamespace()
            expected = c31a_environment.DevPythonEnvironmentEvidence()
            with patch.object(module, "_open_directory", return_value=(10, [])), \
                 patch.object(module, "_validate_host_qualification"), \
                 patch.object(module, "_prepare_snapshot", return_value=snapshot), \
                 patch.object(module, "_validate_snapshot") as validate_snapshot, \
                 patch.object(module, "_venv_precondition"), \
                 patch.object(module, "_python_argv", return_value=(("/usr/bin/python3.12",), ("/venv/python",))), \
                 patch.object(module, "_run_process") as run, \
                 patch.object(module, "_verify_preinstall_venv"), \
                 patch.object(module, "_cleanup_snapshot"), \
                 patch.object(module, "_close", return_value=(False, None)), \
                 patch.object(module._python_qualification, "qualify_dev_python_environment",
                              return_value=expected) as qualify:
                actual = mechanics.construct_python_environment(
                    host_qualification=object(),
                    repository_root=str(repository), wheelhouse_path="/staging/wheels",
                    pip_installer_staging="/staging/pip",
                )
            self.assertEqual(actual, expected)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(validate_snapshot.call_count, 3)
            qualify.assert_called_once_with(configuration=configuration)

            with patch.object(module, "_open_directory", return_value=(10, [])), \
                 patch.object(module, "_validate_host_qualification"), \
                 patch.object(module, "_prepare_snapshot", return_value=snapshot), \
                 patch.object(module, "_validate_snapshot"), \
                 patch.object(module, "_venv_precondition"), \
                 patch.object(module, "_python_argv", return_value=(("/usr/bin/python3.12",), ("/venv/python",))), \
                 patch.object(module, "_run_process"), \
                 patch.object(module, "_verify_preinstall_venv"), \
                 patch.object(module, "_cleanup_snapshot"), \
                 patch.object(module, "_close", return_value=(False, None)), \
                 patch.object(module._python_qualification, "qualify_dev_python_environment",
                              side_effect=ValueError("secret output")):
                with self.assertRaisesRegex(module.ProvisioningMechanicsError, ERROR) as caught:
                    mechanics.construct_python_environment(
                        host_qualification=object(),
                        repository_root=str(repository), wheelhouse_path="/staging/wheels",
                        pip_installer_staging="/staging/pip",
                    )
            self.assertNotIn("secret", str(caught.exception))

    def test_o_python_failure_identifies_only_the_fixed_internal_phase(self):
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        mechanics = module.DevHostProvisioningMechanics(configuration=configuration)
        for target, phase in (
            ("_prepare_snapshot", "snapshot-preparation"),
            ("_venv_precondition", "venv-precondition"),
            ("_run_process", "venv-command"),
            ("_verify_preinstall_venv", "preinstall-venv-verification"),
        ):
            with self.subTest(phase=phase), \
                 patch.object(module, "_open_directory", return_value=(10, [])), \
                 patch.object(module, "_validate_host_qualification"), \
                 patch.object(module, "_prepare_snapshot", return_value=SimpleNamespace()), \
                 patch.object(module, "_validate_snapshot"), \
                 patch.object(module, "_venv_precondition"), \
                 patch.object(module, "_python_argv", return_value=(("/usr/bin/python3.12",), ("/venv/python",))), \
                 patch.object(module, "_run_process"), \
                 patch.object(module, "_verify_preinstall_venv"), \
                 patch.object(module, "_cleanup_snapshot"), \
                 patch.object(module, "_close", return_value=(False, None)):
                with patch.object(module, target, side_effect=OSError("secret subprocess or path")):
                    with self.assertRaises(module.ProvisioningMechanicsError) as caught:
                        mechanics.construct_python_environment(
                            host_qualification=object(), repository_root="/repository",
                            wheelhouse_path="/wheels", pip_installer_staging="/pip",
                        )
            self.assertEqual(caught.exception.phase, phase)
            self.assertEqual(str(caught.exception), ERROR)
            self.assertNotIn("secret", repr(caught.exception))
        with self.assertRaises(ValueError):
            module.ProvisioningMechanicsError("/tmp/secret")

    def test_p_control_exceptions_and_nonmutating_static_boundary(self):
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        mechanics = module.DevHostProvisioningMechanics(configuration=configuration)
        with patch.object(module, "_application_blobs", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                mechanics.materialize_application_tree(
                    repository_root="/repository", application_manifest=object(),
                )
        source = Path(module.__file__).read_text()
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertFalse(imports & {"socket", "urllib", "http", "requests"})
        self.assertNotIn("systemctl", source)
        self.assertNotIn("docker", source.lower())
        self.assertNotIn("shell=True", source)
        self.assertNotIn("ensurepip", source)

    def test_q_complete_synthetic_snapshot_copies_six_exact_inputs_and_cleans(self):
        with tempfile.TemporaryDirectory() as parent:
            configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
            _mechanics, authority, _application, _venv = temporary_mechanics(
                configuration, parent,
            )
            root = Path(parent)
            wheelhouse = root / "wheelhouse"; wheelhouse.mkdir()
            installer_directory = root / "installer"; installer_directory.mkdir()
            wheel_values = tuple(
                (f"runtime-{index}.whl", f"wheel-{index}".encode())
                for index in range(4)
            )
            for name, payload in wheel_values:
                (wheelhouse / name).write_bytes(payload)
            installer_name = "pip-test.whl"; installer_bytes = b"pip-installer"
            (installer_directory / installer_name).write_bytes(installer_bytes)
            lock_bytes = b"closed-lock\n"
            repository = root / "repo"; (repository / "deployment").mkdir(parents=True)
            (repository / "deployment" / module._LOCK_NAME).write_bytes(lock_bytes)
            wheels = tuple(SimpleNamespace(
                filename=name, sha256=hashlib.sha256(payload).hexdigest(),
            ) for name, payload in wheel_values)
            lock = SimpleNamespace(
                path="deployment/" + module._LOCK_NAME,
                sha256=hashlib.sha256(lock_bytes).hexdigest(),
            )
            environment = SimpleNamespace(wheels=wheels, dependency_lock=lock)
            fake_integrity = SimpleNamespace(
                python_environment_requirement=lambda: environment,
            )
            authority = dataclasses.replace(authority, integrity=fake_integrity)

            def capture_wheels(path, _environment, owned):
                flags, file_flags = c28._flags()
                directories, directory = c28._open_path(path, flags, owned)
                files = []
                for item in wheels:
                    digest, descriptor, fingerprint = c28._hash_wheel(
                        directory, item.filename, file_flags, owned,
                    )
                    self.assertEqual(digest, item.sha256)
                    files.append((descriptor, item.filename, fingerprint))
                return object(), directory, tuple(files), directories

            artifact = SimpleNamespace(
                filename=installer_name, size=len(installer_bytes),
                sha256=hashlib.sha256(installer_bytes).hexdigest(),
            )

            def capture_installer(path, owned):
                flags, file_flags = pip_qualification._flags()
                directories, directory = pip_qualification._open_path(path, flags, owned)
                named = os.stat(installer_name, dir_fd=directory, follow_symlinks=False)
                descriptor = pip_qualification._claim(
                    os.open(installer_name, file_flags, dir_fd=directory), owned,
                )
                fingerprint = pip_qualification._fingerprint(os.fstat(descriptor))
                self.assertEqual(pip_qualification._fingerprint(named), fingerprint)
                return object(), directory, (descriptor, installer_name, fingerprint), directories

            owned = []; source_owned = []; build = {}
            repository_fd = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
            owned.append(repository_fd)
            with patch.object(module._c28, "_qualify_open", side_effect=capture_wheels), \
                 patch.object(module._pip_qualification, "_qualify_open",
                              side_effect=capture_installer), \
                 patch.object(module._c31p, "DevPipInstallerProvenance",
                              return_value=SimpleNamespace(artifact=artifact)):
                snapshot = module._prepare_snapshot(
                    authority, repository_fd, str(wheelhouse),
                    str(installer_directory), owned, source_owned, build,
                )
            try:
                module._validate_snapshot(snapshot, authority)
                self.assertEqual(len(snapshot.files), 6)
                expected = {
                    installer_name: installer_bytes,
                    module._LOCK_NAME: lock_bytes,
                    **dict(wheel_values),
                }
                for _parent_fd, name, descriptor, _fingerprint, size, digest in snapshot.files:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    payload = os.read(descriptor, size + 1)
                    self.assertEqual(payload, expected[name])
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
                module._cleanup_snapshot(snapshot, authority)
                build.clear()
                self.assertFalse(Path(authority.paths.snapshot_root).exists())
            finally:
                module._close(source_owned); module._close(owned)


if __name__ == "__main__":
    unittest.main()
