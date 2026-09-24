"""C26 model, real Git-object evidence and disposable repository attack tests."""

import ast
import builtins
import dataclasses
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deployment.application_manifest as module
from deployment.application_source_set import DevApplicationSourceSet
from deployment.policy import canonical_bytes

ROOT = Path(__file__).resolve().parents[2]
UNAVAILABLE = "DEV application manifest evidence is unavailable"
MODEL_ERROR = "DEV application manifest model is invalid"
PATHS = tuple(item.repository_path for item in DevApplicationSourceSet().files)
POPULATED_RECOVERY_PREDECESSOR = "c78e94f5e7c6b1a557ac041bdfb560bb82c1642b"
POPULATED_RECOVERY_MANIFEST_SHA256 = "575d09be5933ea226313a20a958cbc5066cabcf20580e7343ee3034ac3a95f1e"


def git(root, *arguments):
    """Test-side fixed Git, including mutations only of disposable repositories."""
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
        "GIT_AUTHOR_NAME": "C26 Test", "GIT_AUTHOR_EMAIL": "c26@example.invalid",
        "GIT_COMMITTER_NAME": "C26 Test", "GIT_COMMITTER_EMAIL": "c26@example.invalid",
    }
    return subprocess.run(("/usr/bin/git", "--no-replace-objects", "-C", str(root), *arguments),
                          env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, shell=False, timeout=5, check=True).stdout


def fixture():
    """Construct inert valid exact-C25 model values."""
    return module.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", "a" * 40,
        tuple(module.ApplicationManifestEntry(path, "b" * 64, "0644") for path in PATHS),
    )


class Text(str):
    pass


class ModelTests(unittest.TestCase):
    def test_populated_recovery_preserves_every_c25_source_byte(self):
        entries = []
        for source in DevApplicationSourceSet().files:
            path = source.repository_path
            current = (ROOT / path).read_bytes()
            predecessor = git(ROOT, "show", f"{POPULATED_RECOVERY_PREDECESSOR}:{path}")
            self.assertEqual(current, predecessor, path)
            entries.append(module.ApplicationManifestEntry(
                path, hashlib.sha256(current).hexdigest(), "0644",
            ))
        self.assertEqual(len(entries), 28)
        manifest = module.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256",
            POPULATED_RECOVERY_PREDECESSOR, tuple(entries),
        )
        self.assertEqual(
            hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
            POPULATED_RECOVERY_MANIFEST_SHA256,
        )

    def test_exact_api(self):
        self.assertEqual(module.__all__, (
            "ApplicationManifestEvidenceError", "ApplicationManifestEntry",
            "DevApplicationManifest", "generate_dev_application_manifest",
        ))
        self.assertEqual({name for name in vars(module) if not name.startswith("_")}, set(module.__all__))
        self.assertTrue(issubclass(module.ApplicationManifestEvidenceError, Exception))
        self.assertEqual({name for name, value in vars(module.DevApplicationManifest).items()
                          if not name.startswith("_") and callable(value)}, {"to_dict", "canonical_bytes"})

    def test_shapes_and_frozen_slots(self):
        for cls, names, value in (
            (module.ApplicationManifestEntry, ("path", "sha256", "mode"), fixture().entries[0]),
            (module.DevApplicationManifest, ("manifest_kind", "digest_algorithm", "reviewed_commit", "entries"), fixture()),
        ):
            self.assertEqual(tuple(f.name for f in dataclasses.fields(cls)), names)
            self.assertEqual(cls.__slots__, names)
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertFalse(hasattr(value, "__dict__"))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(value, names[0], "changed")

    def test_generator_signature(self):
        parameters = inspect.signature(module.generate_dev_application_manifest).parameters
        self.assertEqual(tuple(parameters), ("repository_root", "reviewed_commit"))
        for parameter in parameters.values():
            self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaises(TypeError):
            module.generate_dev_application_manifest(str(ROOT), "a" * 40)
        for override in ("source_set", "application_root", "git_executable", "mode", "hash_algorithm"):
            with self.subTest(override=override), self.assertRaises(TypeError):
                module.generate_dev_application_manifest(repository_root=str(ROOT), reviewed_commit="a" * 40,
                                                         **{override: "arbitrary"})

    def assert_model_failure(self, callback):
        with self.assertRaises(ValueError) as caught:
            callback()
        self.assertEqual(str(caught.exception), MODEL_ERROR)

    def test_entry_validation(self):
        values = {"path": "deployment/a.py", "sha256": "a" * 64, "mode": "0644"}
        attacks = {
            "path": (Text(values["path"]), None, b"a", "", "/a", "//a", "a//b", "./a", "../a",
                     "a/./b", "a/../b", "a\\b", "a\0b", "a/"),
            "sha256": (Text("a" * 64), None, "A" * 64, "a" * 63, "a" * 65, "g" * 64),
            "mode": (Text("0644"), None, 420, 0o755, "0755", "0600", "0660", "0777", "420", ""),
        }
        for field, candidates in attacks.items():
            for candidate in candidates:
                with self.subTest(field=field, candidate=candidate):
                    self.assert_model_failure(lambda: module.ApplicationManifestEntry(**(values | {field: candidate})))

    def test_manifest_validation(self):
        valid = fixture()
        values = {field.name: getattr(valid, field.name) for field in dataclasses.fields(valid)}
        class EntrySubclass(module.ApplicationManifestEntry):
            pass
        attacks = {
            "manifest_kind": ("wrong", Text(valid.manifest_kind)),
            "digest_algorithm": ("SHA256", Text("sha256")),
            "reviewed_commit": ("0" * 40, "A" * 40, "a" * 39, "a" * 41, "main", Text("a" * 40)),
            "entries": (list(valid.entries), valid.entries[:-1], valid.entries + (valid.entries[0],),
                        tuple(reversed(valid.entries)), (valid.entries[0],) * 28,
                        (EntrySubclass(PATHS[0], "b" * 64, "0644"),) + valid.entries[1:],
                        (module.ApplicationManifestEntry("deployment/unselected.py", "b" * 64, "0644"),)
                        + valid.entries[1:]),
        }
        for field, candidates in attacks.items():
            for candidate in candidates:
                with self.subTest(field=field):
                    self.assert_model_failure(lambda: module.DevApplicationManifest(**(values | {field: candidate})))

    def test_forged_nested_entries(self):
        valid = fixture()
        for fields in ({}, {"path": PATHS[0]}, {"path": PATHS[0], "sha256": "b" * 64},
                       {"path": PATHS[0], "sha256": "b" * 64, "mode": "0755"},
                       {"path": PATHS[0], "sha256": "bad", "mode": "0644"}):
            entry = object.__new__(module.ApplicationManifestEntry)
            for name, value in fields.items():
                object.__setattr__(entry, name, value)
            with self.subTest(fields=fields):
                self.assert_model_failure(lambda: module.DevApplicationManifest(
                    valid.manifest_kind, valid.digest_algorithm, valid.reviewed_commit,
                    (entry,) + valid.entries[1:]))

    def test_canonical_bytes_and_fresh_containers(self):
        manifest = fixture()
        encoded = manifest.canonical_bytes()
        self.assertIs(type(encoded), bytes)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded.count(b"\n"), 1)
        encoded.decode("ascii")
        self.assertNotIn(b": ", encoded)
        self.assertNotIn(b", ", encoded)
        self.assertEqual(encoded, canonical_bytes(manifest.to_dict()))
        self.assertEqual(encoded, manifest.canonical_bytes())
        parsed = json.loads(encoded)
        self.assertEqual(list(parsed), sorted(("manifest_kind", "digest_algorithm", "reviewed_commit", "entries")))
        for entry in parsed["entries"]:
            self.assertEqual(list(entry), ["mode", "path", "sha256"])
        first, second = manifest.to_dict(), manifest.to_dict()
        self.assertIs(type(first), dict)
        self.assertIs(type(first["entries"]), list)
        self.assertIsNot(first, second)
        self.assertIsNot(first["entries"], second["entries"])
        self.assertIsNot(first["entries"][0], second["entries"][0])
        first["entries"][0]["path"] = "changed"
        first["entries"].clear()
        self.assertEqual(manifest.canonical_bytes(), encoded)

    def test_manifest_bound_and_encoder_contract(self):
        self.assertEqual(module._MAX_MANIFEST_BYTES, 65536)
        for encoded in (b"x" * 65537, bytearray(b"x"), "x", b""):
            with self.subTest(kind=type(encoded)), patch.object(module, "_canonical_bytes", return_value=encoded):
                self.assert_model_failure(fixture().canonical_bytes)
        oversized = object.__new__(module.ApplicationManifestEntry)
        for name, value in {"path": PATHS[0], "sha256": "b" * 70000, "mode": "0644"}.items():
            object.__setattr__(oversized, name, value)
        valid = fixture()
        self.assert_model_failure(lambda: module.DevApplicationManifest(
            valid.manifest_kind, valid.digest_algorithm, valid.reviewed_commit,
            (oversized,) + valid.entries[1:]))

    def test_import_inertness(self):
        # Preload C25 dependencies; Python's loader reads are not evidence I/O.
        with patch.object(subprocess, "Popen", side_effect=AssertionError("Git on import")), \
             patch.object(hashlib, "sha256", side_effect=AssertionError("hash on import")), \
             patch.object(builtins, "open", side_effect=AssertionError("open on import")), \
             patch.object(os, "open", side_effect=AssertionError("open on import")), \
             patch.object(os.path, "realpath", side_effect=AssertionError("path inspection")), \
             patch.object(socket, "socket", side_effect=AssertionError("network on import")):
            importlib.reload(module)
            self.assertEqual(len(fixture().entries), 28)

    def test_no_operational_authority(self):
        tree = ast.parse((ROOT / "deployment/application_manifest.py").read_text())
        forbidden = {"urllib", "http", "requests", "socket", "release", "venv", "pip", "shutil"}
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertFalse(imports & forbidden)
        operations = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(operations & {"read_bytes", "read_text", "open", "stat", "chmod", "chown", "mkdir",
                                       "makedirs", "unlink", "rename", "replace", "copy", "write", "write_bytes"})
        strings = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and type(node.value) is str}
        self.assertFalse(any(s.startswith(("/opt", "/etc/omnilyzer", "/var/lib/omnilyzer",
                                          "/var/log/omnilyzer", "/run/omnilyzer")) for s in strings))


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="task014-c26-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        git(self.root, "init", "--quiet")
        git(self.root, "config", "core.autocrlf", "false")
        git(self.root, "config", "core.filemode", "true")
        for index, path in enumerate(PATHS):
            source = self.root / path
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"C26\r\n\x00\xff" + str(index).encode() + b"\n")
            source.chmod(0o644)
        self.commit("A")
        self.a = self.head()

    def head(self):
        return git(self.root, "rev-parse", "HEAD").decode().strip()

    def commit(self, message):
        git(self.root, "add", "--all")
        git(self.root, "commit", "--quiet", "-m", message)

    def generate(self, commit=None):
        return module.generate_dev_application_manifest(repository_root=str(self.root),
                                                        reviewed_commit=commit or self.head())

    def assert_unavailable(self, callback):
        with self.assertRaises(module.ApplicationManifestEvidenceError) as caught:
            callback()
        self.assertEqual(str(caught.exception), UNAVAILABLE)
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_real_repository_head_evidence(self):
        head = git(ROOT, "rev-parse", "HEAD").decode().strip()
        manifest = module.generate_dev_application_manifest(repository_root=str(ROOT), reviewed_commit=head)
        self.assertEqual(tuple(entry.path for entry in manifest.entries), PATHS)
        for entry in manifest.entries:
            record = git(ROOT, "ls-tree", "-z", head, "--", entry.path)
            mode, kind, rest = record.split(b" ", 2)
            blob, path = rest[:-1].split(b"\t")
            self.assertEqual((mode, kind, path.decode()), (b"100644", b"blob", entry.path))
            raw = git(ROOT, "cat-file", "blob", blob.decode())
            self.assertEqual(entry.sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(entry.mode, "0644")
        selection = DevApplicationSourceSet()
        self.assertEqual(len(manifest.entries), 28)
        self.assertEqual(sum(item.kind == "python-module" for item in selection.files), 25)
        self.assertEqual(sum(item.kind == "runtime-data" for item in selection.files), 3)
        for excluded in ("application_manifest.py", "application_source_set.py", "host_provisioning_contract.py",
                         "installation_integrity_contract.py", "requirements-linux-x86_64-py312.lock",
                         "dev_host_provisioning_plan.py", "python_environment_qualification.py",
                         "dev_host_provisioning_mechanics.py",
                         "dev_persistent_state_prerequisites.py",
                         "dev_post_provision_qualification.py",
                         "dev_host_provisioning_orchestration.py",
                         "runtime/dev/host-nginx.conf"):
            self.assertNotIn("deployment/" + excluded, PATHS)
        self.assertFalse(any("/systemd/" in path for path in PATHS))

    def test_dirty_worktree_and_symlink_do_not_change_evidence(self):
        before = self.generate().canonical_bytes()
        selected = self.root / PATHS[0]
        selected.write_bytes(b"dirty replacement")
        self.assertEqual(self.generate(self.a).canonical_bytes(), before)
        selected.unlink()
        selected.symlink_to("does-not-exist")
        self.assertEqual(self.generate(self.a).canonical_bytes(), before)

    def test_head_mismatch(self):
        (self.root / "extra.txt").write_text("B")
        self.commit("B")
        self.assert_unavailable(lambda: self.generate(self.a))

    def test_unselected_commit_change_preserves_selected_evidence(self):
        before = self.generate()
        (self.root / "extra.txt").write_text("B")
        self.commit("B")
        b = self.head()
        git(self.root, "checkout", "--quiet", self.a)
        self.assertEqual(self.generate().canonical_bytes(), before.canonical_bytes())
        git(self.root, "checkout", "--quiet", b)
        after = self.generate()
        self.assertEqual(before.entries, after.entries)
        self.assertNotEqual(before.reviewed_commit, after.reviewed_commit)
        self.assertNotEqual(before.canonical_bytes(), after.canonical_bytes())

    def test_committed_executable_rejected(self):
        (self.root / PATHS[0]).chmod(0o755)
        self.commit("executable")
        self.assert_unavailable(self.generate)

    def test_committed_symlink_rejected(self):
        source = self.root / PATHS[0]
        source.unlink()
        source.symlink_to("elsewhere")
        self.commit("symlink")
        self.assert_unavailable(self.generate)

    def test_missing_selected_path_rejected(self):
        (self.root / PATHS[0]).unlink()
        self.commit("missing")
        self.assert_unavailable(self.generate)

    def test_extra_files_not_admitted(self):
        for name in ("deployment/evil.py", "README-extra.txt", "deployment/tests/not-runtime.py"):
            source = self.root / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("unselected")
        self.commit("extras")
        self.assertEqual(tuple(entry.path for entry in self.generate().entries), PATHS)

    def test_replace_objects_cannot_redirect_evidence(self):
        original = self.generate()
        (self.root / PATHS[0]).write_bytes(b"replaced content")
        self.commit("B")
        b = self.head()
        git(self.root, "checkout", "--quiet", self.a)
        git(self.root, "replace", self.a, b)
        self.assertEqual(git(self.root, "rev-parse", "refs/replace/" + self.a).decode().strip(), b)
        self.assertEqual(self.generate(self.a).canonical_bytes(), original.canonical_bytes())

    def test_worktree_chmod_irrelevant(self):
        before = self.generate().canonical_bytes()
        (self.root / PATHS[0]).chmod(0o777)
        self.assertEqual(self.generate().canonical_bytes(), before)
        self.assertTrue(all(entry.mode == "0644" for entry in self.generate().entries))

    def test_input_validation_and_nested_root(self):
        for root in (Text(str(self.root)), None, "", "/", "relative", "//tmp/repo", str(self.root) + "/",
                     str(self.root) + "/./", str(self.root) + "/../repo", "/tmp/a\0b", "/tmp/a\\b"):
            with self.subTest(root=root):
                self.assert_unavailable(lambda: module.generate_dev_application_manifest(repository_root=root,
                                                                                        reviewed_commit=self.a))
        for commit in (Text(self.a), None, "HEAD", "main", "refs/heads/main", self.a[:12], self.a.upper(),
                       "0" * 40, "g" * 40):
            with self.subTest(commit=commit):
                self.assert_unavailable(lambda: module.generate_dev_application_manifest(
                    repository_root=str(self.root), reviewed_commit=commit))
        self.assert_unavailable(lambda: module.generate_dev_application_manifest(
            repository_root=str(self.root / "deployment"), reviewed_commit=self.a))
        nested = self.root / "nested"
        nested.mkdir()
        git(nested, "init", "--quiet")
        self.assert_unavailable(lambda: module.generate_dev_application_manifest(repository_root=str(nested),
                                                                                reviewed_commit=self.a))

    def test_fixed_git_boundary_and_environment(self):
        original = subprocess.Popen
        invocations = []
        def record(argv, **kwargs):
            invocations.append((argv, kwargs))
            return original(argv, **kwargs)
        hostile = {name: "hostile" for name in (
            "GIT_DIR", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
        )}
        with patch.dict(os.environ, hostile), patch.object(subprocess, "Popen", side_effect=record):
            self.generate(self.a)
        self.assertEqual(module._TIMEOUT, 5.0)
        self.assertTrue(invocations)
        for argv, kwargs in invocations:
            self.assertEqual(argv[:4], ("/usr/bin/git", "--no-replace-objects", "-C", str(self.root)))
            self.assertIn(argv[4], ("rev-parse", "ls-tree", "cat-file"))
            self.assertIs(kwargs["shell"], False)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stdout"], subprocess.PIPE)
            env = kwargs["env"]
            self.assertFalse(set(hostile) & set(env))
            self.assertEqual(env, {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_LITERAL_PATHSPECS": "1",
            })

    def test_malformed_tree_outputs(self):
        original = module._git
        valid = git(self.root, "ls-tree", "-r", "-z", "--full-tree", self.a, "--", *PATHS)
        records = valid[:-1].split(b"\0")
        attacks = (b"", valid[:-1], valid + records[0] + b"\0", b"\0".join(reversed(records)) + b"\0",
                   valid.replace(b"100644", b"100755", 1), valid.replace(b"100644", b"120000", 1),
                   valid.replace(b"blob", b"tree", 1), valid.replace(b"100644", b"160000", 1),
                   valid.replace(PATHS[0].encode(), b"deployment/unknown.py", 1),
                   records[0].replace(b" blob ", b" blob invalid", 1) + b"\0", bytearray(valid))
        for attack in attacks:
            def respond(root, args, maximum):
                return attack if args[0] == "ls-tree" else original(root, args, maximum)
            with self.subTest(attack=type(attack)), patch.object(module, "_git", side_effect=respond):
                self.assert_unavailable(lambda: self.generate(self.a))

    def test_blob_size_and_raw_output_attacks(self):
        original = module._git
        sizes = (b"-1\n", b"01\n", b"+1\n", b" 1\n", b"1", b"1048577\n", b"x\n")
        for size in sizes:
            def respond(root, args, maximum):
                return size if args[:2] == ("cat-file", "-s") else original(root, args, maximum)
            with self.subTest(size=size), patch.object(module, "_git", side_effect=respond):
                self.assert_unavailable(lambda: self.generate(self.a))
        with patch.object(module, "_git", side_effect=lambda root, args, maximum:
                          b"1048576\n" if args[:2] == ("cat-file", "-s") else original(root, args, maximum)):
            self.assert_unavailable(lambda: self.generate(self.a))
        for transform in (lambda raw: raw[:-1], lambda raw: raw + b"x", lambda raw: bytearray(raw)):
            def respond(root, args, maximum):
                raw = original(root, args, maximum)
                return transform(raw) if args[:2] == ("cat-file", "blob") else raw
            with self.subTest(transform=transform), patch.object(module, "_git", side_effect=respond):
                self.assert_unavailable(lambda: self.generate(self.a))

    def test_failures_generic_and_control_flow_preserved(self):
        for failure in (OSError("secret path stderr errno"), subprocess.TimeoutExpired("secret command", 5),
                        ValueError("secret hash")):
            with patch.object(subprocess, "Popen", side_effect=failure):
                self.assert_unavailable(lambda: self.generate(self.a))
        for exception in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with patch.object(module, "_git", side_effect=exception), self.assertRaises(exception):
                self.generate(self.a)

    def test_qualification_and_head_race_outputs(self):
        original = module._git
        for command, response in (
            (("rev-parse", "--show-toplevel"), b"/unrelated-root\n"),
            (("rev-parse", "--show-toplevel"), b"relative\n"),
            (("rev-parse", "--verify", "HEAD^{commit}"), self.a.upper().encode() + b"\n"),
            (("rev-parse", "--verify", "HEAD^{commit}"), self.a.encode()),
            (("cat-file", "-t", self.a), b"tree\n"),
        ):
            def respond(root, args, maximum):
                return response if args == command else original(root, args, maximum)
            with self.subTest(command=command), patch.object(module, "_git", side_effect=respond):
                self.assert_unavailable(lambda: self.generate(self.a))
        count = 0
        def race(root, args, maximum):
            nonlocal count
            if args == ("rev-parse", "--verify", "HEAD^{commit}"):
                count += 1
                if count == 2:
                    return b"b" * 40 + b"\n"
            return original(root, args, maximum)
        with patch.object(module, "_git", side_effect=race):
            self.assert_unavailable(lambda: self.generate(self.a))

    def test_source_set_override_and_forgery_fail_closed(self):
        forged = object.__new__(DevApplicationSourceSet)
        object.__setattr__(forged, "files", ())
        with patch.object(module, "_DevApplicationSourceSet", return_value=forged):
            self.assert_unavailable(lambda: self.generate(self.a))
        with patch.object(module, "_DevApplicationSourceSet", return_value=object()):
            self.assert_unavailable(lambda: self.generate(self.a))

    def test_hash_provider_contract_failures(self):
        for result in ("A" * 64, "a" * 63, Text("a" * 64), b"a" * 64):
            with self.subTest(result=type(result)), patch.object(hashlib, "sha256") as hasher:
                hasher.return_value.hexdigest.return_value = result
                self.assert_unavailable(lambda: self.generate(self.a))

    def test_process_returncode_and_timeout_cleanup(self):
        original = subprocess.Popen
        for returncode in (-9, 1, True, None):
            def spawn(argv, **kwargs):
                process = original(argv, **kwargs)
                wait = process.wait
                def wrong_wait(timeout):
                    wait(timeout=timeout)
                    return returncode
                process.wait = wrong_wait
                return process
            with self.subTest(returncode=returncode), patch.object(subprocess, "Popen", side_effect=spawn):
                self.assert_unavailable(lambda: self.generate(self.a))
        processes = []
        def spawn_record(argv, **kwargs):
            process = original(argv, **kwargs)
            processes.append(process)
            return process
        with patch.object(subprocess, "Popen", side_effect=spawn_record), patch.object(
            module._selectors, "DefaultSelector", side_effect=TimeoutError("private timeout detail")
        ):
            self.assert_unavailable(lambda: self.generate(self.a))
        self.assertTrue(processes)
        self.assertTrue(all(process.poll() is not None and process.stdout.closed for process in processes))

    def test_missing_blob_does_not_fetch(self):
        record = git(self.root, "ls-tree", "-z", self.a, "--", PATHS[0])
        blob = record.split(b" ", 2)[2].split(b"\t")[0].decode()
        git(self.root, "config", "remote.origin.url", "http://127.0.0.1:1/forbidden")
        git(self.root, "config", "remote.origin.promisor", "true")
        git(self.root, "config", "extensions.partialClone", "origin")
        (self.root / ".git/objects" / blob[:2] / blob[2:]).unlink()
        original = subprocess.Popen
        calls = []
        def record_call(argv, **kwargs):
            calls.append(argv)
            return original(argv, **kwargs)
        with patch.object(subprocess, "Popen", side_effect=record_call):
            self.assert_unavailable(lambda: self.generate(self.a))
        self.assertTrue(all(argv[4] in ("rev-parse", "cat-file", "ls-tree") for argv in calls))

    def test_actual_stdout_bound_and_nonzero_stderr_suppression(self):
        self.assert_unavailable_with_git_bound()
        with patch.object(module, "_TIMEOUT", 0.0):
            self.assert_unavailable(lambda: self.generate(self.a))
        # Actual fixed Git reports a nonexistent repository only through suppressed stderr.
        self.assert_unavailable(lambda: module.generate_dev_application_manifest(
            repository_root=str(self.root / "missing-secret"), reviewed_commit=self.a))

    def assert_unavailable_with_git_bound(self):
        with self.assertRaises(ValueError):
            module._git(str(self.root), ("rev-parse", "--verify", "HEAD^{commit}"), 1)


if __name__ == "__main__":
    unittest.main()
