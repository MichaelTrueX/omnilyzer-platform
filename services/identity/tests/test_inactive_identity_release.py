"""File: services/identity/tests/test_inactive_identity_release.py
Purpose: Prove the existing M01 inactive upgrade rejects unsafe source files
         and never changes current even after a successful simulated install.
Related: services/identity/ops/install_inactive_identity_release.py,
         services/identity/omnilyzer-identity.service.
No real user, systemd, PostgreSQL, Keycloak or /opt paths are modified.
"""
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


# Section 1: Load the actual narrowly scoped production operator source.
SOURCE = (Path(__file__).resolve().parents[1] / "ops"
          / "install_inactive_identity_release.py")
SPEC = importlib.util.spec_from_file_location("m01_inactive", SOURCE)
OP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OP)


def make_tar(path, items):
    """Write small test-only tar fixtures without invoking root utilities."""
    with tarfile.open(path, "w") as tf:
        for name, kind, content in items:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(content)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(content))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "../../escape"
                tf.addfile(info)
            else:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)


class InactiveReleaseTests(unittest.TestCase):
    """Focused safety and immutability assertions for the real operator."""

    def test_service_requires_exact_reviewed_selected_release(self):
        """A mere owner GO marker must never start an older BFF binary."""
        unit = (SOURCE.parents[1] / "omnilyzer-identity.service").read_text(
            encoding="utf-8")
        guard = (
            "ExecCondition=/usr/bin/test "
            "/opt/omnilyzer/identity/current -ef "
            "/opt/omnilyzer/identity/releases/"
            "3481cacbef910a37d87a3c26341b1a8f16a6612f"
        )
        self.assertEqual(unit.count(guard), 1)
        self.assertIn(
            "AssertPathExists=/etc/omnilyzer/identity/owner-approved-go",
            unit)
        self.assertLess(unit.index(guard), unit.index("ExecStartPre="))
        self.assertNotIn("-ExecCondition=", unit)
        # Exercise the same /usr/bin/test -ef predicate on disposable
        # filesystem objects without needing root or modifying /opt.
        with tempfile.TemporaryDirectory() as home:
            base = Path(home)
            reviewed = base / "reviewed"
            obsolete = base / "obsolete"
            current = base / "current"
            reviewed.mkdir()
            obsolete.mkdir()
            current.symlink_to(obsolete, target_is_directory=True)
            command = ["/usr/bin/test", str(current), "-ef", str(reviewed)]
            self.assertEqual(subprocess.run(command, check=False).returncode, 1)
            current.unlink()
            current.symlink_to(reviewed, target_is_directory=True)
            self.assertEqual(subprocess.run(command, check=False).returncode, 0)

    def test_symlink_retarget_after_guard_keeps_executable_paths_pinned(self):
        """The service never executes a mutable current symlink after guard."""
        unit = (SOURCE.parents[1] / "omnilyzer-identity.service").read_text(
            encoding="utf-8")
        reviewed_root = (
            "/opt/omnilyzer/identity/releases/"
            "3481cacbef910a37d87a3c26341b1a8f16a6612f"
        )
        lines = [
            line.split("=", 1) for line in unit.splitlines()
            if line.startswith(("WorkingDirectory=", "ExecStartPre=",
                                "ExecStart="))
        ]
        self.assertEqual(len(lines), 3)
        directives = dict(lines)
        self.assertEqual(len(directives), 3)
        self.assertEqual(
            directives["WorkingDirectory"],
            reviewed_root + "/services/identity")
        self.assertEqual(
            directives["ExecStartPre"].split(" ", 1)[0],
            reviewed_root + "/.venv/bin/python")
        self.assertEqual(
            directives["ExecStart"].split(" ", 1)[0],
            reviewed_root + "/.venv/bin/gunicorn")
        self.assertTrue(
            all("/current/" not in value for value in directives.values()))
        # Reproduce reviewer-reported TOCTOU using only disposable paths.
        with tempfile.TemporaryDirectory() as home:
            base = Path(home)
            reviewed = base / "reviewed"
            obsolete = base / "obsolete"
            current = base / "current"
            for p in (reviewed, obsolete):
                (p / "services/identity").mkdir(parents=True)
                (p / ".venv/bin").mkdir(parents=True)
                (p / ".venv/bin/python").write_text("test-only")
                (p / ".venv/bin/gunicorn").write_text("test-only")
            current.symlink_to(reviewed, target_is_directory=True)
            predicate = ["/usr/bin/test", str(current), "-ef", str(reviewed)]
            self.assertEqual(subprocess.run(predicate, check=False).returncode, 0)
            # The selection is changed after the condition passes.
            current.unlink()
            current.symlink_to(obsolete, target_is_directory=True)
            self.assertEqual(subprocess.run(predicate, check=False).returncode, 1)
            for relative in ("services/identity", ".venv/bin/python",
                             ".venv/bin/gunicorn"):
                # Original service directives are rooted at reviewed_root.
                # Simulated executions resolve to reviewed, not current.
                self.assertEqual((reviewed / relative).resolve(),
                                 (reviewed / relative).absolute())
                self.assertNotEqual((reviewed / relative).resolve(),
                                    (current / relative).resolve())

    def test_stage_path_uses_exact_sha_prefix(self):
        self.assertEqual(OP.stage_for("abcd1234" + "0" * 32).name,
                         "omnilyzer-identity-abcd123-source-stage-20261106")

    def test_archive_rejects_traversal_links_and_out_of_scope(self):
        with tempfile.TemporaryDirectory() as home:
            archive = Path(home) / "test.tar"
            for bad in [
                [("../../etc/cron.d/evil", "file", b"x")],
                [("services/identity/escape", "symlink", b"")],
                [("not-the-identity-module", "file", b"x")],
            ]:
                make_tar(archive, bad)
                with self.subTest(bad=bad[0][0]):
                    with self.assertRaisesRegex(RuntimeError,
                                                "M01_INACTIVE_RELEASE_HOLD"):
                        OP.manifest_members(archive)
            make_tar(archive, [
                ("services/", "dir", b""),
                ("services/identity/", "dir", b""),
                ("services/identity/requirements.txt", "file", b"django==6.1"),
            ])
            self.assertEqual(len(OP.manifest_members(archive)), 3)

    def test_cannot_run_privileged_install_directly_from_user_home(self):
        with mock.patch.object(OP.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "root authorization"):
                OP.trusted_privileged_operator()

    def test_root_only_marker_cannot_be_inferred_absent_by_nonroot(self):
        """Do not stat an inaccessible 0700 secret path as nonroot."""
        with (mock.patch.object(OP.os, "geteuid", return_value=1000),
              mock.patch.object(OP, "APPROVAL") as marker,
              mock.patch.object(OP, "CURRENT") as current,
              mock.patch.object(OP, "RELEASES") as releases,
              mock.patch.object(OP, "OLD") as old,
              mock.patch.object(OP.socket, "gethostname", return_value=OP.HOST),
              mock.patch.object(OP, "run", return_value=(
                  "ActiveState=inactive\nUnitFileState=disabled")),
              mock.patch("tarfile.open") as arch):
            current.is_symlink.return_value = True
            current.resolve.return_value = old
            releases.__truediv__.return_value.exists.return_value = False
            releases.__truediv__.return_value.is_symlink.return_value = False
            old.__truediv__.return_value.is_file.return_value = True
            old.__truediv__.return_value.read_bytes.return_value = b""
            arch.return_value.__enter__.return_value.extractfile.return_value.read.return_value = b""
            # The root-only marker must never be probed by nonroot.
            OP.installed_runtime_guard("a" * 40, "fixture.tar")
            marker.exists.assert_not_called()
            marker.is_symlink.assert_not_called()

    def test_runtime_console_relocation(self):
        with tempfile.TemporaryDirectory() as home:
            p = Path(home)
            old = p / "old"
            new = p / "new"
            gunicorn = new / ".venv/bin/gunicorn"
            gunicorn.parent.mkdir(parents=True)
            gunicorn.write_bytes(
                ("#!" + str(old / ".venv/bin/python") +
                 "\nprint('test')\n").encode())
            gunicorn.chmod(0o755)
            OP.rewrite_console_scripts(new / ".venv", old, new)
            self.assertTrue(gunicorn.read_bytes().startswith(
                ("#!" + str(new / ".venv/bin/python") + "\n").encode()))
            self.assertTrue(bool(gunicorn.stat().st_mode & stat.S_IXUSR))

    def test_git_source_directories_traversable_after_restrictive_umask(self):
        """The copied release imports remain accessible to nonroot service."""
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            archive = root / "test.tar"
            make_tar(archive, [
                ("services/", "dir", b""),
                ("services/identity/", "dir", b""),
                ("services/identity/identity_bff/", "dir", b""),
                ("services/identity/identity_bff/views.py", "file", b"test"),
            ])
            output = root / "release"
            output.mkdir()
            previous = os.umask(0o077)
            try:
                with tarfile.open(archive) as tf:
                    members = tf.getmembers()
                    tf.extractall(output, filter="data")
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(
                (output / "services").stat().st_mode), 0o700)
            OP.normalize_source_directories(output, members)
            for rel in ("services", "services/identity",
                        "services/identity/identity_bff"):
                self.assertEqual(stat.S_IMODE(
                    (output / rel).stat().st_mode), 0o755)
            self.assertEqual(
                (output / "services/identity/identity_bff/views.py").read_bytes(),
                b"test")

    def test_existing_inactive_repair_preserves_exact_source_bytes(self):
        """Repair reviewed source dirs once, with no installed file mutation."""
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            archive = root / "test.tar"
            make_tar(archive, [
                ("services/", "dir", b""),
                ("services/identity/", "dir", b""),
                ("services/identity/identity_bff/", "dir", b""),
                ("services/identity/identity_bff/views.py", "file", b"exact"),
            ])
            installed = root / "installed"
            installed.mkdir()
            installed.chmod(0o755)
            with tarfile.open(archive) as tf:
                tf.extractall(installed, filter="data")
            for rel in ("services", "services/identity",
                        "services/identity/identity_bff"):
                (installed / rel).chmod(0o700)
            (installed / ".venv/bin").mkdir(parents=True)
            for exe in ("python", "gunicorn"):
                (installed / ".venv/bin" / exe).write_text("test only")
            original_venv_mode = stat.S_IMODE(
                (installed / ".venv/bin/python").stat().st_mode)

            real_lstat = Path.lstat

            def root_metadata(path):
                original = real_lstat(path)
                return SimpleNamespace(
                    st_mode=original.st_mode, st_uid=0, st_gid=0,
                    st_nlink=original.st_nlink)

            with (mock.patch.object(OP, "trusted_privileged_operator"),
                  mock.patch.object(Path, "lstat", root_metadata),
                  mock.patch.object(OP, "run", return_value="") as action):
                OP.repair_inactive_source_permissions(
                    "a" * 40, archive, installed)
            for rel in ("services", "services/identity",
                        "services/identity/identity_bff"):
                self.assertEqual(
                    stat.S_IMODE((installed / rel).stat().st_mode), 0o755)
            self.assertEqual(
                (installed / "services/identity/identity_bff/views.py").read_bytes(),
                b"exact")
            self.assertEqual(
                stat.S_IMODE(
                    (installed / ".venv/bin/python").stat().st_mode),
                original_venv_mode)
            self.assertEqual(action.call_count, 1)
            self.assertEqual(action.call_args.args[0][:3], [
                "/usr/sbin/runuser", "-u", "omnilyzer-identity"])

    def test_inactive_repair_denies_tampered_source_before_mode_write(self):
        """Reject file drift before modifying any installed directory."""
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            archive = root / "test.tar"
            make_tar(archive, [
                ("services/", "dir", b""),
                ("services/identity/", "dir", b""),
                ("services/identity/identity_bff/", "dir", b""),
                ("services/identity/identity_bff/views.py", "file", b"expected"),
            ])
            installed = root / "installed"
            installed.mkdir(mode=0o755)
            installed.chmod(0o755)
            with tarfile.open(archive) as tf:
                tf.extractall(installed, filter="data")
            target = installed / "services/identity/identity_bff/views.py"
            target.write_bytes(b"tampered")
            (installed / "services").chmod(0o700)
            (installed / ".venv/bin").mkdir(parents=True)
            for exe in ("python", "gunicorn"):
                (installed / ".venv/bin" / exe).write_text("test only")

            # Emulate root:root metadata without requiring sudo in unit tests.
            real_lstat = Path.lstat

            def root_metadata(path):
                original = real_lstat(path)
                return SimpleNamespace(
                    st_mode=original.st_mode, st_uid=0, st_gid=0,
                    st_nlink=original.st_nlink)

            with (mock.patch.object(OP, "trusted_privileged_operator"),
                  mock.patch.object(Path, "lstat", root_metadata)):
                with self.assertRaisesRegex(RuntimeError, "source file differs"):
                    OP.repair_inactive_source_permissions(
                        "a" * 40, archive, installed)
            self.assertEqual(
                stat.S_IMODE((installed / "services").stat().st_mode), 0o700)

    def test_simulated_inactive_release_keeps_original_current(self):
        """Copy small local fixtures, not the production venv or live DB."""
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as home:
            base = Path(home)
            releases = base / "releases"
            old = releases / ("b" * 40)
            oldvenv = old / ".venv/bin"
            oldvenv.mkdir(parents=True)
            (oldvenv / "python").symlink_to(sys.executable)
            (oldvenv / "gunicorn").write_text(
                "#!" + str(oldvenv / "python") + "\nprint('test')\n")
            (oldvenv / "gunicorn").chmod(0o755)
            current = base / "current"
            current.symlink_to(old, target_is_directory=True)
            archive = base / "source.tar"
            make_tar(archive, [
                ("services/", "dir", b""),
                ("services/identity/", "dir", b""),
                ("services/identity/config/", "dir", b""),
                ("services/identity/config/wsgi.py", "file", b""),
                ("services/identity/requirements.txt", "file",
                 b"Django==6.1\n"),
            ])
            target = releases / sha
            with (mock.patch.object(OP, "RELEASES", releases),
                  mock.patch.object(OP, "OLD", old),
                  mock.patch.object(OP, "CURRENT", current),
                  mock.patch.object(OP, "trusted_privileged_operator"),
                  mock.patch.object(OP, "check_pinned_packages")):
                OP.install_inactive(sha, archive, target)
            self.assertTrue(target.is_dir())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual(current.resolve(), old)
            self.assertIn(str(target / ".venv/bin/python"),
                          (target / ".venv/bin/gunicorn").read_text())


if __name__ == "__main__":
    unittest.main()
