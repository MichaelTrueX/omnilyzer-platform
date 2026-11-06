"""File: services/identity/tests/test_inactive_identity_release.py
Purpose: Prove the existing M01 inactive upgrade rejects unsafe source files
         and never changes current even after a successful simulated install.
Related: services/identity/ops/install_inactive_identity_release.py,
         services/identity/omnilyzer-identity.service.
No real user, systemd, PostgreSQL, Keycloak or /opt paths are modified.
"""
import importlib.util
import io
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
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
            self.assertEqual(current.resolve(), old)
            self.assertIn(str(target / ".venv/bin/python"),
                          (target / ".venv/bin/gunicorn").read_text())


if __name__ == "__main__":
    unittest.main()
