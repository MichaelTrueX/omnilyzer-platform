"""Focused tests for the bounded, read-only developer status command.

File: deployment/tests/test_dev_status.py

Purpose:
    Verifies local status collection, output bounds, rendering, and failures.

Related files:
    - deployment/dev_status.py: module under test.
    - deployment/tests/test_dev_handoff.py: tests the dependent handoff command.
"""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment import dev_status


class DevStatusTests(unittest.TestCase):
    """Exercise status collection and CLI behavior with controlled observations."""

    def collect(self, status_output=b"", *, sudo_available=False, docker_mode=None,
                status_truncated=False):
        """Collect with all Git and host observations fixed by the test."""
        def command(arguments, **_kwargs):
            """Return fixed status and sudo results for bounded command calls."""
            if arguments[:2] == ["git", "status"]:
                return status_output, status_truncated
            if arguments == ["sudo", "-n", "true"]:
                if not sudo_available:
                    raise dev_status.StatusError("sudo unavailable")
                return b"", False
            raise AssertionError(arguments)

        def git(arguments, **_kwargs):
            """Return fixed repository identity and Git version responses."""
            outputs = {
                "rev-parse": b"/repo\n" if "--show-toplevel" in arguments else b"a" * 40 + b"\n",
                "branch": b"feature/status\n",
                "--version": b"git version test\n",
            }
            return outputs[arguments[0]]

        def docker_stat(path):
            """Supply the requested Docker socket mode or absence."""
            self.assertEqual(path, "/var/run/docker.sock")
            if docker_mode is None:
                raise FileNotFoundError(path)
            return SimpleNamespace(st_mode=docker_mode)

        with (
            patch.object(dev_status, "_command", side_effect=command),
            patch.object(dev_status, "_git", side_effect=git),
            patch.object(Path, "is_dir", return_value=True),
            patch.object(dev_status.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="tester")),
            patch.object(dev_status.os, "getuid", return_value=1000),
            patch.object(dev_status.os, "getgid", return_value=300),
            patch.object(dev_status.os, "getgroups", return_value=[200, 100, 200]),
            patch.object(dev_status.grp, "getgrgid", side_effect=lambda gid: SimpleNamespace(
                gr_name={100: "alpha", 200: "beta", 300: "gamma"}[gid])),
            patch.object(dev_status.os, "stat", side_effect=docker_stat),
            patch.object(dev_status.socket, "gethostname", return_value="test-host"),
            patch.object(dev_status.platform, "python_version", return_value="3.test"),
        ):
            return dev_status.collect_status()

    def test_clean_repository_and_unavailable_optional_capabilities(self):
        """Report a clean tree and unavailable optional host capabilities."""
        result = self.collect()
        self.assertEqual(result["repository"]["worktree"], "clean")
        self.assertEqual(result["repository"]["changed_paths"], [])
        self.assertEqual(result["host"], {
            "hostname": "test-host", "username": "tester",
            "groups": ["alpha", "beta", "gamma"],
        })
        self.assertEqual(result["security_boundary"], {
            "passwordless_sudo_available": False,
            "docker_socket_exists": False,
            "docker_socket_is_unix_socket": False,
        })

    def test_dirty_repository_and_docker_socket(self):
        """Report changed paths and available local security capabilities."""
        result = self.collect(b" M changed.py\0?? new.py\0", sudo_available=True,
                              docker_mode=stat.S_IFSOCK)
        self.assertEqual(result["repository"]["worktree"], "dirty")
        self.assertEqual(result["repository"]["changed_paths"], ["changed.py", "new.py"])
        self.assertTrue(result["security_boundary"]["passwordless_sudo_available"])
        self.assertTrue(result["security_boundary"]["docker_socket_exists"])
        self.assertTrue(result["security_boundary"]["docker_socket_is_unix_socket"])

    def test_changed_paths_are_bounded_and_non_socket_is_reported(self):
        """Bound changed paths and distinguish a regular file from a socket."""
        raw = b"".join(f"?? path-{index}\0".encode() for index in range(25))
        result = self.collect(raw, docker_mode=stat.S_IFREG)
        self.assertEqual(len(result["repository"]["changed_paths"]), dev_status.MAX_CHANGED_PATHS)
        self.assertTrue(result["repository"]["changed_paths_truncated"])
        self.assertFalse(result["security_boundary"]["docker_socket_is_unix_socket"])
        long_path = b"?? " + b"x" * 500 + b"\0"
        result = self.collect(long_path, status_truncated=True)
        self.assertTrue(result["repository"]["changed_paths_truncated"])
        self.assertLessEqual(len(result["repository"]["changed_paths"][0]),
                             dev_status.MAX_PATH_CHARS + 1)

    def test_json_and_human_rendering(self):
        """Expose expected facts through both CLI output formats."""
        status = self.collect(b"?? new.py\0")
        output = io.StringIO()
        with patch.object(dev_status, "collect_status", return_value=status), redirect_stdout(output):
            self.assertEqual(dev_status.main(["--json"]), 0)
        parsed = json.loads(output.getvalue())
        self.assertEqual(set(parsed), {"repository", "host", "security_boundary", "environment"})
        self.assertEqual(parsed["repository"]["head"], "a" * 40)
        output = io.StringIO()
        with patch.object(dev_status, "collect_status", return_value=status), redirect_stdout(output):
            self.assertEqual(dev_status.main([]), 0)
        for field in ("Repository:", "Branch:", "HEAD:", "Worktree: dirty",
                      "Changed paths:", "Hostname:", "Username:", "Groups:",
                      "Passwordless sudo:", "Docker socket exists:", "Python:", "Git:"):
            self.assertIn(field, output.getvalue())

    def test_subprocess_uses_argument_array_without_shell(self):
        """Run commands with argument arrays and suppressed stderr."""
        original = subprocess.Popen
        calls = []

        def recording_popen(*args, **kwargs):
            """Record process invocation while delegating to Popen."""
            calls.append((args, kwargs))
            return original(*args, **kwargs)

        with patch.object(dev_status.subprocess, "Popen", side_effect=recording_popen):
            output, truncated = dev_status._command([sys.executable, "-c", "print('ok')"])
        self.assertEqual(output, b"ok\n")
        self.assertFalse(truncated)
        self.assertIsInstance(calls[0][0][0], list)
        self.assertNotIn("shell", calls[0][1])
        self.assertEqual(calls[0][1]["stderr"], subprocess.DEVNULL)

    def test_subprocess_output_is_bounded(self):
        """Stop reading command output at the configured byte limit."""
        output, truncated = dev_status._command(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100)"], limit=16,
        )
        self.assertEqual(output, b"x" * 16)
        self.assertTrue(truncated)

    def test_subprocess_timeout_is_enforced(self):
        """Terminate a command that exceeds its deadline."""
        started = time.monotonic()
        with patch.object(dev_status, "COMMAND_TIMEOUT_SECONDS", 0.1):
            with self.assertRaises(dev_status.StatusError):
                dev_status._command([sys.executable, "-c", "import time; time.sleep(10)"])
        self.assertLess(time.monotonic() - started, 1)

    def test_fundamental_git_failure_is_generic(self):
        """Fail without exposing raw repository diagnostics."""
        output, error = io.StringIO(), io.StringIO()
        with (patch.object(dev_status, "collect_status",
                           side_effect=dev_status.StatusError("secret/path: raw stderr")),
              redirect_stdout(output), redirect_stderr(error)):
            self.assertNotEqual(dev_status.main(["--json"]), 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Git repository status", error.getvalue())
        self.assertNotIn("secret/path", error.getvalue())
        self.assertNotIn("raw stderr", error.getvalue())


if __name__ == "__main__":
    unittest.main()
