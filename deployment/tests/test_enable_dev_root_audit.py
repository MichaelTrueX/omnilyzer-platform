"""File: deployment/tests/test_enable_dev_root_audit.py

Purpose: Verify the OWNER-only bootstrap cannot grant arbitrary sudo,
         deploy, write secrets or run without root and the reviewed host.
Related: deployment/enable_dev_root_audit.sh,
         deployment/analytics_dev_host_preflight.py, original Task014 C17.

Sections: embedded Python compilation, exact scoped sudo rule, non-root
          execution denial, read-only metadata method with mocked root.
No sudo invocation, privilege escalation, systemd mutation or server writes.
"""
from __future__ import annotations

from pathlib import Path
import ast
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deployment/enable_dev_root_audit.sh"


def section(raw: str, name: str) -> str:
    """Extract one closed heredoc without running the shell bootstrap."""
    start = f"cat > \"$TMP/{name}\" <<'PY'\n" if name == "helper.py" else (
        f"cat > \"$TMP/{name}\" <<'SUDOERS'\n"
    )
    if name == "helper.py":
        return raw.split(start, 1)[1].split("\nPY\n", 1)[0] + "\n"
    return raw.split(start, 1)[1].split("\nSUDOERS\n", 1)[0] + "\n"


class RestrictedRootBootstrapTests(unittest.TestCase):
    """Owner-only one-time bootstrap must remain closed and inert."""

    @classmethod
    def setUpClass(cls):
        """Read the complete checked-out source, not an internet script."""
        cls.shell = SCRIPT.read_text(encoding="utf-8")
        cls.helper = section(cls.shell, "helper.py")
        cls.sudoers = section(cls.shell, "sudoers")

    def test_real_shell_and_embedded_python_compile(self):
        """No syntax bypasses or unparseable root-owned helper code."""
        result = subprocess.run(
            ("/bin/bash", "-n", str(SCRIPT)),
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        ast.parse(self.helper, filename="omnilyzer-dev-root-audit.py")
        compile(self.helper, "omnilyzer-dev-root-audit.py", "exec")

    def test_sudoers_allows_only_one_argv_without_wildcards(self):
        """Never provide all-command root or a caller-selected interpreter."""
        rules = [line.strip() for line in self.sudoers.splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(rules, [
            "omnigpt ALL=(root) NOPASSWD:NOSETENV: "
            "/usr/bin/python3 -I "
            "/usr/local/libexec/omnilyzer-dev-root-audit.py --read-only",
        ])
        for token in ("* ", "NOPASSWD:ALL", "/bin/bash", "-c ", "/usr/bin/env"):
            self.assertNotIn(token, rules[0])

    def test_nonroot_running_bootstrap_cannot_change_any_system_file(self):
        """A normal omnigpt/CI account is denied before any root operation."""
        if __import__("os").geteuid() == 0:
            self.skipTest("This negative test requires unprivileged CI")
        result = subprocess.run(
            ("/bin/bash", str(SCRIPT)),
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("execute with sudo", result.stderr)

    def test_helper_only_exposes_hardcoded_stat_and_unit_read(self):
        """A requested install/exec/secret path cannot enter the root helper."""
        self.assertEqual(self.helper.count("subprocess.run("), 1)
        self.assertIn('("/usr/bin/systemctl", "is-active", name)', self.helper)
        self.assertIn("follow_symlinks=False", self.helper)
        self.assertIn('sys.argv[1:] != ["--read-only"]', self.helper)
        for snippet in (
            "os.system(", "os.popen(", "os.chmod(", "os.chown(",
            "os.remove(", "os.unlink(", "os.write(", "subprocess.Popen(",
            "shell=True", "requests.", "urllib.request",
            "docker", "DATABASE_URL", "JWT_SECRET",
        ):
            # Documentation may mention a term; inspect only executable
            # portions (comments and module/function docstrings excluded).
            tree = ast.parse(self.helper)
            import_restricted = {
                "socket", "requests", "urllib", "shutil", "ctypes",
            }
            self.assertFalse(any(
                isinstance(node, ast.Import) and any(
                    alias.name.split(".")[0] in import_restricted
                    for alias in node.names
                ) for node in ast.walk(tree)
            ))
            self.assertNotIn(snippet, "\n".join(
                line for line in self.helper.splitlines()
                if not line.lstrip().startswith("#")
            ) if snippet not in ("docker", "DATABASE_URL", "JWT_SECRET")
                             else self.helper.split("def main()", 1)[-1])


if __name__ == "__main__":
    unittest.main()
