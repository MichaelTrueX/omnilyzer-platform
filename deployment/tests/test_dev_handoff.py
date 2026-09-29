"""Focused tests for the local, bounded developer handoff.

File: deployment/tests/test_dev_handoff.py

Purpose:
    Verifies handoff summaries, output formats, bounds, and local Git use.

Related files:
    - deployment/dev_handoff.py: module under test.
    - deployment/dev_status.py: shared observations used by the handoff.
"""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from deployment import dev_handoff, dev_status


class DevHandoffTests(unittest.TestCase):
    """Exercise the handoff with controlled status and Git observations."""

    def status(self, *, dirty=False, paths=None):
        """Build a fixed shared-status result for handoff tests."""
        return {
            "repository": {
                "root": "/repo", "branch": "feature/handoff", "head": "a" * 40,
                "worktree": "dirty" if dirty else "clean",
                "changed_paths": paths or [], "changed_paths_truncated": False,
            },
            "host": {"hostname": "test-host", "username": "tester", "groups": ["dev"]},
            "security_boundary": {"passwordless_sudo_available": False,
                                  "docker_socket_exists": True,
                                  "docker_socket_is_unix_socket": True},
            "environment": {"python_version": "3.test", "git_version": "git version test"},
        }

    def collect(self, *, status=None, upstream=None, ahead=b"0\t0\n",
                staged=b"", unstaged=b"", untracked=b""):
        """Collect a handoff with mocked local Git responses."""
        calls = []

        def git(arguments, **kwargs):
            """Record Git arguments and return the requested fixture."""
            calls.append((arguments, kwargs))
            if arguments[0] == "rev-parse":
                if upstream is None:
                    raise dev_status.StatusError("no upstream")
                return upstream.encode() + b"\n"
            if arguments[0] == "rev-list":
                return ahead
            if arguments[0] == "diff":
                return staged if "--cached" in arguments else unstaged
            if arguments[0] == "ls-files":
                return untracked
            raise AssertionError(arguments)

        with (patch.object(dev_handoff.dev_status, "collect_status",
                           return_value=status or self.status()),
              patch.object(dev_handoff.dev_status, "_git", side_effect=git)):
            result = dev_handoff.collect_handoff()
        return result, calls

    def test_clean_repository_without_upstream(self):
        """Show zero changes and a missing upstream for a clean tree."""
        result, _ = self.collect()
        self.assertEqual(result["repository"]["worktree"], "clean")
        self.assertEqual(result["repository"]["upstream"], "(none)")
        self.assertIsNone(result["repository"]["ahead"])
        self.assertEqual(result["changes"]["staged_files"], 0)
        self.assertEqual(result["changes"]["untracked_files"], 0)
        self.assertEqual(result["changes"]["changed_files"], 0)

    def test_dirty_staged_unstaged_untracked_and_local_upstream(self):
        """Summarize staged, unstaged, untracked, and local upstream state."""
        result, calls = self.collect(
            status=self.status(dirty=True, paths=["staged.py", "working.py", "new.py"]),
            upstream="origin/feature/handoff", ahead=b"2\t3\n",
            staged=b"4\t1\tstaged.py\0", unstaged=b"2\t5\tworking.py\0",
            untracked=b"new.py\0second.txt\0",
        )
        self.assertEqual((result["repository"]["ahead"], result["repository"]["behind"]),
                         (2, 3))
        changes = result["changes"]
        self.assertEqual((changes["staged_files"], changes["unstaged_files"],
                          changes["untracked_files"]), (1, 1, 2))
        self.assertEqual(changes["changed_files"], 4)
        self.assertEqual((changes["staged_insertions"], changes["staged_deletions"]), (4, 1))
        self.assertEqual((changes["unstaged_insertions"], changes["unstaged_deletions"]), (2, 5))
        self.assertEqual((changes["insertions"], changes["deletions"]), (6, 6))
        self.assertEqual(changes["paths"], ["staged.py", "working.py", "new.py"])
        self.assertIn(["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
                      [arguments for arguments, _ in calls])

    def test_changed_file_count_deduplicates_staged_and_unstaged_path(self):
        """Count a path changed in both stages only once overall."""
        result, _ = self.collect(staged=b"1\t0\tshared.py\0",
                                 unstaged=b"0\t1\tshared.py\0")
        self.assertEqual(result["changes"]["changed_files"], 1)

    def test_bounded_paths_and_optional_count_failures(self):
        """Bound displayed paths and tolerate optional Git summary failures."""
        status = self.status(dirty=True, paths=[f"path-{number}" for number in range(25)])

        def git(arguments, **_kwargs):
            """Simulate unavailable optional local Git observations."""
            raise dev_status.StatusError("private diagnostics")

        with (patch.object(dev_handoff.dev_status, "collect_status", return_value=status),
              patch.object(dev_handoff.dev_status, "_git", side_effect=git)):
            result = dev_handoff.collect_handoff()
        self.assertEqual(len(result["changes"]["paths"]), dev_status.MAX_CHANGED_PATHS)
        self.assertTrue(result["changes"]["paths_truncated"])
        self.assertIsNone(result["changes"]["insertions"])
        self.assertIsNone(result["changes"]["untracked_files"])
        self.assertIsNone(result["changes"]["changed_files"])

    def test_binary_and_oversize_summary_is_unavailable(self):
        """Mark binary line counts and oversized summaries unavailable."""
        result, _ = self.collect(staged=b"-\t-\timage.png\0",
                                 unstaged=b"1000000001\t0\tlarge.py\0")
        self.assertEqual(result["changes"]["staged_files"], 1)
        self.assertIsNone(result["changes"]["staged_insertions"])
        self.assertIsNone(result["changes"]["unstaged_files"])
        self.assertIsNone(result["changes"]["insertions"])

    def test_json_structure_and_compact_human_output(self):
        """Keep JSON sections stable and human output concise."""
        result, _ = self.collect(status=self.status(dirty=True, paths=["one.py"]),
                                 upstream="origin/feature/handoff",
                                 unstaged=b"1\t0\tone.py\0")
        with patch.object(dev_handoff, "collect_handoff", return_value=result):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(dev_handoff.main(["--json"]), 0)
            parsed = json.loads(output.getvalue())
            self.assertEqual(set(parsed), {"repository", "changes", "host",
                                           "security_boundary", "environment"})
            self.assertNotIn("root", parsed["repository"])
            self.assertNotIn("\n", output.getvalue().strip())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(dev_handoff.main([]), 0)
        human = output.getvalue()
        self.assertTrue(human.startswith("OMNILYZER DEV HANDOFF\n"))
        for label in ("Repository", "Changes", "Host", "Security boundary", "Environment",
                      "  Branch:", "  HEAD:", "  Worktree: dirty", "  Upstream:",
                      "  Staged files:", "  Unstaged files:", "  Untracked files:",
                      "  Changed files:", "  Insertions:", "  Deletions:", "  Paths:",
                      "  Python:", "  Git:"):
            self.assertIn(label, human)
        self.assertLess(len(human), 1000)
        self.assertNotIn("diff --git", human)

    def test_fundamental_failure_is_generic_and_nonzero(self):
        """Return a generic error without leaking raw Git diagnostics."""
        output, error = io.StringIO(), io.StringIO()
        with (patch.object(dev_handoff.dev_status, "collect_status",
                           side_effect=dev_status.StatusError("secret/path: raw stderr")),
              redirect_stdout(output), redirect_stderr(error)):
            self.assertNotEqual(dev_handoff.main([]), 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Git repository status", error.getvalue())
        self.assertNotIn("secret/path", error.getvalue())
        self.assertNotIn("raw stderr", error.getvalue())

    def test_git_calls_are_local_argument_arrays_with_bounded_output(self):
        """Use local Git subcommands through the argument-array helper."""
        _, calls = self.collect(upstream="origin/feature/handoff")
        forbidden = {"fetch", "pull", "push", "ls-remote"}
        self.assertTrue(calls)
        for arguments, kwargs in calls:
            self.assertIsInstance(arguments, list)
            self.assertTrue(forbidden.isdisjoint(arguments))
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["cwd"], "/repo")
        self.assertTrue(all(command[0][0] in {"rev-parse", "rev-list", "diff", "ls-files"}
                            for command in calls))


if __name__ == "__main__":
    unittest.main()
