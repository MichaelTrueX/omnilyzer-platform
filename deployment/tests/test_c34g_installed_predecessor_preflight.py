"""File: deployment/tests/test_c34g_installed_predecessor_preflight.py

Purpose: Exercise the root-only read-only C34G preflight's source-manifest
pin, canonical configuration parsing, privilege check and fail-closed output.
Related: deployment/c34g_installed_predecessor_preflight.py,
deployment/c34f_application_generation_evidence.py,
deployment/tests/test_c34g_migration_authority.py.

Synthetic fixtures only; this suite does not use sudo, mutate the host,
read protected configuration, restart services or contact GitHub/registry.
"""

from __future__ import annotations

import ast
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment import c34g_installed_predecessor_preflight as check


class C34GInstalledReadOnlyTests(unittest.TestCase):
    """Check immutable predecessor evidence and strict no-side-effects behavior."""

    def test_all_41_pinned_blobs_match_canonical_manifest(self):
        """The standalone root script embeds the exact reviewed source manifest."""
        self.assertEqual(len(check.EXPECTED), 41)
        names = sorted(check.EXPECTED)
        path_digest = hashlib.sha256(("\n".join(names) + "\n").encode()).hexdigest()
        self.assertEqual(path_digest, check.PATH_SET_SHA256)
        manifest = {
            "manifest_kind": "canonical-relative-file-set-v1",
            "digest_algorithm": "sha256",
            "reviewed_commit": check.OLD,
            "entries": [{"path": name, "sha256": check.EXPECTED[name],
                         "mode": "0644"} for name in names],
        }
        raw = (json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("ascii")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), check.MANIFEST_SHA256)

    def test_duplicate_json_members_and_noncanonical_encoding_are_rejected(self):
        """Protected config loader rejects ambiguous serialization."""
        for raw in (
            b'{"a":1,"a":2}\n',
            b'{"b":2, "a":1}\n',
            b'{"a":1}\n\n',
            b'{"a":NaN}\n',
        ):
            with self.subTest(value=raw), self.assertRaises((ValueError, TypeError)):
                check.canonical_object(raw)
        self.assertEqual(check.canonical_object(b'{"a":1}\n'), {"a": 1})

    def test_unprivileged_cannot_inspect_root_files(self):
        """The privilege gate must fail before any source/config reader call."""
        with patch.object(check.os, "getuid", return_value=1005), patch.object(
            check.os, "geteuid", return_value=1005
        ), patch.object(check, "verify_source") as scan:
            with redirect_stdout(io.StringIO()) as output:
                code = check.main()
        self.assertEqual(code, 2)
        self.assertIn("root_identity_required", output.getvalue())
        scan.assert_not_called()

    def test_root_preflight_prints_only_fixed_pass_or_hold(self):
        """Never expose exception text or sensitive files on failure."""
        patches = (
            patch.object(check.os, "getuid", return_value=0),
            patch.object(check.os, "geteuid", return_value=0),
            patch.object(check.os, "getgid", return_value=0),
            patch.object(check.os, "getegid", return_value=0),
        )
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

        with patch.object(check, "service_state", return_value=(
                ("broker", "active"),)), patch.object(
                    check, "verify_source"
                ) as source, patch.object(
                    check, "verify_configs"
                ) as configs:
            with redirect_stdout(io.StringIO()) as passed:
                self.assertEqual(check.main(), 0)
            self.assertIn("C34G_PREFLIGHT_PASS", passed.getvalue())
            source.assert_called_once()
            configs.assert_called_once()

        with patch.object(check, "service_state", side_effect=ValueError(
            "SYNTHETIC_SECRET_THAT_MUST_NOT_LOG"
        )):
            with redirect_stdout(io.StringIO()) as blocked:
                self.assertEqual(check.main(), 2)
            self.assertEqual(
                blocked.getvalue().strip(),
                "C34G_PREFLIGHT_HOLD installed_predecessor_not_qualified",
            )
            self.assertNotIn("SYNTHETIC_SECRET", blocked.getvalue())

    def test_preflight_contains_no_write_or_deployment_primitives(self):
        """Reject accidental integration of mutating filesystem or subprocess calls."""
        path = Path(check.__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden = {
            "replace", "rename", "renameat", "unlink", "remove", "rmdir",
            "mkdir", "makedirs", "chmod", "chown", "fchmod", "fchown",
            "write", "pwrite", "truncate", "ftruncate", "fsync",
        }
        calls = [
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os" and node.func.attr in forbidden
        ]
        self.assertEqual(calls, [])
        self.assertNotIn("sudo", path.read_text(encoding="utf-8"))
        self.assertNotIn("shell=True", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
