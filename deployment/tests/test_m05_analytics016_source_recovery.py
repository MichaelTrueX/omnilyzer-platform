"""File: deployment/tests/test_m05_analytics016_source_recovery.py

Purpose: Test the fresh, non-replayable PR296 source-only operator and its
         independent installed-766e read-only gate without privileged actions.
Related: deployment/m05_pr296_d11_fresh_20261116_source_only.py,
         deployment/analytics_executor_service_config.py, Issue #281.
Authority: Unprivileged tests only. Never dispatch, install, or change Docker.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

# Section 1: Always import the complete first-party source at the exact path.
SOURCE = Path(__file__).resolve().parent.parent / "m05_pr296_d11_fresh_20261116_source_only.py"
_spec = importlib.util.spec_from_file_location("m05_pr296_d11_fresh_review", SOURCE)
assert _spec is not None and _spec.loader is not None
operator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(operator)


def fake_prior(*, change_record: str | None = None):
    """Create only immutable, synthetic root-receipt identities for regression."""
    called = []
    paths = tuple((Path(f"/private/testing/config{i}"), 990 if i < 3 else 991)
                  for i in range(1, 4))
    replay = "a" * 64
    record = {
        "schema_version": 1,
        "previous_installed_commit": "previous-2b",
        "next_installed_commit": operator.OLD_MAIN,
        "previous_oneway_seal": "/private/previous/promotion-armed",
        "consumed_failed_task014_run": 43387587420,
        "historical_failed_runs_nonreplayable": True,
        "source_manifest_sha256": "manifest-sha",
        "previous_executor_sha256": "previous-executor",
        "next_executor_sha256": "next-executor",
        "source_only": True,
        "new_task014_dispatched": False,
        "replay_sha256_before": replay,
        "prior_root_source_backup": "/private/older-backup",
    }
    if change_record:
        record[change_record] = True
    expected = {path: b"{}" for path, _gid in paths}
    receipt = Path("/private/receipt")
    receipt_bytes = operator.canonical(record)
    manifest = {"deployment/analytics_executor.py": "previous-executor"}
    meta = types.SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0,
    )
    recorded_file_meta = types.SimpleNamespace(st_size=len(receipt_bytes))
    def pinned(path, *_args):
        """Use only synthetic values for the requested existing receipt path."""
        if path == receipt / "receipt.json":
            return receipt_bytes
        if path in (receipt / f"config_{i:02d}.before"
                    for i in range(1, 4)):
            return b"{}"
        return b"marker"
    def service_state(name):
        """Represent the original protected service constellation only."""
        return "failed" if name == operator.EXECUTOR else "active"
    helper = types.SimpleNamespace(
        read_config=lambda path, gid: expected[path],
        service_state=service_state,
        healthy=lambda: called.append("health"),
    )
    previous = types.SimpleNamespace(
        original=lambda: helper, NEW_MARKER=b"old-marker",
    )
    diagnostic = {"SEAL_BYTES": b"seal",
                  "active_state_stable": lambda: called.append("active")}
    prior = types.SimpleNamespace(
        root_environment=lambda: called.append("root"),
        STAGE=Path("/private/unused-stage"),
        NEXT_RECEIPT=receipt,
        PREVIOUS_RECEIPT=Path("/private/previous"),
        PREVIOUS_COMMIT="previous-2b",
        MANIFEST_SHA="manifest-sha",
        PREVIOUS_EXECUTOR_SHA="previous-executor",
        NEXT_EXECUTOR_SHA="next-executor",
        NEXT_BACKUP=Path("/private/older-backup"),
        NEXT_MARKER_FILE="source-installed",
        NEXT_MARKER_BYTES=b"old-source-only",
        REL_EXECUTOR="deployment/analytics_executor.py",
        CONFIG_PATHS=paths,
        approved_helpers=lambda: (previous, None, diagnostic),
        reviewed_manifest=lambda: manifest,
        sha=operator.sha,
        _bounded_read_only=lambda path, size: b"synthetic",
        _unique=operator.unique,
        pinned=pinned,
        canonical=operator.canonical,
        next_configs=lambda before, meta: expected,
        source_tree=lambda path, vector: called.append("source_tree"),
        uid991_next_source=lambda: called.append("uid991"),
        replay_snapshot=lambda d: replay,
        post_install_readonly=lambda: (_ for _ in ()).throw(
            AssertionError("Consumed original OAT must not be repeated")),
    )
    def fake_lstat(path):
        """Simulate 0700 protected receipt and existing regular preimages."""
        return meta if path == receipt else recorded_file_meta
    return prior, called, fake_lstat


# Section 2: Prove the new source path refuses rootless execution.
class FreshSourceRecoveryTests(unittest.TestCase):
    """Check non-replay, immutable stage identities and read-only attestation."""

    def test_fresh_source_stays_distinct_from_consumed_installer(self):
        """Use unique root receipts and do not inherit a consumed one-shot flag."""
        self.assertEqual(operator.NEW_MAIN,
                         "d11ce821715b3e1eca2689701065b0e3e2a19e50")
        self.assertEqual(operator.OLD_MAIN,
                         "766e4763f04b0d2dc57b3981374ddc29c6893183")
        self.assertNotEqual(operator.RECEIPT, operator._OLD_PR296_RECEIPT)
        self.assertNotEqual(operator.BACKUP, operator._OLD_PR296_BACKUP)
        self.assertIn("fresh", operator.RECEIPT.name)
        self.assertIn("fresh", operator.BACKUP.name)
        self.assertEqual(operator.STAGE.name, ".analytics-app-reviewed-staging")
        self.assertNotIn("--apply-approved-pr296-source-only-once",
                         SOURCE.read_text())

    def test_nonroot_execution_never_enters_source_installer(self):
        """Deny an authorized-looking new flag outside a root0400 snapshot."""
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SOURCE),
             "--apply-approved-analytics016-d11-fresh-once"],
            capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, (
            b"M05_016_FRESH_HOLD_AT_ROOT_SNAPSHOT_PATH\n"
            b"M05_016_FRESH_HARD_HOLD_NO_AUTORETRY\n"
        ))
        self.assertEqual(result.stderr, b"")

    def test_missing_or_moved_root_snapshot_denied(self):
        """Reject a root-owned path outside the reviewed one-time /run slot."""
        with self.assertRaises(operator.Hold):
            operator._require_root_snapshot()

    def test_full_766_readonly_receipt_checks_without_original_oat(self):
        """Verify one unchanged UID991 primitive and zero composite-OAT replays."""
        prior, called, fake_lstat = fake_prior()
        with (patch.object(operator.os, "lstat", side_effect=fake_lstat),
              patch.object(operator.os.path, "lexists", return_value=False),
              patch.object(operator, "ROUTE", Path("/dev/null"))):
            # The route object is purely fake, never read from host.
            with patch.object(Path, "iterdir", return_value=iter(())):
                operator.attest_prior_766_readonly(prior)
        self.assertEqual(called, [
            "root", "source_tree", "source_tree",
            "uid991", "health", "active",
        ])

    def test_consumed_task014_receipt_rejected_before_uid991(self):
        """Do not accept a signed-dispatch receipt that claims replay occurred."""
        prior, called, fake_lstat = fake_prior(
            change_record="new_signed_dispatch",
        )
        with (patch.object(operator.os, "lstat", side_effect=fake_lstat),
              patch.object(operator.os.path, "lexists", return_value=False)):
            with self.assertRaises(operator.Hold):
                operator.attest_prior_766_readonly(prior)
        self.assertNotIn("uid991", called)

    def test_reuse_existing_approved_76_source_assembly(self):
        """Keep old source-verification methods and original 76-file producer."""
        text = SOURCE.read_text()
        self.assertIn("previous.selected_sources(helper, old_executor)", text)
        self.assertIn("installer._stage_new_generation(", text)
        self.assertIn("installer._original._finish_close(holder)", text)
        self.assertIn("helper.exchange_directory(CANDIDATE, STAGE)", text)
        self.assertIn("verify_tree(CANDIDATE, target)", text)
        self.assertIn("verify_tree(BACKUP, old)", text)
        self.assertIn("uid991_source_preflight()", text)
        self.assertIn('"new_signed_dispatch": False', text)
        self.assertIn("prior.replay_snapshot(diagnostic)", text)
        self.assertNotIn("prior.post_install_readonly()\n", text.split(
            "def root_preflight()", 1)[-1])

    def test_no_generic_sudo_or_external_dispatch(self):
        """The release-specific root code may not start a new signed request."""
        text = SOURCE.read_text()
        self.assertNotIn("sudo ", text)
        self.assertNotIn("gh workflow run", text)
        self.assertNotIn("subprocess.Popen", text)
        self.assertNotIn("docker run", text)


# Section 3: Standard inert test discovery, without installing a package.
if __name__ == "__main__":
    unittest.main()
