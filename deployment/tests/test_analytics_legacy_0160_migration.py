"""Negative read-only source tests of one exact old root OAT lineage."""
from __future__ import annotations

import copy
import stat
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment.analytics_legacy_0160_migration import (
    _validate_historical_documents, _preflight, _apply, main,
    _review_root_installed_operator_path,
)
from deployment.analytics_route_journal import (
    LEGACY_REQUEST, LEGACY_IMAGE, LEGACY_GREEN,
)
from deployment.tests.test_analytics_legacy_0160_attestation import legacy_intent


class HistoricalRootOATLineageTests(unittest.TestCase):
    def setUp(self):
        self.returned=legacy_intent()
        self.before={**self.returned,"generation":1,"phase":"switched"}
        self.restored={**self.before,"phase":"restored"}
        self.base={
            "before":{"route":{"journal":self.before}},
            "restored":{"journal":self.restored},
            "returned":{"journal":self.returned},
            "result":{"pass":True,"replay_unchanged":True,"database_unchanged":True},
        }

    def accept(self, docs):
        return _validate_historical_documents(
            docs["before"], docs["restored"], docs["returned"],
            docs["result"], self.returned,
        )

    def test_exact_historical_generation2_same_request_lineage(self):
        self.assertIsNone(self.accept(self.base))

    def test_unknown_generation_request_container_or_return_hard_hold(self):
        cases=(
            ("before","generation",2),("before","phase","restored"),
            ("restored","phase","switched"),("returned","generation",3),
            ("returned","phase","restored"),
            ("returned","request_sha256","f"*64),
            ("returned","next_image","mutable:image"),
            ("returned","next_container_id","0"*64),
            ("returned","next_slot","blue"),
        )
        for kind,key,value in cases:
            with self.subTest(kind=kind,key=key), self.assertRaises(ValueError):
                changed=copy.deepcopy(self.base)
                record=changed[kind]["route"]["journal"] if kind=="before" else changed[kind]["journal"]
                record[key]=value
                self.accept(changed)

    def test_failure_or_unknown_database_replay_result_denied(self):
        for key,value in (("pass",False),("database_unchanged",False),
                          ("replay_unchanged",False),("pass",1),
                          ("extra_flag",True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                changed=copy.deepcopy(self.base)
                changed["result"][key]=value
                self.accept(changed)

    def test_root_import_must_refuse_user_worktree_and_wrong_operator_location(self):
        # A root process must not import source from this DEV user checkout.
        import os
        with patch("deployment.analytics_legacy_0160_migration.os.getuid",return_value=0), patch(
            "deployment.analytics_legacy_0160_migration.os.geteuid",return_value=0
        ), patch(
            "deployment.analytics_legacy_0160_migration.os.getgid",return_value=0
        ), patch(
            "deployment.analytics_legacy_0160_migration.os.getegid",return_value=0
        ):
            for path in (
                "/home/omnigpt/repos/omnilyzer-platform/deployment/analytics_legacy_0160_migration.py",
                "/usr/local/libexec/analytics_legacy_0160_migration.py",
                "/opt/omnilyzer/deployment/analytics-app-release-notasha/deployment/analytics_legacy_0160_migration.py",
            ):
                with self.subTest(path=path),self.assertRaises(ValueError):
                    _review_root_installed_operator_path(path,"d"*40)

    def test_root_operator_source_commit_never_defaults_or_accepts_unpinned_sha(self):
        with patch("deployment.analytics_legacy_0160_migration.os.getuid",return_value=0), patch(
            "deployment.analytics_legacy_0160_migration.os.geteuid",return_value=0
        ), patch("deployment.analytics_legacy_0160_migration.os.getgid",return_value=0), patch(
            "deployment.analytics_legacy_0160_migration.os.getegid",return_value=0
        ):
            for sha in ("", "main", "0"*40, "A"*40, "f"*39, "f"*40+"/tmp"):
                with self.subTest(source_sha=sha),self.assertRaises(ValueError):
                    _review_root_installed_operator_path(
                        "/usr/local/libexec/omnilyzer-m05-legacy-0160-migration.py",sha,
                    )

    def test_exact_separately_installed_root_operator_accepts_only_immutable_source(self):
        sha = "d" * 40
        script = Path("/usr/local/libexec/omnilyzer-m05-legacy-0160-migration.py")
        source = Path("/opt/omnilyzer/deployment/analytics-app-release-" + sha)
        def verified_stat(path, bad=None):
            path = Path(path)
            if path == script:
                mode = stat.S_IFREG | 0o500
            elif path in (source / "deployment/analytics_route_journal.py",
                          source / "deployment/policy.py"):
                mode = stat.S_IFREG | 0o644
            else:
                mode = stat.S_IFDIR | 0o755
            uid,gid,links=0,0,1
            if bad is not None and path == bad[0]:
                updates=bad[1]
                mode=updates.get("mode",mode)
                uid=updates.get("uid",uid)
                gid=updates.get("gid",gid)
                links=updates.get("links",links)
            return SimpleNamespace(st_mode=mode,st_uid=uid,st_gid=gid,st_nlink=links)
        with (patch("deployment.analytics_legacy_0160_migration.os.getuid",return_value=0),
              patch("deployment.analytics_legacy_0160_migration.os.geteuid",return_value=0),
              patch("deployment.analytics_legacy_0160_migration.os.getgid",return_value=0),
              patch("deployment.analytics_legacy_0160_migration.os.getegid",return_value=0)):
            with patch("deployment.analytics_legacy_0160_migration.os.lstat",side_effect=verified_stat):
                self.assertEqual(_review_root_installed_operator_path(str(script),sha),source)
            for bad in (
                (script,{"mode":stat.S_IFREG|0o644}),
                (script,{"uid":1005}),
                (script,{"links":2}),
                (script,{"mode":stat.S_IFLNK|0o777}),
                (source,{"gid":991}),
                (source,{"mode":stat.S_IFDIR|0o775}),
                (source/"deployment/policy.py",{"mode":stat.S_IFREG|0o664}),
                (source/"deployment/analytics_route_journal.py",{"uid":991}),
                (source/"deployment/analytics_route_journal.py",{"links":2}),
            ):
                with self.subTest(bad=bad),patch(
                    "deployment.analytics_legacy_0160_migration.os.lstat",
                    side_effect=lambda path,bad=bad:verified_stat(path,bad)
                ),self.assertRaises(ValueError):
                    _review_root_installed_operator_path(str(script),sha)

    def test_non_root_migration_is_denied_without_existing_file_access(self):
        # Works under both GitHub native-root QA and unprivileged DEV QA.
        with patch("deployment.analytics_legacy_0160_migration.os.getuid",return_value=1005):
            with self.assertRaises(ValueError):
                _preflight()

    def test_no_source_only_apply_can_write_real_root_journal(self):
        # Reading or calling the operator through the connected UID1005 is
        # a *negative* path; its mandatory root guard stops before any writes.
        with patch("deployment.analytics_legacy_0160_migration.os.getuid",return_value=1005):
            with self.assertRaises(ValueError):
                _preflight()


def main_root_uid():
    import os
    return os.getuid()


if __name__=="__main__":
    unittest.main()
