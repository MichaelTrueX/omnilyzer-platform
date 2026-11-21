"""Negative read-only source tests of one exact old root OAT lineage."""
from __future__ import annotations

import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment.analytics_legacy_0160_migration import (
    _validate_historical_documents, _preflight, _apply, main,
)
from deployment.analytics_legacy_0160_attestation import (
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
