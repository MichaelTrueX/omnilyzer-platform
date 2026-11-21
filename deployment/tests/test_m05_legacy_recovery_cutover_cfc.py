"""M05 source-only cutover tests; NEVER run a privileged root switch.

All systemd/file mutation operations are mocked; read-only fixtures are real
Git-reviewed 330f config bytes and derived pinned cfc payloads.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

REPO_OPERATOR = Path(__file__).resolve().parents[1] / "operators/m05_legacy_recovery_cutover_cfc.py"
MODULE_PATH = REPO_OPERATOR if REPO_OPERATOR.exists() else Path(__file__).with_name(
    "root-recovery-cutover-cfc-reviewed.py"
)
spec = importlib.util.spec_from_file_location("m05_cfc_recovery_review", MODULE_PATH)
m = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(m)


class PinnedSourceConfigTests(unittest.TestCase):
    def test_exact_four_current_root_preimages_and_derived_payloads(self):
        root = Path("/home/omnigpt/repos/omnilyzer-platform")
        old_handoff = root / ".m05-ordinary-dev-review-handoff-330f-20261121/payload"
        new_handoff = MODULE_PATH.parent / "payload"
        self.assertEqual(len(m.PLAN), 4)
        for name, expected_target_sha, _, _ in m.PLAN:
            with self.subTest(file=name):
                old = (old_handoff / name.lstrip("/")).read_bytes()
                new = (new_handoff / name.lstrip("/")).read_bytes()
                self.assertEqual(hashlib.sha256(old).hexdigest(), m.EXPECTED_OLD[name])
                self.assertEqual(hashlib.sha256(new).hexdigest(), expected_target_sha)
                self.assertNotEqual(old, new)
                if name.endswith(".json"):
                    a,b=json.loads(old),json.loads(new)
                    self.assertEqual(set(a),set(b))
                    self.assertEqual({key for key in a if a[key]!=b[key]},
                                     {"reviewed_installed_commit","source_sha256"})
                    self.assertEqual(a["reviewed_installed_commit"], m.ORIGINAL_SOURCE)
                    self.assertEqual(b["reviewed_installed_commit"], m.SHA)
                    self.assertEqual(a["expected_workflow_sha"],b["expected_workflow_sha"])
                    self.assertEqual(a["expected_workflow_sha"],
                                     "630db1ae5a05a691493764637e066e487f52f599")
                    self.assertEqual(len(a["source_sha256"]),26)
                    self.assertEqual(len(b["source_sha256"]),26)
                    self.assertEqual({k for k in a["source_sha256"]
                                      if a["source_sha256"][k]!=b["source_sha256"][k]},
                                     {"deployment/analytics_executor.py",
                                      "deployment/analytics_route_journal.py"})
                else:
                    self.assertEqual(new, old.replace(m.OLD_ROOT.encode(),
                                                       m.NEW_ROOT.encode()))
        broker, executor=m.PLAN[0][0],m.PLAN[1][0]
        self.assertEqual((new_handoff/broker.lstrip("/")).read_bytes(),
                         (new_handoff/executor.lstrip("/")).read_bytes())

    def test_nonroot_must_refuse_both_actions(self):
        with patch.object(m.os,"getuid",return_value=1005):
            for action in ("--preflight","--switch"):
                with self.subTest(action=action),self.assertRaises(PermissionError):
                    m.main([action])


class FailClosedServiceTransitionTests(unittest.TestCase):
    def test_known_failed_socket_allowed_only_with_exact_incident_state(self):
        expected={
            (m.SOCKET,"ActiveState"):"failed",
            (m.SOCKET,"Result"):"service-start-limit-hit",
            (m.EXECUTOR,"ActiveState"):"failed",
            (m.EXECUTOR,"Result"):"exit-code",
        }
        def query(command,**kwargs):
            _,action,unit,_,key,_=command
            assert action=="show"
            return Mock(stdout=expected[(unit,key)]+"\n",returncode=0)
        def unit_state(unit):
            return unit in (m.BROKER,"omnilyzer-analytics-loopback.service")
        with patch.object(m,"active",side_effect=unit_state),patch.object(
            m.subprocess,"run",side_effect=query
        ):
            self.assertIsNone(m.existing_failed_executor_boundary())
        for unit,key in expected:
            bad=dict(expected);bad[(unit,key)]="active"
            def changed(command,**kwargs):
                return Mock(stdout=bad[(command[2],command[4])]+"\n",returncode=0)
            with self.subTest(unit=unit,key=key),patch.object(m,"active",side_effect=unit_state),patch.object(
                m.subprocess,"run",side_effect=changed
            ),self.assertRaises(ValueError):
                m.existing_failed_executor_boundary()

    def test_no_root_certificate_halts_before_any_service_change(self):
        with patch.object(m,"existing_failed_executor_boundary"),patch.object(
            m,"stable_legacy_state",side_effect=ValueError("no root attest")
        ),patch.object(m,"journal") as j,patch.object(m,"systemctl") as systemctl:
            with self.assertRaises(ValueError):
                m.cutover(tuple())
            j.assert_not_called()
            systemctl.assert_not_called()

    def test_successful_source_switch_resets_failed_socket_only_after_attestation(self):
        events=[]
        def syst(*args):
            events.append(("systemctl",)+args)
        def switch(path,new,*,gid,mode):
            events.append(("atomic",str(path),hashlib.sha256(new).hexdigest()))
        def is_active(unit):
            return unit != m.EXECUTOR
        original=((Path("/etc/file1"),b"old1",b"new1",0o640,990),
                  (Path("/etc/file2"),b"old2",b"new2",0o640,991))
        with patch.object(m,"existing_failed_executor_boundary",side_effect=lambda:events.append(("incident",))),patch.object(
            m,"stable_legacy_state",side_effect=lambda:events.append(("attested",))
        ),patch.object(m,"journal",side_effect=lambda x:events.append(("journal",))),patch.object(
            m,"systemctl",side_effect=syst
        ),patch.object(m,"atomic_replace",side_effect=switch),patch.object(
            m,"active",side_effect=is_active
        ),patch.object(m,"verify_service_selection",side_effect=lambda x:events.append(("verified",x))),patch.object(
            m,"write_exclusive",side_effect=lambda *a,**k:events.append(("receipt",))
        ):
            m.cutover(original)
        self.assertLess(events.index(("attested",)),events.index(("journal",)))
        self.assertLess(events.index(("journal",)),events.index(("systemctl","stop",m.BROKER)))
        self.assertLess(events.index(("systemctl","daemon-reload")),events.index(("systemctl","reset-failed",m.EXECUTOR)))
        self.assertLess(events.index(("systemctl","reset-failed",m.SOCKET)),events.index(("systemctl","start",m.SOCKET)))
        self.assertEqual(events[-1],("receipt",))
        self.assertIn(("verified",m.NEW_ROOT),events)

    def test_failed_new_socket_keeps_old_signed_root_and_socket_failclosed(self):
        events=[]
        calls={"new_start_socket":0}
        def syst(*args):
            events.append(("systemctl",)+args)
            if args==("start",m.SOCKET):
                calls["new_start_socket"]+=1
                raise RuntimeError("simulated new socket cannot start")
        original=((Path("/etc/file1"),b"old1",b"new1",0o640,990),
                  (Path("/etc/file2"),b"old2",b"new2",0o640,991))
        def atomic(path,payload,*,gid,mode):
            events.append(("atomic",str(path),payload))
        with patch.object(m,"existing_failed_executor_boundary"),patch.object(
            m,"stable_legacy_state"
        ),patch.object(m,"journal"),patch.object(m,"systemctl",side_effect=syst),patch.object(
            m,"atomic_replace",side_effect=atomic
        ),patch.object(m,"active",side_effect=lambda unit:unit!=m.EXECUTOR),patch.object(
            m,"verify_service_selection",side_effect=lambda x:events.append(("verified",x))
        ),patch.object(m,"write_exclusive",side_effect=lambda *a,**k:events.append(("receipt",))):
            with self.assertRaises(RuntimeError):
                m.cutover(original)
        self.assertEqual(calls["new_start_socket"],1)
        self.assertEqual([x[2] for x in events if x[0]=="atomic" and x[1]=="/etc/file1"],
                         [b"new1",b"old1"])
        self.assertEqual([x[2] for x in events if x[0]=="atomic" and x[1]=="/etc/file2"],
                         [b"new2",b"old2"])
        self.assertEqual(events[-1],("receipt",))
        self.assertIn(("verified",m.OLD_ROOT),events)
        self.assertIn(("systemctl","start",m.BROKER),events)
        self.assertNotIn(("systemctl","reset-failed",m.EXECUTOR,"retry"),events)

    def test_unexpected_user_or_commands_never_mutate(self):
        with patch.object(m.os,"getuid",return_value=1005),patch.object(m,"systemctl") as ctl:
            with self.assertRaises(PermissionError):
                m.main(["--switch"])
            with self.assertRaises(ValueError):
                m.main(["--retry"])
            ctl.assert_not_called()


if __name__=="__main__":
    unittest.main()
