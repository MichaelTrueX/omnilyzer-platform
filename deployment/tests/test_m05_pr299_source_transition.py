"""Unprivileged source-transition checks; no DEV state or sudo execution."""
import hashlib
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / 'm05_pr299_source_transition.py'
spec = importlib.util.spec_from_file_location('pr299_transition', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def canonical(model):
    return (json.dumps(model, sort_keys=True, separators=(',', ':')) + '\n').encode()


class PR299SourceTransitionTests(unittest.TestCase):
    def test_wrong_caller_cannot_read_or_write_root_state(self):
        with patch.object(m.os, 'getuid', return_value=1001), patch.object(m.os, 'open') as opened:
            with self.assertRaises(ValueError):
                m.load()
            opened.assert_not_called()

    def test_fix_payload_matches_exact_reviewed_source(self):
        path = SOURCE.parent / 'analytics_active_state_review.py'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), m.FIX_SHA)
        self.assertNotEqual(m.FIX_SHA, m.OLD_SHA)
        self.assertNotEqual(m.NEW_MAIN, m.OLD_MAIN)

    def test_opened_descriptor_custody_must_match_named_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'code.py';path.write_bytes(b'fixture');path.chmod(0o400)
            values = list(path.lstat());values[4] = values[5] = 0
            before = os.stat_result(values)
            values[4] = values[5] = 991
            opened = os.stat_result(values)
            with patch.object(Path, 'lstat', return_value=before), \
                    patch.object(m.os, 'fstat', return_value=opened), \
                    patch.object(m.os, 'fdopen') as reader:
                with self.assertRaises(ValueError):
                    m.pinned(path, 0o400, hashlib.sha256(b'fixture').hexdigest())
                reader.assert_not_called()

    def test_bootstrap_pins_payloads_and_only_two_exact_commands(self):
        owner = SOURCE.parent / 'm05_pr299_access_owner_once.py'
        tree = ast.parse(owner.read_text())
        script = next(n.value.value for n in tree.body if isinstance(n, ast.Assign)
                      and any(isinstance(v, ast.Name) and v.id == 'ROOT_COMMAND' for v in n.targets))
        self.assertIn(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), script)
        self.assertIn(m.FIX_SHA, script)
        self.assertIn('--inspect, sha256:%s %s --apply-once', script)
        self.assertNotIn('NOPASSWD: ALL', script)
        result = subprocess.run(['/bin/bash', '-n'], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_config_delta_changes_only_authority_and_one_existing_hash(self):
        paths = tuple((Path('/synthetic/config' + str(i)), 990 if i < 3 else 991)
                      for i in range(1, 4))
        model = {'reviewed_installed_commit': m.OLD_MAIN, 'expected_workflow_sha': m.OLD_MAIN,
                 'schema_version': 3, 'owner_authorized_first_successor': True,
                 'source_sha256': {m.REL: m.OLD_SHA,
                    **{'unchanged' + str(i): 'a' * 64 for i in range(25)}},
                 'profile': 'unchanged-private-profile'}
        issuer = {'expected_workflow_sha': m.OLD_MAIN, 'issuer': 'unchanged-issuer'}
        before = {paths[0][0]: canonical(issuer), paths[1][0]: canonical(model),
                  paths[2][0]: canonical(model)}

        def record(ctx):
            ctx.wanted = before
            ctx.replay = 'r' * 64

        ctx = SimpleNamespace(
            op=SimpleNamespace(RECEIPT=Path('/synthetic/old'), unique=lambda p: dict(p),
                               canonical=canonical, sha=lambda b: hashlib.sha256(b).hexdigest()),
            prior=SimpleNamespace(CONFIG_PATHS=paths, _bounded_read_only=lambda *a: b'old-receipt'),
            helper=object(), oldest={}, old={}, legacy=SimpleNamespace(record=record))
        m.configs(ctx)
        changed_issuer = json.loads(ctx.wanted[paths[0][0]])
        changed = json.loads(ctx.wanted[paths[1][0]])
        self.assertEqual(changed_issuer, {**issuer, 'expected_workflow_sha': m.NEW_MAIN})
        self.assertEqual(changed, {**model, 'reviewed_installed_commit': m.NEW_MAIN,
            'expected_workflow_sha': m.NEW_MAIN,
            'source_sha256': {**model['source_sha256'], m.REL: m.FIX_SHA}})
        self.assertEqual(ctx.wanted[paths[1][0]], ctx.wanted[paths[2][0]])
        self.assertEqual(ctx.before, before)

    def test_consumption_is_durable_exclusive_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'CONSUMED', Path(directory)/'consumed'):
            synced = []
            ctx = SimpleNamespace(helper=SimpleNamespace(fsync_directory=lambda p: synced.append(p)))
            m.consume(ctx)
            raw = m.CONSUMED.read_bytes()
            with self.assertRaises(FileExistsError):
                m.consume(ctx)
            self.assertEqual(m.CONSUMED.read_bytes(), raw)
            self.assertEqual(synced, [Path(directory)])

    def test_uid991_prewrite_is_pinned_review_and_postwrite_uses_installed_module(self):
        ctx = SimpleNamespace(op=SimpleNamespace(CANDIDATE=Path('/synthetic/candidate')))
        response = b'M05_PR299_UID991_BLUE_PASS\nM05_PR299_RAW_PORT_ORDER_EQUAL\n'
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, response)) as run:
            m.uid991(ctx, installed=False)
            before = run.call_args
            self.assertIn(m.FIX_SHA, before.args[0][-1])
            self.assertIn(m.OLD_MAIN, before.args[0][-1])
            self.assertIn('spec.loader.exec_module(active)', before.args[0][-1])
            self.assertEqual(before.kwargs['timeout'], 45)
            self.assertEqual(before.kwargs['stderr'], subprocess.DEVNULL)
            m.uid991(ctx, installed=True)
            after = run.call_args
            self.assertIn(m.NEW_MAIN, after.args[0][-1])
            self.assertIn('from deployment import analytics_active_state_review as active', after.args[0][-1])
            self.assertNotIn('spec.loader.exec_module(active)', after.args[0][-1])
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'synthetic-secret')):
            with self.assertRaises(ValueError):
                m.uid991(ctx, installed=True)

    def test_tree_scope_does_not_rebind_any_frozen_helper_globals(self):
        op = SimpleNamespace(CANDIDATE=Path('/synthetic/candidate'), STAGE=Path('/synthetic/stage'),
                             BACKUP=Path('/synthetic/old-backup'))
        ctx = SimpleNamespace(op=op)
        with self.assertRaises(ValueError):
            m.verify_tree(ctx, Path('/unapproved'), {'x'+str(i): 'a'*64 for i in range(76)})
        self.assertEqual(op.BACKUP, Path('/synthetic/old-backup'))

    def test_failed_prewrite_matrix_never_imports_installer_or_exchanges_source(self):
        ctx = SimpleNamespace(completed=False, op=object(), prior=object(), helper=object())
        with patch.object(m.os.path, 'lexists', return_value=False), \
                patch.object(m.os, 'statvfs', return_value=SimpleNamespace(
                    f_bavail=16, f_frsize=1024*1024, f_favail=1000)), \
                patch.object(m, 'consume') as consumed, patch.object(m, 'inspect', return_value=False):
            with self.assertRaises(ValueError):
                m.apply(ctx)
            consumed.assert_called_once_with(ctx)

    def test_post_exchange_config_failure_preserves_sources_receipt_and_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, stage, backup = root/'candidate', root/'stage', root/'backup'
            candidate.mkdir()
            receipt, consumed, marker = root/'receipt', root/'consumed', root/'receipt'/'marker'
            names = [m.REL] + ['deployment/fixture'+str(i)+'.py' for i in range(75)]
            raw = b'old verified fixture'
            old = {name: hashlib.sha256(raw).hexdigest() for name in names}
            for name in names:
                path = candidate/name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(raw)
            fixed = b'new reviewed fixture'
            target = {**old, m.REL: hashlib.sha256(fixed).hexdigest()}
            paths = tuple((root/('config'+str(i)), 990) for i in range(3))
            before = {path: b'unchanged-before' for path, _ in paths}
            starts = []
            temporary = root/'imported-installer';temporary.mkdir()

            def stage_sources(fd, selected, **kwargs):
                stage.mkdir()
                for name, data in selected:
                    path = stage/name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(data)

            def exchange(a, b):
                swap = root/'swap';os.rename(a, swap);os.rename(b, a);os.rename(swap, b)

            def write(path, data, *args):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:stream.write(data)

            def verify(ctx, path, expected):
                actual = {p.relative_to(path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in path.rglob('*') if p.is_file()}
                self.assertEqual(actual, expected)

            installer = SimpleNamespace(_open_checked_root=lambda *args: 123,
                _stage_new_generation=stage_sources,
                _original=SimpleNamespace(_finish_close=lambda holder: None))
            helper = SimpleNamespace(import_pinned_source_installer=lambda: (installer, temporary),
                write_durable=write, fsync_directory=lambda *args: None,
                read_config=lambda path, gid: before[path], exchange_directory=exchange,
                atomic_config=lambda *args: (_ for _ in ()).throw(OSError('synthetic-write-failure')),
                service_action=lambda *args: starts.append(args))
            prior = SimpleNamespace(CONFIG_PATHS=paths, admission_closed=lambda *args: None,
                                    pinned=lambda path, uid, gid, mode, size, sha: path.read_bytes())
            op = SimpleNamespace(CANDIDATE=candidate, STAGE=stage, sha=lambda r: hashlib.sha256(r).hexdigest(),
                                 canonical=canonical)
            ctx = SimpleNamespace(op=op, prior=prior, helper=helper, completed=False,
                diagnostic={}, replay='r'*64, old=old, target=target, fixed=fixed,
                before=before, wanted={p: b'after' for p, _ in paths})
            with patch.multiple(m, BASE=root, BACKUP=backup, RECEIPT=receipt, CONSUMED=consumed, MARKER=marker), \
                    patch.object(m, 'inspect', return_value=True), patch.object(m, 'verify_tree', side_effect=verify), \
                    patch.object(m, 'receipt_model', return_value={'fixture': True}):
                with self.assertRaises(OSError):m.apply(ctx)
                self.assertTrue(consumed.exists())
                self.assertTrue((receipt/'receipt.json').exists())
                self.assertEqual((candidate/m.REL).read_bytes(), fixed)
                self.assertEqual((backup/m.REL).read_bytes(), raw)
                self.assertFalse(marker.exists())
                self.assertEqual(starts, [])
                self.assertFalse(temporary.exists())
                with self.assertRaises(ValueError):m.apply(ctx)


if __name__ == '__main__':
    unittest.main()
