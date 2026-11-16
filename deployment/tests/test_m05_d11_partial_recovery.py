"""Unprivileged checks of diagnosis confinement and missing-tail-only writes."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / 'm05_d11_partial_recovery.py'
spec = importlib.util.spec_from_file_location('d11_recovery', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class D11RecoveryTests(unittest.TestCase):
    def test_wrong_caller_fails_before_any_source_read(self):
        with patch.object(m.os, 'getuid', return_value=1001), \
                patch.object(m.os, 'open') as opened:
            with self.assertRaises(ValueError):
                m.load()
            opened.assert_not_called()

    def test_diagnostic_only_exposes_exit_stdout_and_numeric_statement(self):
        raw = b'File "<string>", line 7\nsynthetic-sensitive-config-and-token'
        expected = b'M05_016_DELIVERY_UID991_SOURCE_BLUE_PASS\n'

        def uid():
            r = subprocess.run(['/usr/bin/setpriv', '--reuid', '991', '-c',
                                'import sys;assert False;print("fixed")'],
                               stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
            m.require(r.returncode == 0 and r.stdout == expected)

        op = SimpleNamespace(uid991_source_preflight=uid)
        with patch.object(m.subprocess, 'run', return_value=
                          subprocess.CompletedProcess([], 1, b'synthetic-stdout-secret', raw)) as run:
            with self.assertRaises(ValueError):
                m.uid991_diagnostic(op)
            self.assertEqual(op._m05_diagnostic_observations,
                             ['EXIT_NONZERO', 'STDOUT_DIFFERS', 'CHILD_STATEMENT_7'])
            self.assertEqual(run.call_args.kwargs['stderr'], subprocess.PIPE)
            self.assertIn('\n', run.call_args.args[0][-1])

    def test_fd_confinement_covers_native_output(self):
        code = ('import importlib.util,os;'
                f's=importlib.util.spec_from_file_location("m",{str(SOURCE)!r});'
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
                'with m.confined():\n'
                ' os.write(1,b"synthetic-native-secret");os.write(2,b"synthetic-error-secret")\n'
                'print("FIXED")')
        r = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', code], capture_output=True)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b'FIXED\n', b''))

    def test_real_child_trace_only_reports_allowlisted_source_index_and_line(self):
        actual_run = subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'owned.py').write_text('raise ValueError("synthetic-protected-child-value")\n')

            def uid():
                r = subprocess.run(['/usr/bin/setpriv', '--reuid', '991', '-c',
                    f'import sys;sys.path.insert(0,{str(root)!r});import owned'],
                    stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
                m.require(r.returncode == 0)

            def delegate(args, **kwargs):
                return actual_run(['/usr/bin/python3', '-I', '-B', '-c', args[-1]], **kwargs)

            op = SimpleNamespace(CANDIDATE=root, uid991_source_preflight=uid)
            with patch.object(m.subprocess, 'run', side_effect=delegate):
                with self.assertRaises(ValueError):
                    m.uid991_diagnostic(op, {'owned.py': 'fixture'})
            self.assertIn('TRACE_FILE_0_LINE_1', op._m05_diagnostic_observations)
            self.assertNotIn('synthetic-protected-child-value', repr(op._m05_diagnostic_observations))

    def test_completion_only_writes_original_marker_and_starts_original_units(self):
        calls = []
        helper = SimpleNamespace(
            write_durable=lambda *args: calls.append(('marker', args)),
            fsync_directory=lambda *args: calls.append(('fsync', args)),
            service_action=lambda *args: calls.append(('service', args)))
        op = SimpleNamespace(BASE=Path('/synthetic'), MARKER=Path('/synthetic/marker'),
            MARKER_BYTES=b'original', RECEIPT=Path('/synthetic/receipt'),
            SOCKET='original.socket', BROKER='original.service',
            postcheck=lambda *args: calls.append(('postcheck', args)))
        prior = SimpleNamespace(admission_closed=lambda *args: calls.append(('closed', args)))
        ctx = SimpleNamespace(op=op, prior=prior, helper=helper, completed=False,
            diagnostic={}, replay='replay', previous=object(), old={}, target={}, configs={}, wanted={})
        with patch.object(m.os, 'statvfs', return_value=SimpleNamespace(
                f_bavail=16, f_frsize=1024*1024, f_favail=1000)):
            m.finish(ctx)
        self.assertEqual([c[0] for c in calls],
                         ['closed', 'marker', 'fsync', 'service', 'service', 'postcheck'])
        self.assertEqual(calls[3][1], ('start', 'original.socket'))
        self.assertEqual(calls[4][1], ('start', 'original.service'))
        ctx.completed = True
        with self.assertRaises(ValueError):
            m.finish(ctx)
        self.assertEqual(len(calls), 6)

    def test_second_finish_consumption_is_rejected_without_overwriting_history(self):
        with tempfile.TemporaryDirectory() as d, \
                patch.object(m, 'RECOVERY_CONSUMED', Path(d) / 'consumed'):
            m.consume()
            before = m.RECOVERY_CONSUMED.read_bytes()
            with self.assertRaises(FileExistsError):
                m.consume()
            self.assertEqual(m.RECOVERY_CONSUMED.read_bytes(), before)

    def test_independent_matrix_continues_after_receipt_failure(self):
        attempted = []
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            op = SimpleNamespace(RECEIPT=root/'absent', STAGE=root/'stage',
                CANDIDATE=root/'candidate', BACKUP=root/'backup', ROUTE=root,
                MARKER=root/'marker', BLUE='blue', BROKER='broker', SOCKET='socket', EXECUTOR='executor',
                verify_tree=lambda *args: attempted.append('source'),
                uid991_source_preflight=lambda: attempted.append('uid'),
                sha=lambda raw: 'digest')
            helper = SimpleNamespace(
                service_state=lambda unit: 'active' if unit == 'blue' else 'failed' if unit == 'executor' else 'inactive',
                healthy=lambda: attempted.append('health'))
            prior = SimpleNamespace(pinned=lambda *args: None)
            ctx = SimpleNamespace(op=op, prior=prior, helper=helper, old={}, target={},
                diagnostic={'active_state_stable': lambda: attempted.append('active')})
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertFalse(m.inspect(ctx, diagnose=False))
            self.assertIn('CONFIG_LIVE=BLOCKED', out.getvalue())
            self.assertIn('UID991_EXACT=PASS', out.getvalue())
            self.assertEqual(attempted, ['source', 'source', 'health', 'active', 'uid'])


if __name__ == '__main__':
    unittest.main()
