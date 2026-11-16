"""Focused safety checks for the new read-only component matrix only."""
import ast
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / 'm05_prior766_component_readonly.py'
spec = importlib.util.spec_from_file_location('component_matrix', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ComponentMatrixTests(unittest.TestCase):
    def test_wrong_caller_denied_before_source_import(self):
        with patch.object(module.os, 'getuid', return_value=1005):
            with self.assertRaises(ValueError):
                module.load_source()

    def test_fd_confinement_includes_native_and_child_output(self):
        code = (
            'import importlib.util,os,subprocess;'
            f's=importlib.util.spec_from_file_location("m",{str(SOURCE)!r});'
            'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
            '\nwith m.confined():\n'
            ' os.write(1,b"synthetic-secret-one");os.write(2,b"synthetic-secret-two");'
            'subprocess.run(["/bin/echo","synthetic-child-secret"],check=True)\n'
            'print("FIXED")'
        )
        r = subprocess.run([sys.executable, '-I', '-B', '-c', code], capture_output=True)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b'FIXED\n', b''))

    def test_failed_group_does_not_stop_independent_groups(self):
        statements = ast.parse('raise ValueError("synthetic-secret")\nx=1\n').body
        final = ast.parse('require(True and False)').body[0]
        fn = type('Function', (), {'body': statements + [final] * 27})()
        ns = {'require': module.require}
        output = io.StringIO()
        with patch.object(module, 'GROUPS', (
            ('FIRST', 0, 1, ()), ('SECOND', 1, 2, ()),
            ('DEPENDENT', 1, 2, ('FIRST',)),
        )), contextlib.redirect_stdout(output):
            self.assertEqual(module.run_matrix(ns, fn), 2)
        text = output.getvalue()
        self.assertIn('FIRST=HOLD', text)
        self.assertIn('SECOND=PASS', text)
        self.assertIn('DEPENDENT=BLOCKED', text)
        self.assertIn('ROUTE_EMPTY=HOLD', text)
        self.assertNotIn('synthetic-secret', text)

    def test_matrix_cannot_call_install_composites(self):
        tree = ast.parse(SOURCE.read_text())
        calls = [n.func.attr for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertFalse(set(calls) & {
            'apply_once', 'post_install_readonly', 'root_preflight',
            'attest_prior_766_readonly', 'write_durable', 'service_action',
        })
        covered = [i for _, begin, end, _ in module.GROUPS for i in range(begin, end)]
        self.assertEqual(covered, list(range(1, 28)))


if __name__ == '__main__':
    unittest.main()
