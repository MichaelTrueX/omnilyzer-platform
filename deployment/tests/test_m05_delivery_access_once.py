"""Unprivileged tests of the exact one-use root capability and bootstrap."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class DeliveryAccessTests(unittest.TestCase):
    def test_installed_source_hash_and_bootstrap_pins_match_actual_files(self):
        access = load('m05_d11_delivery_access_once')
        owner = load('m05_delivery_access_owner_once')
        source = ROOT / 'm05_pr296_d11_delivery_20261116_source_only.py'
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), access.SOURCE_SHA)
        for file in (source, ROOT / 'm05_d11_delivery_access_once.py'):
            self.assertIn(hashlib.sha256(file.read_bytes()).hexdigest(), owner.ROOT_COMMAND)
        r = subprocess.run(['/bin/bash', '-n'], input=owner.ROOT_COMMAND,
                           text=True, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('sha256:%s %s ""', owner.ROOT_COMMAND)
        self.assertNotIn('NOPASSWD: ALL', owner.ROOT_COMMAND)

    def test_wrong_caller_and_extra_arguments_never_run_operator(self):
        m = load('m05_d11_delivery_access_once')
        with patch.object(m.os, 'getuid', return_value=1001), \
                patch.object(m.subprocess, 'run') as run:
            self.assertEqual(m.main(), 2)
            run.assert_not_called()
        with patch.object(m.sys, 'argv', [str(m.SELF), 'status']), \
                patch.object(m.subprocess, 'run') as run:
            self.assertEqual(m.main(), 2)
            run.assert_not_called()

    def test_owner_wrong_arguments_do_not_create_log_or_start_ssh(self):
        m = load('m05_delivery_access_owner_once')
        with patch.object(m.sys, 'argv', ['helper', 'wrong']), \
                patch.object(m.os, 'open') as opened, \
                patch.object(m.subprocess, 'Popen') as child:
            self.assertEqual(m.main(), 2)
            opened.assert_not_called()
            child.assert_not_called()

    def test_failure_consumes_capability_and_second_call_cannot_start_child(self):
        m = load('m05_d11_delivery_access_once')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'operator.py'
            source.write_bytes(b'not executed: synthetic exact source')
            source.chmod(0o400)
            selfpath = root / 'access'
            selfpath.write_bytes(b'synthetic wrapper')
            selfpath.chmod(0o750)
            consumed = root / 'consumed'
            original_stat = Path.lstat

            def stat_root(path):
                # Test fixture changes ownership metadata only; no production
                # parameter accepts alternate UID, source or operation.
                st = original_stat(path)
                class RootStat:
                    st_uid = st_gid = 0
                    st_mode = st.st_mode
                return RootStat()

            # Source reads use real fstat identity; only directory checks and
            # regular() owner checks need synthetic root metadata here.
            real_mkdtemp = tempfile.mkdtemp
            with patch.multiple(m, SELF=selfpath, SOURCE=source, CONSUMED=consumed,
                                SOURCE_SHA=hashlib.sha256(source.read_bytes()).hexdigest(),
                                __file__=str(selfpath)), \
                    patch.object(m.sys, 'argv', [str(selfpath)]), \
                    patch.multiple(m.os, getuid=lambda: 0, geteuid=lambda: 0,
                                   getgid=lambda: 0, getegid=lambda: 0), \
                    patch.object(m.socket, 'gethostname', return_value='omnilyzerdev'), \
                    patch.object(m, 'regular', side_effect=lambda p, mode: original_stat(p)), \
                    patch.object(Path, 'lstat', stat_root), \
                    patch.object(m.tempfile, 'mkdtemp',
                                 side_effect=lambda **kw: real_mkdtemp(prefix=kw['prefix'], dir=root)), \
                    patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as run:
                self.assertEqual(m.main(), 1)
                self.assertTrue(consumed.exists())
                self.assertEqual(run.call_count, 1)
                self.assertEqual(m.main(), 2)
                self.assertEqual(run.call_count, 1)
            self.assertEqual(list(root.glob('m05-analytics016-d11-delivery-launch.*')), [])


if __name__ == '__main__':
    unittest.main()
