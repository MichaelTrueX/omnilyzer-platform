"""Deterministic C32G contracts; fake processes do not prove cryptography."""

from contextlib import ExitStack
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from deployment import blob_verifier as bv
from deployment.policy import EXPECTED_CERTIFICATE_IDENTITY, EXPECTED_CERTIFICATE_ISSUER
from deployment.tests.test_promotion import sigstore_result


INPUT = (b'{"exact": "manifest"}\n', b'{"exact": "provenance"}\n', b'manifest-bundle', b'provenance-bundle')
AUTHORITY = dict(expected_cosign_version='3.1.2', expected_binary_sha256='a' * 64,
                 expected_trusted_root_sha256='b' * 64, broker_uid=1234, broker_gid=1235)


class Runner:
    def __init__(self, results=None):
        self.calls = []
        self.results = results or [bv._ProcessResult(0, 0, 0)] * 2

    def run(self, argv, blob, *, executable, descriptors, home):
        bundle = int(argv[3].rsplit('/', 1)[1])
        root = int(argv[5].rsplit('/', 1)[1])
        binary = int(executable.rsplit('/', 1)[1])
        # The same sealed bytes survive attempted writes and have no disk name.
        for fd in (bundle, root, binary):
            with unittest.TestCase().assertRaises(OSError):
                os.pwrite(fd, b'alter', 0)
            self.assert_sealed(fd)
        self.calls.append((argv, blob, bv._read(bundle, os.fstat(bundle).st_size),
                           bv._read(root, os.fstat(root).st_size), home, descriptors))
        result = self.results[len(self.calls) - 1]
        if isinstance(result, BaseException):
            raise result
        return result

    @staticmethod
    def assert_sealed(fd):
        assert stat.S_ISREG(os.fstat(fd).st_mode)
        assert os.fstat(fd).st_nlink == 0
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE


class VerifierTests(unittest.TestCase):
    def sandbox(self, runner):
        stack = ExitStack()
        self.addCleanup(stack.close)
        workspace = stack.enter_context(tempfile.TemporaryDirectory())
        runtime = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, runtime)

        def snapshot(path, digest, maximum, owned, *, executable):
            self.assertIn((path, digest, maximum, executable), (
                (bv.COSIGN_PATH, 'a' * 64, bv.MAX_BINARY_BYTES, True),
                (bv.TRUSTED_ROOT_PATH, 'b' * 64, bv.MAX_ROOT_BYTES, False)))
            return bv._sealed(b'binary' if executable else b'reviewed-root', owned, executable=executable)

        stack.enter_context(patch.object(bv, '_snapshot', side_effect=snapshot))
        stack.enter_context(patch.object(bv, '_directory', return_value=runtime))
        from types import SimpleNamespace
        original_stat, original_fstat = os.stat, os.fstat
        def broker_status(value):
            names = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_size',
                     'st_mtime', 'st_mtime_ns', 'st_ctime_ns')
            return SimpleNamespace(**{name: getattr(value, name) for name in names},
                                   st_uid=1234, st_gid=1235)
        stack.enter_context(patch.object(bv.os, 'stat', side_effect=lambda *a, **kw: broker_status(original_stat(*a, **kw))))
        stack.enter_context(patch.object(bv.os, 'fstat', side_effect=lambda *a: broker_status(original_fstat(*a))))
        for name, value in (('getuid', 1234), ('geteuid', 1234), ('getgid', 1235), ('getegid', 1235)):
            stack.enter_context(patch.object(bv.os, name, return_value=value))
        return bv.CosignReleaseBlobVerifier(**AUTHORITY, runner=runner), workspace

    def test_exact_fixed_invocations_and_bytes_and_cleanup(self):
        runner = Runner()
        verifier, workspace = self.sandbox(runner)
        self.assertEqual(verifier.verify(*INPUT), sigstore_result())
        self.assertEqual(len(runner.calls), 2)
        for index, (argv, blob, bundle, root, home, descriptors) in enumerate(runner.calls):
            self.assertEqual(argv[:3], (bv.COSIGN_PATH, 'verify-blob', '--bundle'))
            self.assertEqual(argv[4], '--trusted-root')
            self.assertEqual(argv[6:], ('--certificate-identity', EXPECTED_CERTIFICATE_IDENTITY,
                                      '--certificate-oidc-issuer', EXPECTED_CERTIFICATE_ISSUER, '-'))
            self.assertEqual(blob, INPUT[index])
            self.assertEqual(bundle, INPUT[index + 2])
            self.assertEqual(root, b'reviewed-root')
            self.assertEqual(stat.S_IMODE(os.stat(workspace).st_mode), 0o700)
            self.assertFalse(os.path.exists(home))
            for fd in descriptors[:3]:
                with self.assertRaises(OSError):
                    os.fstat(fd)
        self.assertEqual(list(Path(workspace).iterdir()), [])

    def test_required_authority_and_no_paths(self):
        for name in AUTHORITY:
            args = AUTHORITY.copy()
            del args[name]
            with self.subTest(name=name), self.assertRaises(TypeError):
                bv.CosignReleaseBlobVerifier(**args)
        for name in ('executable', 'executable_path', 'trusted_root', 'trusted_root_path',
                     'certificate_identity', 'issuer'):
            with self.subTest(name=name), self.assertRaises(TypeError):
                bv.CosignReleaseBlobVerifier(**AUTHORITY, **{name: '/caller/path'})
        cases = {
            'expected_cosign_version': ('3.1.1', 'latest', None, True),
            'expected_binary_sha256': (None, '', '0' * 64, 'A' * 64, True),
            'expected_trusted_root_sha256': (None, '', '0' * 64, 'A' * 64, True),
            'broker_uid': (0, True, -1), 'broker_gid': (0, True, -1),
        }
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value=value), self.assertRaises(bv.BlobVerificationError):
                    bv.CosignReleaseBlobVerifier(**(AUTHORITY | {name: value}))

    def test_no_supported_replacement_or_deletion_and_bound_runner(self):
        runner = Runner()
        verifier, _ = self.sandbox(runner)
        for name in verifier.__slots__ + ('certificate_identity', 'issuer', 'executable', 'trusted_root'):
            with self.assertRaises(AttributeError):
                setattr(verifier, name, None)
            with self.assertRaises(AttributeError):
                delattr(verifier, name)
        runner.run = lambda *a, **kw: self.fail('replacement runner used')
        self.assertEqual(verifier.verify(*INPUT), sigstore_result())
        accessed = []
        class PropertyRunner:
            @property
            def run(self):
                accessed.append(True)
                raise AssertionError('property evaluated')
        with self.assertRaises(bv.BlobVerificationError):
            bv.CosignReleaseBlobVerifier(**AUTHORITY, runner=PropertyRunner())
        self.assertEqual(accessed, [])

    def test_every_input_validated_before_io(self):
        verifier = bv.CosignReleaseBlobVerifier(**AUTHORITY, runner=Runner())
        for index in range(4):
            for raw in (None, '', bytearray(b'x'), b'', b'x' * (bv.MAX_EVIDENCE_BYTES + 1)):
                inputs = list(INPUT)
                inputs[index] = raw
                with self.subTest(index=index, kind=type(raw)), patch.object(bv, '_snapshot') as io:
                    with self.assertRaises(bv.BlobVerificationError):
                        verifier.verify(*inputs)
                    io.assert_not_called()

    def test_manifest_and_provenance_failures_no_partial_result(self):
        bad = (bv._ProcessResult(1, 0, 0), TimeoutError('private path'),
               FileNotFoundError('private path'), RuntimeError('bundle text'), None,
               {'returncode': 0}, bv._ProcessResult(True, 0, 0),
               bv._ProcessResult(0, True, 0), bv._ProcessResult(0, -1, 0),
               bv._ProcessResult(0, bv.MAX_OUTPUT_BYTES + 1, 0),
               bv._ProcessResult(0, 0, bv.MAX_OUTPUT_BYTES + 1))
        for index in range(2):
            for result in bad:
                results = [bv._ProcessResult(0, 0, 0)] * 2
                results[index] = result
                runner = Runner(results)
                verifier, workspace = self.sandbox(runner)
                with self.subTest(index=index, result=result), self.assertRaises(bv.BlobVerificationError) as raised:
                    verifier.verify(*INPUT)
                self.assertEqual(str(raised.exception), bv.ERROR)
                self.assertIsNone(raised.exception.__cause__)
                self.assertEqual(len(runner.calls), index + 1)
                self.assertEqual(list(Path(workspace).iterdir()), [])

    def test_cleanup_failure_rejected_and_control_exceptions_preserved(self):
        verifier, _ = self.sandbox(Runner())
        original = bv.shutil.rmtree
        def failing_cleanup(path):
            original(path)
            raise OSError('private cleanup information')
        with patch.object(bv.shutil, 'rmtree', side_effect=failing_cleanup):
            # Mock retains the standard-library safety marker deliberately.
            bv.shutil.rmtree.avoids_symlink_attacks = True
            with self.assertRaises(bv.BlobVerificationError):
                verifier.verify(*INPUT)
        runner = Runner([KeyboardInterrupt()])
        verifier, workspace = self.sandbox(runner)
        with self.assertRaises(KeyboardInterrupt):
            verifier.verify(*INPUT)
        self.assertEqual(list(Path(workspace).iterdir()), [])

    def test_unlink_and_descriptor_cleanup_failure_rejected(self):
        for kind in ('unlink', 'close'):
            verifier, workspace = self.sandbox(Runner())
            original = getattr(bv.os, kind)
            calls = []
            def failing_once(*args, **kwargs):
                result = original(*args, **kwargs)
                if not calls:
                    calls.append(True)
                    raise OSError('private cleanup failure')
                return result
            with self.subTest(kind=kind), patch.object(bv.os, kind, side_effect=failing_once):
                with self.assertRaises(bv.BlobVerificationError):
                    verifier.verify(*INPUT)
            # A failed directory-fd close can leave an empty private request
            # directory; no result is trusted and no bundle bytes persist.
            for child in Path(workspace).iterdir():
                self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)
                self.assertEqual(list(child.iterdir()), [])

    def test_policy_identity_is_captured(self):
        verifier, _ = self.sandbox(Runner())
        with patch.object(bv, 'EXPECTED_CERTIFICATE_IDENTITY', 'caller-selected'), \
             patch.object(bv, 'EXPECTED_CERTIFICATE_ISSUER', 'caller-selected'):
            self.assertEqual(verifier.verify(*INPUT), sigstore_result())

    def test_bundle_symlink_and_hardlink_substitution_rejected(self):
        original = bv.tempfile.mkstemp
        for kind in ('symlink', 'hardlink'):
            verifier, workspace = self.sandbox(Runner())
            def substituted(*a, **kw):
                fd, path = original(*a, **kw)
                replacement = path + '-other'
                if kind == 'symlink':
                    os.unlink(path)
                    Path(replacement).write_bytes(b'other')
                    os.symlink(replacement, path)
                else:
                    os.link(path, replacement)
                return fd, path
            with self.subTest(kind=kind), patch.object(bv.tempfile, 'mkstemp', side_effect=substituted):
                with self.assertRaises(bv.BlobVerificationError):
                    verifier.verify(*INPUT)
            self.assertEqual(list(Path(workspace).iterdir()), [])

    def test_staging_directory_symlink_substitution_rejected(self):
        runner = Runner()
        verifier, workspace = self.sandbox(runner)
        original = bv.tempfile.mkdtemp
        def substitute(*a, **kw):
            path = original(*a, **kw)
            os.rmdir(path)
            target = Path(workspace) / 'substitute-target'
            target.mkdir(mode=0o700)
            os.symlink(target, path)
            return path
        with patch.object(bv.tempfile, 'mkdtemp', side_effect=substitute):
            with self.assertRaises(bv.BlobVerificationError):
                verifier.verify(*INPUT)
        self.assertEqual(runner.calls, [])
        self.assertFalse(any(Path(workspace).rglob('bundle-*')))

    def test_no_host_io_at_construction_or_missing_installation(self):
        with patch.object(bv.os, 'open') as opened:
            verifier = bv.CosignReleaseBlobVerifier(**AUTHORITY)
            opened.assert_not_called()
        with self.assertRaises(bv.BlobVerificationError):
            verifier.verify(*INPUT)

    def test_production_runner_uses_sealed_executable_and_exact_two_blobs(self):
        verifier, workspace = self.sandbox(bv._CosignProcess())
        script = ("#!" + sys.executable + "\n" + """import sys
assert sys.argv[1] == 'verify-blob'
assert sys.argv[2] == '--bundle' and sys.argv[4] == '--trusted-root'
assert sys.argv[6] == '--certificate-identity' and sys.argv[8] == '--certificate-oidc-issuer'
assert len(sys.argv) == 11 and sys.argv[10] == '-'
blob = sys.stdin.buffer.read()
expected = {""" + repr(INPUT[0]) + ': ' + repr(INPUT[2]) + ', ' + repr(INPUT[1]) + ': ' + repr(INPUT[3]) + """}
assert open(sys.argv[3], 'rb').read() == expected[blob]
assert open(sys.argv[5], 'rb').read() == b'reviewed-root'
""").encode()
        def snapshot(path, digest, maximum, owned, *, executable):
            return bv._sealed(script if executable else b'reviewed-root', owned, executable=executable)
        with patch.object(bv, '_snapshot', side_effect=snapshot):
            self.assertEqual(verifier.verify(*INPUT), sigstore_result())
        self.assertEqual(list(Path(workspace).iterdir()), [])


class SnapshotTests(unittest.TestCase):
    def test_fixed_ancestor_validation_rejects_shared_tmp_and_symlink(self):
        owned = []
        try:
            with self.assertRaises(OSError):
                bv._directory('/tmp', owned)
        finally:
            for fd in owned:
                os.close(fd)
        # Real /proc/self traversal includes a symlink and must not be authority.
        owned = []
        try:
            with self.assertRaises(OSError):
                bv._directory('/proc/self', owned)
        finally:
            for fd in owned:
                os.close(fd)

    def test_digest_root_ownership_permissions_links_and_exact_snapshot(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'authority'
            path.write_bytes(b'reviewed authority')
            path.chmod(0o500)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            original_stat, original_fstat = os.stat, os.fstat
            def root_status(value, *, uid=0):
                fields = {name: getattr(value, name) for name in (
                    'st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_gid', 'st_size',
                    'st_mtime', 'st_mtime_ns', 'st_ctime_ns')}
                return SimpleNamespace(**fields, st_uid=uid)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(bv, '_directory', return_value=directory_fd), \
                     patch.object(bv.os, 'stat', side_effect=lambda *a, **kw: root_status(original_stat(*a, **kw))), \
                     patch.object(bv.os, 'fstat', side_effect=lambda *a: root_status(original_fstat(*a))):
                    for kind in ('success', 'digest', 'mode', 'hardlink', 'symlink', 'size'):
                        owned = []
                        try:
                            path.unlink()
                            path.write_bytes(b'reviewed authority')
                            path.chmod(0o500)
                            if kind == 'mode':
                                path.chmod(0o522)
                            if kind == 'hardlink':
                                os.link(path, str(path) + '-link')
                            if kind == 'symlink':
                                path.unlink()
                                os.symlink(str(path) + '-link', path)
                            with self.subTest(kind=kind):
                                if kind == 'success':
                                    fd = bv._snapshot(str(path), digest, 100, owned, executable=True)
                                    path.chmod(0o700)
                                    path.write_bytes(b'changed after qualification')
                                    self.assertEqual(bv._read(fd, len(b'reviewed authority')), b'reviewed authority')
                                    with self.assertRaises(OSError):
                                        os.pwrite(fd, b'x', 0)
                                else:
                                    with self.assertRaises(OSError):
                                        bv._snapshot(str(path), 'a' * 64 if kind == 'digest' else digest,
                                                     1 if kind == 'size' else 100, owned, executable=True)
                        finally:
                            for fd in owned:
                                os.close(fd)
                path.unlink()
                path.write_bytes(b'reviewed authority')
                path.chmod(0o500)
                owned = []
                try:
                    with patch.object(bv, '_directory', return_value=directory_fd), \
                         patch.object(bv.os, 'stat', side_effect=lambda *a, **kw: root_status(original_stat(*a, **kw), uid=1234)), \
                         patch.object(bv.os, 'fstat', side_effect=lambda *a: root_status(original_fstat(*a), uid=1234)), \
                         self.assertRaises(OSError):
                        bv._snapshot(str(path), digest, 100, owned, executable=True)
                finally:
                    for fd in owned:
                        os.close(fd)
            finally:
                os.close(directory_fd)


class BrokerTrustedRootTests(unittest.TestCase):
    def test_root_requires_exact_root_broker_0750_0640_authority(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'root.json'
            path.write_bytes(b'reviewed root')
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, directory_fd)
            original_stat, original_fstat = os.stat, os.fstat
            for kind in ('success', 'file_mode', 'file_group', 'file_owner',
                         'directory_mode', 'directory_group', 'directory_owner'):
                def authority_status(value):
                    is_directory = stat.S_ISDIR(value.st_mode)
                    fields = {name: getattr(value, name) for name in (
                        'st_ino', 'st_dev', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                    prefix = 'directory' if is_directory else 'file'
                    mode = 0o750 if is_directory else 0o640
                    if kind == prefix + '_mode':
                        mode = 0o755 if is_directory else 0o644
                    fields.update(st_mode=(stat.S_IFDIR if is_directory else stat.S_IFREG) | mode,
                                  st_uid=1234 if kind == prefix + '_owner' else 0,
                                  st_gid=2002 if kind == prefix + '_group' else 1235)
                    return SimpleNamespace(**fields)
                owned = []
                try:
                    with self.subTest(kind=kind), patch.object(bv, '_directory', return_value=directory_fd), \
                         patch.object(bv.os, 'getegid', return_value=1235), \
                         patch.object(bv.os, 'stat', side_effect=lambda *a, **kw: authority_status(original_stat(*a, **kw))), \
                         patch.object(bv.os, 'fstat', side_effect=lambda *a: authority_status(original_fstat(*a))):
                        digest = hashlib.sha256(b'reviewed root').hexdigest()
                        if kind == 'success':
                            descriptor = bv._snapshot(str(path), digest, 100, owned, executable=False)
                            self.assertEqual(bv._read(descriptor, len(b'reviewed root')), b'reviewed root')
                        else:
                            with self.assertRaises(OSError):
                                bv._snapshot(str(path), digest, 100, owned, executable=False)
                finally:
                    for descriptor in owned:
                        os.close(descriptor)


class ProcessTests(unittest.TestCase):
    def fake(self, body):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'fake-cosign'
        path.write_text('#!' + sys.executable + '\n' + body)
        path.chmod(0o700)
        return str(path), directory.name

    def run_fake(self, body, blob=b'exact\x00blob\n', tail=()):
        path, home = self.fake(body)
        return bv._CosignProcess().run((bv.COSIGN_PATH, *tail), blob,
                                      executable=path, descriptors=(), home=home)

    def test_real_process_argv_stdin_bundle_root_environment(self):
        owned = []
        self.addCleanup(lambda: [os.close(fd) for fd in owned])
        bundle = bv._sealed(b'exact-bundle', owned)
        root = bv._sealed(b'exact-root', owned)
        path, home = self.fake('''import os, sys
assert sys.argv[1:] == ['verify-blob', '--bundle', sys.argv[3], '--trusted-root', sys.argv[5], '--certificate-identity', sys.argv[7], '--certificate-oidc-issuer', sys.argv[9], '-']
assert sys.argv[7] == ''' + repr(EXPECTED_CERTIFICATE_IDENTITY) + '''
assert sys.argv[9] == ''' + repr(EXPECTED_CERTIFICATE_ISSUER) + '''
assert sys.stdin.buffer.read() == b'exact\\x00blob\\n'
assert open(sys.argv[3], 'rb').read() == b'exact-bundle'
assert open(sys.argv[5], 'rb').read() == b'exact-root'
assert set(os.environ) <= {'HOME', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'LANG', 'LC_ALL'}
assert os.environ['HOME'] == os.getcwd()
''')
        argv = (bv.COSIGN_PATH, 'verify-blob', '--bundle', f'/proc/self/fd/{bundle}',
                '--trusted-root', f'/proc/self/fd/{root}', '--certificate-identity',
                EXPECTED_CERTIFICATE_IDENTITY, '--certificate-oidc-issuer', EXPECTED_CERTIFICATE_ISSUER, '-')
        poisoned = {name: 'untrusted' for name in ('HOME', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY',
                    'NO_PROXY', 'COSIGN_TEST', 'SIGSTORE_TEST', 'AWS_TEST', 'GOOGLE_TEST',
                    'AZURE_TEST', 'KUBECONFIG', 'DOCKER_CONFIG')}
        with patch.dict(os.environ, poisoned):
            result = bv._CosignProcess().run(argv, b'exact\x00blob\n', executable=path,
                                           descriptors=(bundle, root), home=home)
        self.assertEqual(result, bv._ProcessResult(0, 0, 0))

    def test_bounded_output_both_streams(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream), self.assertRaises(ValueError):
                self.run_fake(f'import sys\nsys.{stream}.buffer.write(b"x" * {bv.MAX_OUTPUT_BYTES + 1})\nsys.{stream}.flush()')

    def test_timeout_and_unavailable(self):
        with patch.object(bv, 'EXECUTION_TIMEOUT', 0.05), self.assertRaises(TimeoutError):
            self.run_fake('import time\ntime.sleep(10)')
        with patch.object(bv.subprocess, 'Popen', side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError):
            self.run_fake('pass')

    def test_nonzero_and_large_stdin_without_deadlock(self):
        self.assertEqual(self.run_fake('import sys\nsys.stdin.buffer.read()\nsys.exit(7)').returncode, 7)
        self.assertEqual(self.run_fake('import sys\nassert len(sys.stdin.buffer.read()) == 2097152',
                                      b'x' * bv.MAX_EVIDENCE_BYTES).returncode, 0)


if __name__ == '__main__':
    unittest.main()
