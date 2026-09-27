"""Deterministic C32G contracts; fake processes do not prove cryptography."""

from contextlib import ExitStack
import fcntl
import hashlib
import inspect
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from deployment import blob_verifier as bv
from deployment import broker_service_config as broker_config
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

        def snapshot(path, digest, owned, *, executable, broker_gid):
            self.assertEqual(broker_gid, 1235)
            self.assertIn((path, digest, executable), (
                (bv.COSIGN_PATH, 'a' * 64, True),
                (bv.TRUSTED_ROOT_PATH, 'b' * 64, False)))
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
                     'certificate_identity', 'issuer', 'binary_size', 'expected_binary_size',
                     'maximum_binary_bytes', 'tools_directory', 'binary_mode',
                     'directory_mode', 'file_mode', 'owner_uid'):
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

    def test_snapshot_failures_expose_only_fixed_external_failure(self):
        runner = Runner()
        verifier, _ = self.sandbox(runner)
        with patch.object(bv, '_snapshot', side_effect=OSError('private size/path diagnostic')):
            with self.assertRaises(bv.BlobVerificationError) as caught:
                verifier.verify(*INPUT)
        self.assertEqual(str(caught.exception), bv.ERROR)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(runner.calls, [])

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
        def snapshot(path, digest, owned, *, executable, broker_gid):
            self.assertEqual(broker_gid, 1235)
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
            path.chmod(0o540)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            original_stat, original_fstat = os.stat, os.fstat
            def root_status(value, *, uid=0):
                fields = {name: getattr(value, name) for name in (
                    'st_ino', 'st_dev', 'st_nlink', 'st_size',
                    'st_mtime', 'st_mtime_ns', 'st_ctime_ns')}
                return SimpleNamespace(**fields, st_uid=uid, st_gid=1235,
                                       st_mode=stat.S_IFDIR | 0o750 if stat.S_ISDIR(value.st_mode) else value.st_mode)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(bv, 'COSIGN_BINARY_SIZE', len(b'reviewed authority')), \
                     patch.object(bv, '_directory', return_value=directory_fd), \
                     patch.object(bv.os, 'stat', side_effect=lambda *a, **kw: root_status(original_stat(*a, **kw))), \
                     patch.object(bv.os, 'fstat', side_effect=lambda *a: root_status(original_fstat(*a))):
                    for kind in ('success', 'digest', 'mode', 'hardlink', 'symlink', 'size'):
                        owned = []
                        try:
                            path.unlink()
                            path.write_bytes(b'reviewed authority')
                            path.chmod(0o540)
                            if kind == 'size':
                                path.chmod(0o700)
                                path.write_bytes(b'reviewed authority!')
                                path.chmod(0o540)
                            if kind == 'mode':
                                path.chmod(0o522)
                            if kind == 'hardlink':
                                os.link(path, str(path) + '-link')
                            if kind == 'symlink':
                                path.unlink()
                                os.symlink(str(path) + '-link', path)
                            with self.subTest(kind=kind):
                                if kind == 'success':
                                    fd = bv._snapshot(str(path), digest, owned, executable=True, broker_gid=1235)
                                    path.chmod(0o700)
                                    path.write_bytes(b'changed after qualification')
                                    self.assertEqual(bv._read(fd, len(b'reviewed authority')), b'reviewed authority')
                                    with self.assertRaises(OSError):
                                        os.pwrite(fd, b'x', 0)
                                else:
                                    with self.assertRaises(OSError):
                                        bv._snapshot(str(path), 'a' * 64 if kind == 'digest' else digest,
                                                     owned, executable=True, broker_gid=1235)
                        finally:
                            for fd in owned:
                                os.close(fd)
                path.unlink()
                path.write_bytes(b'reviewed authority')
                path.chmod(0o540)
                owned = []
                try:
                    with patch.object(bv, '_directory', return_value=directory_fd), \
                         patch.object(bv.os, 'stat', side_effect=lambda *a, **kw: root_status(original_stat(*a, **kw), uid=1234)), \
                         patch.object(bv.os, 'fstat', side_effect=lambda *a: root_status(original_fstat(*a), uid=1234)), \
                         self.assertRaises(OSError):
                        bv._snapshot(str(path), digest, owned, executable=True, broker_gid=1235)
                finally:
                    for fd in owned:
                        os.close(fd)
            finally:
                os.close(directory_fd)


class ExactBinarySizeTests(unittest.TestCase):
    def metadata(self, **changes):
        from types import SimpleNamespace
        return SimpleNamespace(**(dict(
            st_mode=stat.S_IFREG | 0o540, st_uid=0, st_gid=1235, st_nlink=1,
            st_size=bv.COSIGN_BINARY_SIZE, st_ino=100, st_dev=200,
            st_mtime_ns=300, st_ctime_ns=400,
        ) | changes))

    def snapshot_boundary(self, opened=None, named=None, *, stack=None, directory=None):
        # Model the metadata/read boundary without allocating a 141 MB fixture.
        # Existing real-file tests exercise reading, hashing, sealing and mutation.
        if stack is None:
            stack = ExitStack()
            self.addCleanup(stack.close)
        opened = opened if opened is not None else self.metadata()
        named = named if named is not None else opened
        stack.enter_context(patch.object(bv, '_directory', return_value=10))
        stack.enter_context(patch.object(bv.os, 'open', return_value=11))
        file_status = Mock(return_value=opened)
        directory_status = Mock(return_value=directory if directory is not None else self.metadata(
            st_mode=stat.S_IFDIR | 0o750, st_size=4096))
        stack.enter_context(patch.object(bv.os, 'fstat', side_effect=lambda fd: (
            directory_status() if fd == 10 else file_status())))
        mocks = {
            'directory': directory_status,
            'named': stack.enter_context(patch.object(bv.os, 'stat', return_value=named)),
            'opened': file_status,
            'read': stack.enter_context(patch.object(bv, '_read', return_value=b'synthetic binary')),
            'sealed': stack.enter_context(patch.object(bv, '_sealed', return_value=12)),
            'hash': stack.enter_context(patch.object(bv.hashlib, 'sha256', wraps=hashlib.sha256)),
        }
        return mocks

    def test_closed_exact_size_and_no_size_parameter(self):
        self.assertIs(type(broker_config.COSIGN_BINARY_SIZE), int)
        self.assertEqual(broker_config.COSIGN_BINARY_SIZE, 141150460)
        self.assertEqual(bv.COSIGN_BINARY_SIZE, broker_config.COSIGN_BINARY_SIZE)
        self.assertFalse(hasattr(bv, 'MAX_BINARY_BYTES'))
        self.assertEqual(tuple(inspect.signature(bv._snapshot).parameters),
                         ('path', 'digest', 'owned', 'executable', 'broker_gid'))
        self.assertNotIn('binary_size', inspect.signature(bv.CosignReleaseBlobVerifier).parameters)

    def test_wrong_or_malformed_stat_size_fails_before_read_or_hash(self):
        class Integer(int):
            pass
        for size in (0, -1, 1, 128 * 1024 * 1024, 141150459, 141150461, 2**63 - 1,
                     True, False, 141150460.0, '141150460', None, Integer(141150460)):
            with self.subTest(size=size), ExitStack() as stack:
                mocks = self.snapshot_boundary(self.metadata(st_size=size), stack=stack)
                with self.assertRaises(OSError):
                    bv._snapshot(bv.COSIGN_PATH, 'a' * 64, [], executable=True, broker_gid=1235)
                for name in ('read', 'hash', 'sealed'):
                    mocks[name].assert_not_called()

    def test_malformed_closed_size_authority_fails_before_read(self):
        class Integer(int):
            pass
        opened = self.metadata()
        for authority in (True, False, 0, -1, None, '141150460', 141150460.0, Integer(141150460)):
            with self.subTest(authority=authority), ExitStack() as stack:
                mocks = self.snapshot_boundary(opened, stack=stack)
                stack.enter_context(patch.object(bv, 'COSIGN_BINARY_SIZE', authority))
                with self.assertRaises(OSError):
                    bv._snapshot(bv.COSIGN_PATH, 'a' * 64, [], executable=True, broker_gid=1235)
                mocks['read'].assert_not_called()
                mocks['hash'].assert_not_called()

    def test_exact_size_reaches_digest_and_seals_only_hashed_bytes(self):
        raw = b'synthetic binary'
        digest = hashlib.sha256(raw).hexdigest()
        mocks = self.snapshot_boundary()
        with patch.dict(os.environ, {'COSIGN_BINARY_SIZE': '1', 'MAX_BINARY_BYTES': '1'}):
            self.assertEqual(bv._snapshot(bv.COSIGN_PATH, digest, [], executable=True, broker_gid=1235), 12)
        mocks['read'].assert_called_once_with(11, 141150460)
        mocks['hash'].assert_called_once_with(raw)
        mocks['sealed'].assert_called_once_with(raw, [11], executable=True)

    def test_exact_size_cannot_make_wrong_digest_acceptable(self):
        mocks = self.snapshot_boundary()
        with self.assertRaises(OSError):
            bv._snapshot(bv.COSIGN_PATH, 'a' * 64, [], executable=True, broker_gid=1235)
        mocks['read'].assert_called_once_with(11, 141150460)
        mocks['hash'].assert_called_once_with(b'synthetic binary')
        mocks['sealed'].assert_not_called()

    def test_correct_digest_cannot_make_wrong_size_acceptable(self):
        digest = hashlib.sha256(b'synthetic binary').hexdigest()
        mocks = self.snapshot_boundary(self.metadata(st_size=141150459))
        with self.assertRaises(OSError):
            bv._snapshot(bv.COSIGN_PATH, digest, [], executable=True, broker_gid=1235)
        for name in ('read', 'hash', 'sealed'):
            mocks[name].assert_not_called()

    def test_metadata_mutation_during_read_rejected_before_sealing(self):
        digest = hashlib.sha256(b'synthetic binary').hexdigest()
        for field, changed in (('st_size', 141150459), ('st_mtime_ns', 301), ('st_ctime_ns', 401)):
            for source in ('opened', 'named'):
                with self.subTest(field=field, source=source), ExitStack() as stack:
                    mocks = self.snapshot_boundary(stack=stack)
                    mocks[source].side_effect = [self.metadata(), self.metadata(**{field: changed})]
                    with self.assertRaises(OSError):
                        bv._snapshot(bv.COSIGN_PATH, digest, [], executable=True, broker_gid=1235)
                    mocks['read'].assert_called_once()
                    mocks['sealed'].assert_not_called()

    def test_named_open_substitution_rejected_before_read(self):
        mocks = self.snapshot_boundary(named=self.metadata(st_ino=101))
        with self.assertRaises(OSError):
            bv._snapshot(bv.COSIGN_PATH, 'a' * 64, [], executable=True, broker_gid=1235)
        mocks['read'].assert_not_called()
        mocks['sealed'].assert_not_called()

    def test_executable_file_type_owner_mode_and_links_unchanged(self):
        for changes in ({'st_uid': 1234}, {'st_nlink': 2}, {'st_nlink': 0},
                        {'st_mode': stat.S_IFREG | 0o522}, {'st_mode': stat.S_IFREG | 0o400},
                        {'st_mode': stat.S_IFLNK | 0o500}, {'st_mode': stat.S_IFIFO | 0o500}):
            with self.subTest(changes=changes), ExitStack() as stack:
                mocks = self.snapshot_boundary(self.metadata(**changes), stack=stack)
                with self.assertRaises(OSError):
                    bv._snapshot(bv.COSIGN_PATH, 'a' * 64, [], executable=True, broker_gid=1235)
                mocks['read'].assert_not_called()
                mocks['sealed'].assert_not_called()

    def test_exact_binary_mode_and_broker_gid_before_content_read(self):
        digest = hashlib.sha256(b'synthetic binary').hexdigest()
        for changes in (
            *({'st_mode': stat.S_IFREG | mode} for mode in
              (0o550, 0o500, 0o440, 0o544, 0o640, 0o560, 0o542, 0o7540)),
            {'st_uid': 1234}, {'st_gid': 0}, {'st_gid': 2002},
            {'st_uid': False}, {'st_gid': True}, {'st_nlink': True},
        ):
            with self.subTest(changes=changes), ExitStack() as stack:
                mocks = self.snapshot_boundary(self.metadata(**changes), stack=stack)
                with self.assertRaises(OSError):
                    bv._snapshot(bv.COSIGN_PATH, digest, [], executable=True, broker_gid=1235)
                for name in ('read', 'hash', 'sealed'):
                    mocks[name].assert_not_called()

    def test_exact_tools_directory_authority_before_binary_read(self):
        digest = hashlib.sha256(b'synthetic binary').hexdigest()
        for changes in (
            {'st_gid': 0, 'st_mode': stat.S_IFDIR | 0o755},
            *({'st_mode': stat.S_IFDIR | mode} for mode in
              (0o700, 0o755, 0o770, 0o752, 0o1750, 0o2750)),
            {'st_uid': 1234}, {'st_gid': 2002}, {'st_mode': stat.S_IFREG | 0o750},
            {'st_uid': False}, {'st_gid': True},
        ):
            with self.subTest(changes=changes), ExitStack() as stack:
                directory = self.metadata(st_mode=stat.S_IFDIR | 0o750, st_size=4096)
                for name, value in changes.items():
                    setattr(directory, name, value)
                mocks = self.snapshot_boundary(directory=directory, stack=stack)
                with self.assertRaises(OSError):
                    bv._snapshot(bv.COSIGN_PATH, digest, [], executable=True, broker_gid=1235)
                for name in ('opened', 'read', 'hash', 'sealed'):
                    mocks[name].assert_not_called()

    def test_correct_content_wrong_mode_or_gid_fixed_failure_no_execution(self):
        # Size is modeled; small actual bytes/digest exercise the content boundary.
        # Authority failure must prevent even reaching that matching content.
        digest = hashlib.sha256(b'synthetic binary').hexdigest()
        for changes in ({'st_gid': 2002}, {'st_mode': stat.S_IFREG | 0o550}):
            with self.subTest(changes=changes), ExitStack() as stack:
                runner = Runner()
                verifier = bv.CosignReleaseBlobVerifier(
                    **(AUTHORITY | {'expected_binary_sha256': digest}), runner=runner,
                )
                for name, value in (('getuid', 1234), ('geteuid', 1234),
                                    ('getgid', 1235), ('getegid', 1235)):
                    stack.enter_context(patch.object(bv.os, name, return_value=value))
                stack.enter_context(patch.object(bv.os, 'close'))
                mocks = self.snapshot_boundary(self.metadata(**changes), stack=stack)
                with self.assertRaises(bv.BlobVerificationError) as caught:
                    verifier.verify(*INPUT)
                self.assertEqual(str(caught.exception), bv.ERROR)
                self.assertEqual(runner.calls, [])
                for name in ('read', 'hash', 'sealed'):
                    mocks[name].assert_not_called()

    def test_directory_mutation_during_binary_read_rejected(self):
        mocks = self.snapshot_boundary()
        mocks['directory'].side_effect = [
            self.metadata(st_mode=stat.S_IFDIR | 0o750, st_size=4096),
            self.metadata(st_mode=stat.S_IFDIR | 0o755, st_size=4096),
        ]
        with self.assertRaises(OSError):
            bv._snapshot(bv.COSIGN_PATH, hashlib.sha256(b'synthetic binary').hexdigest(),
                         [], executable=True, broker_gid=1235)
        mocks['read'].assert_called_once()
        mocks['sealed'].assert_not_called()

    def test_captured_group_requires_no_ambient_group_lookup(self):
        self.snapshot_boundary()
        with patch.object(bv.os, 'getegid', side_effect=AssertionError('ambient group')):
            self.assertEqual(bv._snapshot(
                bv.COSIGN_PATH, hashlib.sha256(b'synthetic binary').hexdigest(),
                [], executable=True, broker_gid=1235), 12)
        for gid in (True, False, 0, -1, None, '1235', 1235.0):
            with self.subTest(gid=gid), ExitStack() as stack:
                mocks = self.snapshot_boundary(stack=stack)
                with self.assertRaises(OSError):
                    bv._snapshot(bv.COSIGN_PATH, 'a' * 64, [], executable=True, broker_gid=gid)
                mocks['read'].assert_not_called()


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
                         'directory_mode', 'directory_group', 'directory_owner',
                         'empty', 'oversize', 'at_bound', 'digest'):
                raw = (b'' if kind == 'empty' else b'x' * (bv.MAX_ROOT_BYTES + 1)
                       if kind == 'oversize' else b'x' * bv.MAX_ROOT_BYTES
                       if kind == 'at_bound' else b'reviewed root')
                path.write_bytes(raw)
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
                         patch.object(bv.os, 'getegid', side_effect=AssertionError('ambient group')), \
                         patch.object(bv.os, 'stat', side_effect=lambda *a, **kw: authority_status(original_stat(*a, **kw))), \
                         patch.object(bv.os, 'fstat', side_effect=lambda *a: authority_status(original_fstat(*a))):
                        digest = 'a' * 64 if kind == 'digest' else hashlib.sha256(raw).hexdigest()
                        if kind in ('success', 'at_bound'):
                            descriptor = bv._snapshot(str(path), digest, owned, executable=False, broker_gid=1235)
                            self.assertEqual(bv._read(descriptor, len(raw)), raw)
                        else:
                            with self.assertRaises(OSError):
                                bv._snapshot(str(path), digest, owned, executable=False, broker_gid=1235)
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
