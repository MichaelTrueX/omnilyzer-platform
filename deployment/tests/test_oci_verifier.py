"""C32N deterministic process/credential contracts, never real Cosign or zot."""

import ast
import builtins
from contextlib import ExitStack
import fcntl
import inspect
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment import blob_verifier as bv, oci_verifier as ov
from deployment.release_consumer import OCISignatureVerifier, ZotReadCredential
from deployment.policy import EXPECTED_CERTIFICATE_IDENTITY, EXPECTED_CERTIFICATE_ISSUER
from deployment.tests import test_blob_verifier as blob_tests

AUTHORITY = blob_tests.AUTHORITY

ROOT = Path(__file__).resolve().parents[2]
NOW = 1770000000
TOKEN = 'synthetic.zot.READ.credential'
REFERENCE = 'oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:' + 'a' * 64
RESULT = dict(verified=True, repository='omnilyzer/task013-release-canary',
              manifest_digest='sha256:' + 'a' * 64,
              certificate_identity=EXPECTED_CERTIFICATE_IDENTITY, issuer=EXPECTED_CERTIFICATE_ISSUER)
ERROR = 'OCI signature verification is unavailable or invalid'


class Provider:
    def __init__(self, credential=None):
        self.calls = 0
        self.value = credential if credential is not None else ZotReadCredential(TOKEN, NOW + 100)

    def zot_read_credential(self):
        self.calls += 1
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


class Runner:
    def __init__(self, result=None):
        self.calls = []
        self.result = result if result is not None else bv._ProcessResult(0, 0, 0)

    def run(self, argv, blob, *, executable, descriptors, home, docker_config):
        self.calls.append((argv, blob, executable, descriptors, home, docker_config))
        self.assertion = unittest.TestCase()
        self.assertion.assertEqual(blob, b'')
        self.assertion.assertEqual(argv, (bv.COSIGN_PATH, 'verify', '--offline', '--trusted-root',
            argv[4], '--certificate-identity', EXPECTED_CERTIFICATE_IDENTITY,
            '--certificate-oidc-issuer', EXPECTED_CERTIFICATE_ISSUER, REFERENCE))
        self.assertion.assertNotIn(TOKEN, str((argv, executable, home, docker_config)))
        for fd in descriptors[:2]:
            self.assertion.assertTrue(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE)
            with self.assertion.assertRaises(OSError):
                os.pwrite(fd, b'change', 0)
        self.assertion.assertEqual(executable, '/proc/self/fd/' + str(descriptors[0]))
        self.assertion.assertEqual(argv[4], '/proc/self/fd/' + str(descriptors[1]))
        self.assertion.assertEqual(bv._read(descriptors[0], 6), b'binary')
        self.assertion.assertEqual(bv._read(descriptors[1], 4), b'root')
        self.assertion.assertEqual(set(os.listdir(home)), {'.docker'})
        self.assertion.assertEqual(set(os.listdir(docker_config)), {'config.json'})
        self.assertion.assertEqual(os.stat(home + '/.docker').st_ino, os.stat(docker_config).st_ino)
        self.assertion.assertEqual(stat.S_IMODE(os.stat(home).st_mode), 0o700)
        self.assertion.assertEqual(stat.S_IMODE(os.stat(docker_config).st_mode), 0o700)
        path = Path(docker_config) / 'config.json'
        self.assertion.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertion.assertEqual(path.read_bytes(), json.dumps(
            {'auths': {'oci-dev.omnilyzer.ai': {'registrytoken': TOKEN}}},
            sort_keys=True, separators=(',', ':')).encode('ascii'))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class VerifierTests(unittest.TestCase):
    def sandbox(self, *, provider=None, runner=None):
        previous = getattr(self, '_sandbox_stack', None)
        if previous is not None:
            previous.close()
        stack = ExitStack()
        self._sandbox_stack = stack
        self.addCleanup(stack.close)
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        selected_provider, selected_runner = provider or Provider(), runner or Runner()
        stack.enter_context(patch.object(ov, '_RUNTIME_DIRECTORY', directory))
        original_stat, original_fstat = os.stat, os.fstat
        def status(value):
            fields = {name: getattr(value, name) for name in (
                'st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_size', 'st_mtime', 'st_mtime_ns', 'st_ctime_ns')}
            return SimpleNamespace(**fields, st_uid=1234, st_gid=1235)
        stack.enter_context(patch.object(os, 'stat', side_effect=lambda *a, **kw: status(original_stat(*a, **kw))))
        stack.enter_context(patch.object(os, 'fstat', side_effect=lambda *a: status(original_fstat(*a))))
        for name, value in (('getuid', 1234), ('geteuid', 1234), ('getgid', 1235), ('getegid', 1235)):
            stack.enter_context(patch.object(os, name, return_value=value))
        def snapshot(path, digest, owned, *, executable, broker_gid):
            self.assertEqual(broker_gid, 1235)
            self.assertIn((path, digest, executable), (
                (bv.COSIGN_PATH, 'a' * 64, True), (bv.TRUSTED_ROOT_PATH, 'b' * 64, False)))
            return bv._sealed(b'binary' if executable else b'root', owned, executable=executable)
        stack.enter_context(patch.object(bv, '_snapshot', side_effect=snapshot))
        def runtime(path, owned, *, broker):
            self.assertEqual(path, directory)
            self.assertEqual(broker, (1234, 1235))
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            owned.append(fd)
            return fd
        stack.enter_context(patch.object(bv, '_directory', side_effect=runtime))
        # Only the already-tested protected ancestor traversal is substituted.
        stack.enter_context(patch.object(ov, '_chain', side_effect=lambda fds, path: (
            (fds[0], None, None, ov._stable(bv._fingerprint(os.fstat(fds[0])))),)))
        stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('network')))
        stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess')))
        original_open = os.open
        def guarded_open(name, flags, *args, **kwargs):
            if flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR | os.O_TRUNC):
                self.assertEqual(name, 'config.json')
                parent = os.readlink('/proc/self/fd/' + str(kwargs['dir_fd']))
                self.assertTrue(Path(parent).is_relative_to(directory))
            return original_open(name, flags, *args, **kwargs)
        stack.enter_context(patch.object(os, 'open', side_effect=guarded_open))
        verifier = ov.CosignOCISignatureVerifier(**AUTHORITY,
            zot_credential_provider=selected_provider, runner=selected_runner)
        return verifier, directory, selected_provider, selected_runner

    def reject(self, verifier, reference=REFERENCE, now=NOW):
        with self.assertRaises(ov.OCIVerificationError) as caught:
            verifier.verify(reference, now)
        self.assertEqual(str(caught.exception), ERROR)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_exact_result_config_sealed_invocation_and_cleanup(self):
        verifier, directory, provider, runner = self.sandbox()
        self.assertEqual(provider.calls, 0)
        self.assertEqual(verifier.verify(REFERENCE, NOW), RESULT)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(os.listdir(directory), [])
        for fd in runner.calls[0][3]:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertNotIn(TOKEN, repr(verifier))

    def test_strict_references_before_credential_or_resource_io(self):
        for reference in (None, True, '', REFERENCE + '?x', REFERENCE + '#x', REFERENCE + '/x',
            'https://' + REFERENCE, REFERENCE.replace('oci-dev', 'other'),
            REFERENCE.replace('task013-release-canary', 'other'),
            REFERENCE.replace('@sha256:', ':latest@sha256:'), REFERENCE.split('@')[0] + ':latest',
            REFERENCE.replace('a' * 64, 'A' * 64), REFERENCE[:-1], REFERENCE + '\n'):
            verifier, directory, provider, runner = self.sandbox()
            with self.subTest(reference=reference), patch.object(bv, '_snapshot') as snapshot:
                self.reject(verifier, reference)
                snapshot.assert_not_called()
                self.assertEqual(provider.calls, 0)
                self.assertEqual(os.listdir(directory), [])

    def test_explicit_exact_time(self):
        self.assertEqual(tuple(inspect.signature(OCISignatureVerifier.verify).parameters), ('self', 'image_reference', 'now'))
        verifier, *_ = self.sandbox()
        with self.assertRaises(TypeError):
            verifier.verify(REFERENCE)
        for value in (None, True, False, -1, float(NOW), str(NOW)):
            with self.subTest(now=value):
                self.reject(verifier, now=value)

    def test_credential_type_expiry_and_token_fail_closed(self):
        class Subclass(ZotReadCredential):
            pass
        values = (object(), {'token': TOKEN, 'expires_at': NOW + 1}, Subclass(TOKEN, NOW + 1),
            ZotReadCredential(TOKEN, NOW), ZotReadCredential(TOKEN, NOW - 1),
            ZotReadCredential(TOKEN, NOW + 301), ZotReadCredential(TOKEN, True),
            ZotReadCredential(TOKEN, float(NOW + 1)),
            *(ZotReadCredential(token, NOW + 100) for token in ('', 'a' * 8193, 'white space',
                '\n', '\0', 'é', b'bytes', True)))
        for credential in values:
            verifier, directory, _, runner = self.sandbox(provider=Provider(credential))
            with self.subTest(credential_type=type(credential)):
                self.reject(verifier)
                self.assertEqual(os.listdir(directory), [])
                self.assertEqual(runner.calls, [])

    def test_expiry_bounds_one_and_300_seconds_accepted(self):
        for lifetime in (1, 300):
            verifier, directory, *_ = self.sandbox(provider=Provider(ZotReadCredential(TOKEN, NOW + lifetime)))
            self.assertEqual(verifier.verify(REFERENCE, NOW), RESULT)
            self.assertEqual(os.listdir(directory), [])

    def test_provider_exception_private_diagnostics_not_exposed(self):
        verifier, directory, _, runner = self.sandbox(provider=Provider(RuntimeError(TOKEN)))
        self.reject(verifier)
        self.assertEqual(os.listdir(directory), [])
        self.assertEqual(runner.calls, [])

    def test_captured_provider_and_runner_cannot_be_replaced(self):
        verifier, directory, provider, runner = self.sandbox()
        provider.zot_read_credential = lambda: self.fail('replacement provider')
        runner.run = lambda *args, **kwargs: self.fail('replacement runner')
        self.assertEqual(verifier.verify(REFERENCE, NOW), RESULT)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(os.listdir(directory), [])
        for field in ov.CosignOCISignatureVerifier.__slots__:
            with self.assertRaises(AttributeError):
                setattr(verifier, field, None)
            with self.assertRaises(AttributeError):
                delattr(verifier, field)

    def test_constructor_closed_authority_no_io_or_token(self):
        provider = Provider()
        with patch.object(os, 'open', side_effect=AssertionError('I/O')):
            ov.CosignOCISignatureVerifier(**AUTHORITY, zot_credential_provider=provider, runner=Runner())
        self.assertEqual(provider.calls, 0)
        for field, value in (('expected_cosign_version', 'latest'), ('expected_cosign_version', '3.1.1'),
            ('expected_binary_sha256', '0' * 64), ('expected_binary_sha256', 'A' * 64),
            ('expected_trusted_root_sha256', 'invalid'), ('broker_uid', 0), ('broker_gid', True)):
            with self.subTest(field=field), self.assertRaises(ov.OCIVerificationError):
                ov.CosignOCISignatureVerifier(**(AUTHORITY | {field: value}), zot_credential_provider=provider)
        for field in ('token', 'path', 'image_reference', 'registry', 'mode', 'size'):
            with self.subTest(field=field), self.assertRaises(TypeError):
                ov.CosignOCISignatureVerifier(**AUTHORITY, zot_credential_provider=provider, **{field: 'caller'})

    def test_invalid_provider_property_not_invoked(self):
        class Property:
            @property
            def zot_read_credential(self):
                raise AssertionError('property invoked')
        for value in (None, {}, Property()):
            with self.assertRaises(ov.OCIVerificationError):
                ov.CosignOCISignatureVerifier(**AUTHORITY, zot_credential_provider=value)

    def test_nonzero_timeout_unavailable_malformed_process_result_cleanup(self):
        for result in (bv._ProcessResult(1, 0, 0), TimeoutError(TOKEN), FileNotFoundError(TOKEN),
            RuntimeError(TOKEN), {'returncode': 0}, bv._ProcessResult(True, 0, 0),
            bv._ProcessResult(0, True, 0), bv._ProcessResult(0, -1, 0),
            bv._ProcessResult(0, 65537, 0), bv._ProcessResult(0, 0, 65537)):
            verifier, directory, _, _ = self.sandbox(runner=Runner(result))
            with self.subTest(result_type=type(result)):
                self.reject(verifier)
                self.assertEqual(os.listdir(directory), [])

    def test_control_exception_preserves_semantics_and_removes_credentials(self):
        verifier, directory, *_ = self.sandbox(runner=Runner(KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            verifier.verify(REFERENCE, NOW)
        self.assertEqual(os.listdir(directory), [])

    def test_cleanup_failure_prevents_success(self):
        verifier, directory, *_ = self.sandbox()
        original = os.rmdir
        def fail(name, **kwargs):
            if name == '.docker':
                raise OSError('cleanup private path')
            return original(name, **kwargs)
        with patch.object(os, 'rmdir', side_effect=fail):
            self.reject(verifier)
        self.assertFalse(list(Path(directory).rglob('config.json')))

    def test_config_write_failure_cleans_own_token_file(self):
        verifier, directory, *_ = self.sandbox()
        original = os.write
        def fail(fd, raw):
            if os.readlink('/proc/self/fd/' + str(fd)).endswith('/config.json'):
                original(fd, raw[:5])
                raise OSError(TOKEN)
            return original(fd, raw)
        with patch.object(os, 'write', side_effect=fail):
            self.reject(verifier)
        self.assertEqual(os.listdir(directory), [])

    def test_wrong_process_identity_before_resources_and_provider(self):
        for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
            verifier, directory, provider, runner = self.sandbox()
            with patch.object(os, name, return_value=0):
                self.reject(verifier)
            self.assertEqual(provider.calls, 0)
            self.assertEqual(runner.calls, [])
            self.assertEqual(os.listdir(directory), [])

    def test_wrong_static_authority_never_acquires_credentials(self):
        for executable in (True, False):
            verifier, directory, provider, runner = self.sandbox()
            original = bv._snapshot
            def fail(*args, **kwargs):
                if kwargs['executable'] == executable:
                    raise OSError('wrong source authority')
                return original(*args, **kwargs)
            with patch.object(bv, '_snapshot', side_effect=fail):
                self.reject(verifier)
            self.assertEqual(provider.calls, 0)
            self.assertEqual(runner.calls, [])
            self.assertEqual(os.listdir(directory), [])

    def test_shared_binary_metadata_enforced_before_process(self):
        helper = blob_tests.ExactBinarySizeTests()
        for changes in ({'st_uid': 1234}, {'st_gid': 0}, {'st_mode': stat.S_IFREG | 0o550},
                        {'st_size': 141150459}, {'st_nlink': 2}):
            verifier, _, provider, runner = self.sandbox()
            with ExitStack() as stack:
                # Restore the real shared snapshot behind the sandbox source seam.
                stack.enter_context(patch.object(bv, '_snapshot', new=REAL_SNAPSHOT))
                mocks = helper.snapshot_boundary(helper.metadata(**changes), stack=stack)
                stack.enter_context(patch.object(os, 'close'))
                self.reject(verifier)
                mocks['read'].assert_not_called()
            self.assertEqual(provider.calls, 0)
            self.assertEqual(runner.calls, [])

    def test_wrong_digest_rejected_using_shared_snapshot(self):
        verifier, _, provider, runner = self.sandbox()
        helper = blob_tests.ExactBinarySizeTests()
        with ExitStack() as stack:
            stack.enter_context(patch.object(bv, '_snapshot', new=REAL_SNAPSHOT))
            mocks = helper.snapshot_boundary(stack=stack)
            stack.enter_context(patch.object(os, 'close'))
            self.reject(verifier)
            mocks['hash'].assert_called_once()
            mocks['sealed'].assert_not_called()
        self.assertEqual(provider.calls, 0)
        self.assertEqual(runner.calls, [])

    def test_runtime_and_private_directory_substitution_rejected(self):
        verifier, directory, provider, runner = self.sandbox()
        original = os.open
        def replace(name, flags, *args, **kwargs):
            if name == '.docker':
                parent = Path('/proc/self/fd/' + str(kwargs['dir_fd']))
                (parent / name).rename(parent / 'original-docker')
                (parent / name).mkdir(mode=0o700)
            return original(name, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=replace):
            self.reject(verifier)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(runner.calls, [])
        self.assertFalse(list(Path(directory).rglob('config.json')))

    def test_shared_trusted_root_metadata_and_digest_enforced(self):
        helper = blob_tests.ExactBinarySizeTests()
        for changes in ({'st_uid': 1234}, {'st_gid': 0}, {'st_mode': stat.S_IFREG | 0o644},
                        {'st_nlink': 2}, {'st_size': 0}, {'st_size': bv.MAX_ROOT_BYTES + 1}, {}):
            verifier, _, provider, runner = self.sandbox()
            with ExitStack() as stack:
                opened = helper.metadata(**({'st_mode': stat.S_IFREG | 0o640, 'st_size': 6787} | changes))
                mocks = helper.snapshot_boundary(opened, stack=stack)
                def snapshot(path, digest, owned, *, executable, broker_gid):
                    if executable:
                        return 42  # No actual binary or process: root must fail.
                    return REAL_SNAPSHOT(path, digest, owned, executable=False, broker_gid=broker_gid)
                stack.enter_context(patch.object(bv, '_snapshot', side_effect=snapshot))
                stack.enter_context(patch.object(os, 'close'))
                self.reject(verifier)
                if changes:
                    mocks['read'].assert_not_called()
                else:
                    mocks['hash'].assert_called_once()
                    mocks['sealed'].assert_not_called()
            self.assertEqual(provider.calls, 0)
            self.assertEqual(runner.calls, [])

    def test_config_mutation_during_process_rejected(self):
        runner = Runner()
        verifier, directory, *_ = self.sandbox(runner=runner)
        original = runner.run
        # Constructor has already captured original; use a distinct trusted seam.
        class Mutating(Runner):
            def run(self, *args, **kwargs):
                result = original(*args, **kwargs)
                path = Path(kwargs['docker_config']) / 'config.json'
                path.write_bytes(b'changed')
                return result
        verifier = ov.CosignOCISignatureVerifier(**AUTHORITY, zot_credential_provider=Provider(), runner=Mutating())
        self.reject(verifier)
        self.assertEqual(os.listdir(directory), [])

    def test_cleanup_does_not_unlink_substituted_config(self):
        class Substitute(Runner):
            def run(self, *args, **kwargs):
                result = super().run(*args, **kwargs)
                path = Path(kwargs['docker_config']) / 'config.json'
                path.rename(path.with_name('held-original'))
                path.write_bytes(b'unrelated replacement')
                return result
        verifier, directory, *_ = self.sandbox(runner=Substitute())
        self.reject(verifier)
        self.assertEqual(next(Path(directory).rglob('config.json')).read_bytes(), b'unrelated replacement')

    def test_no_environment_path_or_credential_authority(self):
        verifier, directory, *_ = self.sandbox()
        with patch.dict(os.environ, {name: TOKEN for name in ('HOME', 'DOCKER_CONFIG', 'COSIGN_REPOSITORY',
            'HTTPS_PROXY', 'AWS_SECRET_ACCESS_KEY', 'SIGSTORE_ROOT_FILE', 'REGISTRY_AUTH_FILE')}):
            self.assertEqual(verifier.verify(REFERENCE, NOW), RESULT)
        self.assertEqual(os.listdir(directory), [])

    def test_exact_builtin_subclasses_rejected(self):
        class Integer(int):
            pass
        class String(str):
            pass
        for reference, now in ((String(REFERENCE), NOW), (REFERENCE, Integer(NOW))):
            verifier, *_ = self.sandbox()
            self.reject(verifier, reference, now)
        for credential in (ZotReadCredential(String(TOKEN), NOW + 1),
                           ZotReadCredential(TOKEN, Integer(NOW + 1))):
            verifier, directory, *_ = self.sandbox(provider=Provider(credential))
            self.reject(verifier)
            self.assertEqual(os.listdir(directory), [])

    def test_none_process_result_rejected(self):
        class NoResult(Runner):
            def run(self, *args, **kwargs):
                super().run(*args, **kwargs)
                return None
        verifier, directory, *_ = self.sandbox(runner=NoResult())
        self.reject(verifier)
        self.assertEqual(os.listdir(directory), [])

    def test_token_json_escaping_cannot_inject_helpers_or_auth_entries(self):
        token = 'x"},"credsStore":"attacker","auths":{"other":{"auth":"x\\'
        class InspectConfig:
            def run(self, argv, blob, *, executable, descriptors, home, docker_config):
                assertion = unittest.TestCase()
                actual = json.loads(Path(docker_config, 'config.json').read_bytes())
                assertion.assertEqual(actual, {'auths': {'oci-dev.omnilyzer.ai': {'registrytoken': token}}})
                assertion.assertNotIn(token, str((argv, executable, home, docker_config)))
                return bv._ProcessResult(0, 0, 0)
        verifier, directory, *_ = self.sandbox(
            provider=Provider(ZotReadCredential(token, NOW + 100)), runner=InspectConfig())
        self.assertEqual(verifier.verify(REFERENCE, NOW), RESULT)
        self.assertEqual(os.listdir(directory), [])

    def test_closed_identity_not_derived_from_process_output(self):
        # The runner returns only counters: even nonempty untrusted output has
        # no parsed identity/policy channel or extra result fields.
        verifier, directory, *_ = self.sandbox(runner=Runner(bv._ProcessResult(0, 100, 200)))
        self.assertEqual(verifier.verify(REFERENCE, NOW), RESULT)
        self.assertEqual(os.listdir(directory), [])

    def test_config_exclusive_creation_and_no_follow(self):
        for kind in ('file', 'symlink'):
            verifier, directory, provider, runner = self.sandbox()
            original = ov._auth
            def residue(fd, *args):
                path = Path('/proc/self/fd/' + str(fd)) / 'config.json'
                if kind == 'file':
                    path.write_bytes(b'unrelated residue')
                else:
                    path.symlink_to('/nonexistent-synthetic-config')
                return original(fd, *args)
            with patch.object(ov, '_auth', side_effect=residue):
                self.reject(verifier)
            self.assertEqual(provider.calls, 1)
            self.assertEqual(runner.calls, [])
            self.assertTrue(list(Path(directory).rglob('config.json')))

    def test_auth_config_metadata_and_inode_checks(self):
        for change in ({'st_uid': 0}, {'st_gid': 0}, {'st_mode': stat.S_IFREG | 0o644},
                       {'st_nlink': 2}, {'st_size': True}):
            verifier, directory, _, runner = self.sandbox()
            original = os.fstat
            def wrong(fd):
                value = original(fd)
                if os.readlink('/proc/self/fd/' + str(fd)).endswith('/config.json'):
                    return SimpleNamespace(**(vars(value) | change))
                return value
            with patch.object(os, 'fstat', side_effect=wrong):
                self.reject(verifier)
            self.assertEqual(runner.calls, [])
            self.assertEqual(os.listdir(directory), [])

    def test_private_modes_and_owner_exact(self):
        for change in ({'st_uid': 0}, {'st_gid': 0}, {'st_mode': stat.S_IFDIR | 0o750},
                       {'st_mode': stat.S_IFREG | 0o700}, {'st_uid': True}):
            verifier, directory, _, runner = self.sandbox()
            original = os.fstat
            def wrong(fd):
                value = original(fd)
                if os.readlink('/proc/self/fd/' + str(fd)).endswith('/.docker'):
                    return SimpleNamespace(**(vars(value) | change))
                return value
            with patch.object(os, 'fstat', side_effect=wrong):
                self.reject(verifier)
            self.assertEqual(runner.calls, [])
            self.assertEqual(os.listdir(directory), [])

    def test_config_unlink_and_descriptor_close_failure_fail_closed(self):
        verifier, directory, *_ = self.sandbox()
        original = os.unlink
        def fail(name, **kwargs):
            if name == 'config.json':
                raise OSError('credential unlink failure')
            return original(name, **kwargs)
        with patch.object(os, 'unlink', side_effect=fail):
            self.reject(verifier)
        self.assertTrue(list(Path(directory).rglob('config.json')))
        verifier, directory, *_ = self.sandbox()
        original = os.close
        def close_then_fail(fd):
            original(fd)
            raise OSError('close failure')
        with patch.object(os, 'close', side_effect=close_then_fail):
            self.reject(verifier)
        self.assertEqual(os.listdir(directory), [])

    def test_workspace_replaced_after_process_token_removed_from_held_directory(self):
        class Replace(Runner):
            def run(self, *args, **kwargs):
                result = super().run(*args, **kwargs)
                real = Path(os.path.realpath(kwargs['home']))
                real.rename(real.with_name('original-workspace'))
                real.mkdir(mode=0o700)
                return result
        verifier, directory, *_ = self.sandbox(runner=Replace())
        self.reject(verifier)
        self.assertFalse(list(Path(directory).rglob('config.json')))

    def test_no_host_docker_config_read(self):
        verifier, directory, *_ = self.sandbox()
        original = builtins.open
        def guarded(path, *args, **kwargs):
            if type(path) is str and '.docker' in path:
                self.assertTrue(path.startswith('/proc/self/fd/'))
            return original(path, *args, **kwargs)
        with patch.object(builtins, 'open', side_effect=guarded):
            self.assertEqual(verifier.verify(REFERENCE, NOW), RESULT)
        self.assertEqual(os.listdir(directory), [])


REAL_SNAPSHOT = bv._snapshot


class ProcessTests(unittest.TestCase):
    def fixture(self, body):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        home = Path(directory.name)
        docker = home / '.docker'
        docker.mkdir(mode=0o700)
        (docker / 'config.json').write_text(json.dumps({'auths': {'oci-dev.omnilyzer.ai': {'registrytoken': TOKEN}}}))
        (docker / 'config.json').chmod(0o600)
        executable = home / 'fake-cosign'
        executable.write_text('#!' + sys.executable + '\n' + body)
        executable.chmod(0o700)
        fds = [os.open(path, os.O_RDONLY | os.O_DIRECTORY) for path in (home, docker)]
        self.addCleanup(lambda: [os.close(fd) for fd in fds])
        return str(executable), '/proc/self/fd/' + str(fds[0]), '/proc/self/fd/' + str(fds[1]), tuple(fds)

    def run_fake(self, body):
        executable, home, docker, fds = self.fixture(body)
        return bv._CosignProcess().run((bv.COSIGN_PATH, 'verify', '--offline', REFERENCE), b'',
            executable=executable, descriptors=fds, home=home, docker_config=docker)

    def test_private_descriptor_docker_lookup_and_minimal_environment(self):
        body = '''import os, json, sys
assert sys.stdin.buffer.read() == b''
assert sys.argv[1:] == ['verify', '--offline', ''' + repr(REFERENCE) + ''']
expected = {'HOME', 'DOCKER_CONFIG', 'XDG_RUNTIME_DIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'LANG', 'LC_ALL'}
assert set(os.environ) == expected
assert os.stat(os.environ['HOME'] + '/.docker').st_ino == os.stat(os.environ['DOCKER_CONFIG']).st_ino
assert json.load(open(os.environ['DOCKER_CONFIG'] + '/config.json')) == {'auths': {'oci-dev.omnilyzer.ai': {'registrytoken': ''' + repr(TOKEN) + '''}}}
assert os.getcwd() == os.path.realpath(os.environ['HOME'])
'''
        with patch.dict(os.environ, {key: TOKEN for key in ('PATH', 'HOME', 'DOCKER_CONFIG', 'HTTP_PROXY',
            'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'COSIGN_REPOSITORY', 'SIGSTORE_TEST', 'AWS_TEST',
            'GOOGLE_TEST', 'AZURE_TEST', 'KUBECONFIG', 'REGISTRY_AUTH_FILE', 'DOCKER_AUTH_CONFIG')}):
            self.assertEqual(self.run_fake(body), bv._ProcessResult(0, 0, 0))

    def test_explicit_process_flags_and_no_token_in_environment_or_argv(self):
        original = subprocess.Popen
        calls = []
        def capture(argv, **kwargs):
            calls.append((argv, kwargs))
            return original(argv, **kwargs)
        with patch.object(subprocess, 'Popen', side_effect=capture):
            self.run_fake('import sys\nsys.stdin.buffer.read()')
        argv, kwargs = calls[0]
        self.assertFalse(kwargs['shell'])
        self.assertTrue(kwargs['start_new_session'])
        self.assertTrue(kwargs['close_fds'])
        self.assertNotIn(TOKEN, str((argv, kwargs['env'], kwargs['executable'], kwargs['cwd'])))
        self.assertEqual(len(kwargs['pass_fds']), 2)

    def test_bounded_stdout_stderr(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream), self.assertRaises(ValueError):
                self.run_fake('import sys\nsys.' + stream + '.buffer.write(b"x" * 65537)')

    def test_timeout_nonzero_unavailable_and_no_deadlock(self):
        with patch.object(bv, 'EXECUTION_TIMEOUT', 0.05), self.assertRaises(TimeoutError):
            self.run_fake('import time\ntime.sleep(10)')
        self.assertEqual(self.run_fake('import sys\nsys.exit(7)').returncode, 7)
        with patch.object(subprocess, 'Popen', side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError):
            self.run_fake('pass')
        self.assertEqual(self.run_fake('import sys\nsys.stdout.buffer.write(b"x" * 65536)\nsys.stderr.buffer.write(b"x" * 65536)'),
                         bv._ProcessResult(0, 65536, 65536))

    def test_process_group_killed_before_reaping_even_success(self):
        events = []
        killpg, wait = os.killpg, subprocess.Popen.wait
        def kill(pid, sig):
            events.append(('kill', pid, sig))
            return killpg(pid, sig)
        def reap(child, *args, **kwargs):
            events.append(('wait', child.pid))
            return wait(child, *args, **kwargs)
        with patch.object(os, 'killpg', side_effect=kill), patch.object(subprocess.Popen, 'wait', new=reap):
            self.run_fake('pass')
        self.assertEqual(events[0][0], 'kill')
        self.assertEqual(events[0][2], signal.SIGKILL)
        self.assertEqual(events[1], ('wait', events[0][1]))

    def test_process_cleanup_failure_propagates(self):
        original = os.killpg
        def kill_then_fail(pid, sig):
            original(pid, sig)
            raise OSError('group cleanup failure')
        with patch.object(os, 'killpg', side_effect=kill_then_fail), self.assertRaises(OSError):
            self.run_fake('pass')

    def test_descendant_cannot_keep_private_descriptor_after_completion(self):
        body = '''import os, sys, time
sys.stdin.buffer.read()
pid = os.fork()
if pid == 0:
    os.close(1); os.close(2)
    while True:
        time.sleep(1)
else:
    open(os.environ['HOME'] + '/descendant.pid', 'w').write(str(pid))
'''
        executable, home, docker, fds = self.fixture(body)
        bv._CosignProcess().run((bv.COSIGN_PATH, 'verify'), b'', executable=executable,
            descriptors=fds, home=home, docker_config=docker)
        pid = int(Path(home, 'descendant.pid').read_text())
        for _ in range(100):
            try:
                state = Path('/proc/' + str(pid) + '/stat').read_text().split()[2]
            except FileNotFoundError:
                return
            if state == 'Z':
                return
            time.sleep(0.01)
        self.fail('descendant survived process-group cleanup')


class AuthorityTests(unittest.TestCase):
    def test_fixed_runtime_and_no_production_mutation_or_runtime_network_lookup(self):
        self.assertEqual(ov._RUNTIME_DIRECTORY, '/run/omnilyzer/deployment/dev/oci-verifier')
        source = Path(ov.__file__).read_text()
        calls = {node.func.attr for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {'getenv', 'system', 'replace', 'chown', 'getgrnam', 'getpwnam', 'urlopen'})
        self.assertNotIn('__main__', source)
        self.assertNotIn('time.time', source)
        self.assertNotIn('cosign initialize', source)
        self.assertNotIn('dev.json', source)

    def test_import_is_inert(self):
        source = Path(ov.__file__).read_text()
        namespace = {'__name__': ov.__name__, '__package__': 'deployment'}
        with patch.object(os, 'open', side_effect=AssertionError), \
             patch.object(builtins, 'open', side_effect=AssertionError), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError):
            exec(compile(source, ov.__file__, 'exec'), namespace)

    def test_closed_command_source_no_unsafe_flags(self):
        source = Path(ov.__file__).read_text()
        for flag in ('--registry-token', '--registry-password', '--registry-username', '--key',
            '--certificate-identity-regexp', '--certificate-oidc-issuer-regexp', '--insecure-ignore-tlog',
            '--insecure-ignore-sct', '--allow-insecure-registry', '--allow-http-registry', '--registry-cacert',
            '--registry-client-cert', '--registry-client-key', '--registry-server-name', '--signature',
            '--payload', '--local-image', '--k8s-keychain'):
            self.assertNotIn(flag, source)

    def test_chain_rejects_named_directory_substitution_and_metadata_change(self):
        def status(ino, mode=0o755):
            return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_ino=ino, st_dev=1,
                st_nlink=1, st_uid=0, st_gid=0, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
        with patch.object(os, 'fstat', side_effect=lambda fd: status(fd)):
            chain = ov._chain([10, 11], '/run')
            with patch.object(os, 'stat', return_value=status(11)):
                ov._revalidate_chain(chain)
            with patch.object(os, 'stat', return_value=status(12)), self.assertRaises(OSError):
                ov._revalidate_chain(chain)
            with patch.object(os, 'stat', return_value=status(11, 0o777)), self.assertRaises(OSError):
                ov._revalidate_chain(chain)

    def test_source_set_and_historical_generations_unchanged(self):
        from deployment.application_source_set import DevApplicationSourceSet
        from deployment import application_manifest, dev_post_c31_application_update as update
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 41)
        self.assertIn('deployment/oci_verifier.py', paths)
        self.assertIn('deployment/blob_verifier.py', paths)
        self.assertEqual((len(application_manifest._predecessor_paths()), len(application_manifest._paths())), (28, 31))
        self.assertEqual(update.PREDECESSOR, '3ef02a6d61d20df3a1495b290c20807162b65b06')
        self.assertEqual(update.TARGET, 'c04e66008cff556315603a9de59dacb4679787d4')
        self.assertIs(json.loads((ROOT / 'deployment/environments/dev.json').read_text())['activation']['deployment_enabled'], False)


if __name__ == '__main__':
    unittest.main()
