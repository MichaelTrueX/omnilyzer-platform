"""C32K deterministic staged-identity tests; no real executable acquisition."""

import ast
import builtins
from contextlib import ExitStack, contextmanager
from dataclasses import fields, FrozenInstanceError, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request

from deployment import sigstore_toolchain_qualification as q
from deployment.broker_service_config import COSIGN_BINARY_SIZE, COSIGN_VERSION
from deployment.sigstore_authority_provenance import DevSigstoreVerificationProvenance
from deployment.application_source_set import DevApplicationSourceSet
from deployment import application_manifest, dev_post_c31_application_update

ROOT = Path(__file__).resolve().parents[2]
ERROR = 'DEV Sigstore toolchain qualification is unavailable'
MODEL_ERROR = 'DEV Sigstore toolchain qualification evidence is invalid'
REVIEWED = DevSigstoreVerificationProvenance()
BINARY = REVIEWED.cosign.asset_name
TRUSTED_ROOT = REVIEWED.trusted_root.retained_target_path.rsplit('/', 1)[1]
ROOT_BYTES = (ROOT / REVIEWED.trusted_root.retained_target_path).read_bytes()
PAYLOAD = b'synthetic binary data\0' * 10000


def status_changed(value, **changes):
    values = list(value)
    names = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid', 'st_size')
    for index, name in enumerate(names):
        values[index] = changes.get(name, values[index])
    extra = {name: changes.get(name, getattr(value, name))
             for name in ('st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')}
    return os.stat_result(values, extra)


class QualificationTests(unittest.TestCase):
    @contextmanager
    def staged(self, *, synthetic=True, mode=0o600):
        with tempfile.TemporaryDirectory() as parent, ExitStack() as stack:
            root = Path(parent) / 'sigstore'
            root.mkdir(mode=0o700)
            (root / BINARY).write_bytes(PAYLOAD)
            (root / TRUSTED_ROOT).write_bytes(ROOT_BYTES)
            for path in root.iterdir():
                path.chmod(mode)
            if synthetic:
                # Only private test authority changes; public inputs remain closed.
                reviewed = SimpleNamespace(
                    cosign=SimpleNamespace(asset_name=BINARY, asset_size=len(PAYLOAD),
                                           asset_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
                                           version=COSIGN_VERSION),
                    trusted_root=REVIEWED.trusted_root,
                )
                stack.enter_context(patch.object(q, '_reviewed', return_value=reviewed))
            yield root

    def qualify(self, root):
        return q.qualify_dev_sigstore_toolchain(staging_directory=str(root))

    def reject(self, root):
        with self.assertRaises(q.SigstoreToolchainQualificationError) as caught:
            q.qualify_dev_sigstore_toolchain(staging_directory=root)
        self.assertEqual(str(caught.exception), ERROR)
        self.assertIsNone(caught.exception.__cause__)

    @contextmanager
    def production_metadata(self, root, *, size=COSIGN_BINARY_SIZE, field=None, value=None):
        inode = (root / BINARY).stat().st_ino
        original_stat, original_fstat = os.stat, os.fstat
        def adjusted(result):
            if result.st_ino == inode and stat.S_ISREG(result.st_mode):
                changes = {'st_size': size}
                if field is not None:
                    changes[field] = value
                return status_changed(result, **changes)
            return result
        with patch.object(q._os, 'stat', side_effect=lambda *a, **kw: adjusted(original_stat(*a, **kw))), \
             patch.object(q._os, 'fstat', side_effect=lambda *a: adjusted(original_fstat(*a))):
            yield

    def test_public_surface_and_only_directory_input(self):
        self.assertEqual(q.__all__, ('SigstoreToolchainQualificationError',
                                    'SigstoreToolchainFileEvidence', 'DevSigstoreToolchainEvidence',
                                    'qualify_dev_sigstore_toolchain'))
        self.assertEqual({name for name in vars(q) if not name.startswith('_')}, set(q.__all__))
        params = tuple(inspect.signature(q.qualify_dev_sigstore_toolchain).parameters.values())
        self.assertEqual(tuple(p.name for p in params), ('staging_directory',))
        self.assertIs(params[0].kind, inspect.Parameter.KEYWORD_ONLY)
        for name in ('cosign_path', 'trusted_root_path', 'filename', 'expected_size',
                     'expected_sha256', 'owner_uid', 'url'):
            with self.assertRaises(TypeError):
                q.qualify_dev_sigstore_toolchain(staging_directory='/stage', **{name: 'caller'})

    def test_exact_closed_artifacts_and_provenance_cross_check(self):
        self.assertEqual(q._artifacts(), (
            ('cosign-linux-amd64', 141150460,
             'f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf'),
            ('sigstore-public-good-trusted-root.json', 6787,
             '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66'),
        ))
        self.assertEqual(q._reviewed(), REVIEWED)
        self.assertEqual(q._BINARY_SIZE, REVIEWED.cosign.asset_size)
        self.assertEqual(q._VERSION, REVIEWED.cosign.version)
        self.assertEqual((len(ROOT_BYTES), hashlib.sha256(ROOT_BYTES).hexdigest()),
                         (REVIEWED.trusted_root.target_size, REVIEWED.trusted_root.target_sha256))

    def test_drifted_code_authority_fails_before_io(self):
        for name, attack in (('_BINARY_SIZE', True), ('_BINARY_SIZE', 141150461),
                             ('_VERSION', 'latest')):
            with self.subTest(name=name), patch.object(q, name, attack), \
                 patch.object(q._os, 'open') as opened:
                self.reject('/stage')
                opened.assert_not_called()

    def test_import_and_evidence_revalidation_are_inert(self):
        with self.staged() as root:
            evidence = self.qualify(root)
        code = compile(Path(q.__file__).read_text(), q.__file__, 'exec')
        with ExitStack() as stack:
            for owner, name in ((builtins, 'open'), (os, 'open'), (os, 'stat'), (os, 'read'),
                                (socket, 'socket'), (subprocess, 'Popen'), (hashlib, 'sha256')):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
            exec(code, {'__name__': q.__name__, '__package__': 'deployment'})
            # Revalidate under the same explicit synthetic authority; no I/O.
            synthetic = SimpleNamespace(cosign=SimpleNamespace(
                asset_name=BINARY, asset_size=len(PAYLOAD), asset_sha256=evidence.cosign.sha256,
                version=COSIGN_VERSION), trusted_root=REVIEWED.trusted_root)
            with patch.object(q, '_reviewed', return_value=synthetic):
                evidence.__post_init__()

    def test_real_synthetic_streaming_success_and_no_mutation(self):
        with self.staged() as root:
            before = {p.name: (p.read_bytes(), q._fingerprint(p.stat())) for p in root.iterdir()}
            original_read = os.read
            calls = []
            def bounded(descriptor, size):
                self.assertLessEqual(size, 65536)
                calls.append((descriptor, size))
                return original_read(descriptor, size)
            with patch.object(q._os, 'read', side_effect=bounded):
                evidence = self.qualify(root)
            after = {p.name: (p.read_bytes(), q._fingerprint(p.stat())) for p in root.iterdir()}
            self.assertEqual(before, after)
            self.assertEqual(evidence.staging_directory, str(root))
            self.assertEqual((evidence.staging_uid, evidence.staging_gid), (os.getuid(), os.getgid()))
            self.assertEqual(evidence.cosign.sha256, hashlib.sha256(PAYLOAD).hexdigest())
            self.assertEqual(evidence.trusted_root.sha256, REVIEWED.trusted_root.target_sha256)
            self.assertEqual(sum(size == 1 for _, size in calls), 2)
            self.assertGreater(len(calls), 4)
            for descriptor, _ in calls:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_qualification_ignores_environment_and_never_executes_or_mutates(self):
        with self.staged() as root, ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {
                'SIGSTORE_STAGING_DIRECTORY': '/untrusted', 'COSIGN_BINARY_SIZE': '1',
                'TUF_ROOT': '/untrusted', 'TUF_MIRROR': 'https://untrusted.invalid',
            }))
            for owner, name in ((builtins, 'open'), (socket, 'socket'), (subprocess, 'Popen'),
                                (subprocess, 'run'), (urllib.request, 'urlopen'),
                                (os, 'write'), (os, 'chmod'), (os, 'chown'), (os, 'mkdir'),
                                (os, 'unlink'), (os, 'rename')):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
            self.assertEqual(self.qualify(root).staging_directory, str(root))

    def test_read_only_files_are_valid_staging(self):
        with self.staged(mode=0o400) as root:
            self.assertEqual(self.qualify(root).cosign.size, len(PAYLOAD))

    def test_production_metadata_accepted_without_binary_allocation(self):
        with self.staged(synthetic=False) as root, self.production_metadata(root), \
             patch.object(q, '_hash_file', side_effect=[REVIEWED.cosign.asset_sha256,
                                                      REVIEWED.trusted_root.target_sha256]) as hash_file:
            evidence = self.qualify(root)
        self.assertEqual(evidence.cosign.size, 141150460)
        self.assertEqual([c.args[1] for c in hash_file.call_args_list], [141150460, 6787])

    def test_wrong_production_binary_sizes_rejected_before_hashing(self):
        for size in (0, 1, 141150459, 141150461, 134217728, 2**63 - 1):
            with self.subTest(size=size), self.staged(synthetic=False) as root, \
                 self.production_metadata(root, size=size), patch.object(q, '_hash_file') as hash_file:
                self.reject(str(root))
                hash_file.assert_not_called()

    def test_malformed_bool_noninteger_stat_metadata_rejected(self):
        class Integer(int):
            pass
        for field, value in (('st_size', True), ('st_size', 141150460.0),
                             ('st_size', '141150460'), ('st_size', Integer(141150460)),
                             ('st_uid', True), ('st_nlink', 1.0), ('st_mtime_ns', None)):
            with self.subTest(field=field, value=value), self.staged(synthetic=False) as root, \
                 self.production_metadata(root, field=field, value=value), \
                 patch.object(q, '_hash_file') as hash_file:
                self.reject(str(root))
                hash_file.assert_not_called()
        for fake in (None, (), SimpleNamespace(st_size=141150460)):
            with self.subTest(fake=fake), self.assertRaises(OSError):
                q._fingerprint(fake)

    def test_wrong_digest_for_each_file_rejected(self):
        for filename in (BINARY, TRUSTED_ROOT):
            with self.subTest(filename=filename), self.staged() as root:
                path = root / filename
                raw = path.read_bytes()
                path.write_bytes(b'x' + raw[1:])
                self.reject(str(root))

    def test_wrong_root_size_before_its_hash(self):
        for size in (0, 6786, 6788):
            with self.subTest(size=size), self.staged() as root:
                (root / TRUSTED_ROOT).write_bytes(b'x' * size)
                original = q._hash_file
                with patch.object(q, '_hash_file', wraps=original) as hash_file:
                    self.reject(str(root))
                self.assertEqual(hash_file.call_count, 1)

    def test_closed_entry_set_missing_renamed_extra_nested_rejected(self):
        for kind in ('missing', 'rename', 'extra', 'nested', 'bundle'):
            with self.subTest(kind=kind), self.staged() as root:
                if kind == 'missing':
                    (root / BINARY).unlink()
                elif kind == 'rename':
                    (root / BINARY).rename(root / 'other')
                elif kind == 'nested':
                    (root / 'nested').mkdir()
                else:
                    (root / ('bundle.sigstore.json' if kind == 'bundle' else 'extra')).write_bytes(b'x')
                with patch.object(q, '_hash_file') as hash_file:
                    self.reject(str(root))
                    hash_file.assert_not_called()

    def test_symlink_hardlink_fifo_directory_rejected_for_each_file(self):
        for filename in (BINARY, TRUSTED_ROOT):
            for kind in ('symlink', 'hardlink', 'fifo', 'directory'):
                with self.subTest(filename=filename, kind=kind), self.staged() as root:
                    path = root / filename
                    if kind == 'hardlink':
                        os.link(path, root.parent / 'hardlink')
                    else:
                        path.unlink()
                        if kind == 'symlink':
                            path.symlink_to(root.parent / 'missing')
                        elif kind == 'fifo':
                            os.mkfifo(path)
                        else:
                            path.mkdir()
                    self.reject(str(root))

    def test_unsafe_file_modes_and_staging_directory_mode_rejected(self):
        for filename in (BINARY, TRUSTED_ROOT):
            for mode in (0o644, 0o660, 0o666, 0o700, 0o755, 0o4600):
                with self.subTest(filename=filename, mode=mode), self.staged() as root:
                    (root / filename).chmod(mode)
                    self.reject(str(root))
        for mode in (0o750, 0o755, 0o777, 0o1700, 0o2700):
            with self.subTest(mode=mode), self.staged() as root:
                root.chmod(mode)
                self.reject(str(root))

    def test_wrong_file_and_staging_owners_or_groups_rejected(self):
        for target in ('directory', BINARY, TRUSTED_ROOT):
            for field in ('st_uid', 'st_gid'):
                with self.subTest(target=target, field=field), self.staged() as root:
                    inode = (root if target == 'directory' else root / target).stat().st_ino
                    original_stat, original_fstat = os.stat, os.fstat
                    def adjusted(value):
                        return status_changed(value, **{field: getattr(value, field) + 1}) if value.st_ino == inode else value
                    with patch.object(q._os, 'stat', side_effect=lambda *a, **kw: adjusted(original_stat(*a, **kw))), \
                         patch.object(q._os, 'fstat', side_effect=lambda *a: adjusted(original_fstat(*a))):
                        self.reject(str(root))

    def test_ancestor_policy_and_symlink_components(self):
        with self.staged() as root:
            self.assertEqual(self.qualify(root).staging_uid, os.getuid())  # root-owned sticky /tmp accepted
            alias = root.parent / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            self.reject(str(alias))
            parent_alias = root.parent.parent / (root.parent.name + '-alias')
            parent_alias.symlink_to(root.parent, target_is_directory=True)
            try:
                self.reject(str(parent_alias / root.name))
            finally:
                parent_alias.unlink()
        with self.staged() as root:
            root.parent.chmod(0o777)
            self.reject(str(root))
        with self.staged() as root:
            inode = root.parent.stat().st_ino
            real_stat = os.stat
            def foreign(*args, **kwargs):
                result = real_stat(*args, **kwargs)
                return status_changed(result, st_uid=os.getuid() + 1) if result.st_ino == inode else result
            with patch.object(q._os, 'stat', side_effect=foreign):
                self.reject(str(root))

    def test_named_open_file_and_directory_substitution(self):
        for target in (BINARY, 'directory', '/'):
            with self.subTest(target=target), self.staged() as root:
                inode = (root / BINARY if target == BINARY else root if target == 'directory' else Path('/')).stat().st_ino
                real_fstat = os.fstat
                def substituted(fd):
                    result = real_fstat(fd)
                    return status_changed(result, st_ino=inode + 1) if result.st_ino == inode else result
                with patch.object(q._os, 'fstat', side_effect=substituted), \
                     patch.object(q, '_hash_file') as hash_file:
                    self.reject(str(root))
                    hash_file.assert_not_called()

    def test_in_place_mutation_while_reading(self):
        for filename in (BINARY, TRUSTED_ROOT):
            with self.subTest(filename=filename), self.staged() as root:
                real_hash = q._hash_file
                def mutate_after_hash(fd, size):
                    digest = real_hash(fd, size)
                    if os.fstat(fd).st_ino == (root / filename).stat().st_ino:
                        with (root / filename).open('r+b') as stream:
                            stream.write(b'changed')
                    return digest
                with patch.object(q, '_hash_file', side_effect=mutate_after_hash):
                    self.reject(str(root))

    def test_first_file_mutation_during_second_hash_is_detected(self):
        with self.staged() as root:
            real_hash = q._hash_file
            def mutate_first(fd, size):
                digest = real_hash(fd, size)
                if size == len(ROOT_BYTES):
                    with (root / BINARY).open('r+b') as stream:
                        stream.write(b'changed')
                return digest
            with patch.object(q, '_hash_file', side_effect=mutate_first):
                self.reject(str(root))

    def test_path_replacement_after_hash(self):
        for target in ('file', 'directory'):
            with self.subTest(target=target), self.staged() as root:
                real_hash = q._hash_file
                calls = 0
                def substitute(fd, size):
                    nonlocal calls
                    digest = real_hash(fd, size)
                    calls += 1
                    if calls == 1:
                        if target == 'file':
                            replacement = root / 'replacement'
                            replacement.write_bytes(PAYLOAD)
                            replacement.chmod(0o600)
                            os.replace(replacement, root / BINARY)
                        else:
                            root.rename(root.parent / 'renamed')
                            root.mkdir(mode=0o700)
                    return digest
                with patch.object(q, '_hash_file', side_effect=substitute):
                    self.reject(str(root))

    def test_identity_policy_and_post_read_identity_revalidation(self):
        for name, value in (('getuid', 0), ('geteuid', os.getuid() + 1),
                            ('getgid', True), ('getegid', os.getgid() + 1)):
            with self.subTest(name=name), self.staged() as root, patch.object(q._os, name, return_value=value):
                self.reject(str(root))
        with self.staged() as root, patch.object(q, '_identity', side_effect=[(os.getuid(), os.getgid()),
                                                                           (os.getuid() + 1, os.getgid())]):
            self.reject(str(root))

    def test_canonical_path_validation_before_io(self):
        class Text(str):
            pass
        for path in (None, True, Path('/stage'), '', '/', 'relative', '//stage', '/a//b',
                     '/a/../b', '/a/./b', '/a/', '/a\\b', '/a\0b', 'https://example.com', Text('/stage')):
            with self.subTest(path=path), patch.object(q._os, 'open') as opened:
                self.reject(path)
                opened.assert_not_called()

    def test_read_flags_and_deterministic_descriptor_cleanup(self):
        for failed in (False, True):
            with self.subTest(failed=failed), self.staged() as root:
                real_open, real_close = os.open, os.close
                opened, closed = [], []
                def capture(path, flags, **kwargs):
                    self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
                    self.assertTrue(flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC)
                    self.assertNotIn(path, (str(root / BINARY), str(root / TRUSTED_ROOT)))
                    if path != '/':
                        self.assertIs(type(kwargs['dir_fd']), int)
                    fd = real_open(path, flags, **kwargs)
                    self.assertFalse(os.get_inheritable(fd))
                    opened.append(fd)
                    return fd
                def close(fd):
                    closed.append(fd)
                    return real_close(fd)
                with patch.object(q._os, 'open', side_effect=capture), \
                     patch.object(q._os, 'close', side_effect=close):
                    if failed:
                        with patch.object(q, '_hash_file', side_effect=OSError('private file diagnostic')):
                            self.reject(str(root))
                    else:
                        self.qualify(root)
                self.assertEqual(closed, list(reversed(opened)))

    def test_cleanup_failure_fails_closed_and_all_descriptors_attempted(self):
        for failure in ('raise', 'return'):
            with self.subTest(failure=failure), self.staged() as root:
                real_close = os.close
                closed = []
                def close(fd):
                    closed.append(fd)
                    real_close(fd)
                    if len(closed) == 1:
                        if failure == 'raise':
                            raise OSError('private cleanup diagnostic')
                        return 1
                with patch.object(q._os, 'close', side_effect=close):
                    self.reject(str(root))
                self.assertGreater(len(closed), 3)

    def test_control_exceptions_clean_up_and_propagate(self):
        for kind in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(kind=kind), self.staged() as root:
                real_close = os.close
                with patch.object(q, '_hash_file', side_effect=kind), \
                     patch.object(q._os, 'close', wraps=real_close) as closed:
                    with self.assertRaises(kind):
                        self.qualify(root)
                    self.assertGreater(closed.call_count, 3)
        with self.staged() as root:
            real_close = os.close
            calls = []
            def cleanup_control(fd):
                real_close(fd)
                calls.append(fd)
                if len(calls) == 1:
                    raise KeyboardInterrupt
            with patch.object(q._os, 'close', side_effect=cleanup_control), self.assertRaises(KeyboardInterrupt):
                self.qualify(root)
            self.assertGreater(len(calls), 3)

    def test_evidence_immutable_narrow_and_forged_values_fail_revalidation(self):
        with self.staged() as root:
            evidence = self.qualify(root)
            for value in (evidence, evidence.cosign, evidence.trusted_root):
                self.assertFalse(hasattr(value, '__dict__'))
                for field in fields(value):
                    with self.assertRaises(FrozenInstanceError):
                        setattr(value, field.name, None)
                    with self.assertRaises(FrozenInstanceError):
                        delattr(value, field.name)
            for changes in ({'staging_directory': 'relative'}, {'staging_uid': True},
                            {'staging_gid': 0}, {'directory_fingerprint': ()},
                            {'cosign_version': 'latest'}, {'cosign': object()},
                            {'trusted_root': evidence.cosign}):
                with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, MODEL_ERROR):
                    replace(evidence, **changes)
            for changes in ({'filename': 'other'}, {'size': True}, {'size': len(PAYLOAD) + 1},
                            {'sha256': '0' * 64}, {'fingerprint': ()}):
                with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, MODEL_ERROR):
                    replace(evidence.cosign, **changes)
            forged = object.__new__(type(evidence))
            for field in fields(evidence):
                object.__setattr__(forged, field.name, getattr(evidence, field.name))
            object.__setattr__(forged, 'staging_uid', os.getuid() + 1)
            with self.assertRaisesRegex(ValueError, MODEL_ERROR):
                forged.__post_init__()
            self.assertEqual(set(field.name for field in fields(evidence.cosign)),
                             {'filename', 'size', 'sha256', 'fingerprint'})


class HashTests(unittest.TestCase):
    def test_streaming_real_bytes_exact_eof_and_short_reads(self):
        raw = b'x' * (65536 * 2 + 11)
        with tempfile.TemporaryFile() as stream:
            stream.write(raw)
            stream.seek(0)
            real_read = os.read
            calls = []
            def partial(fd, maximum):
                self.assertLessEqual(maximum, 65536)
                calls.append(maximum)
                return real_read(fd, min(maximum, 4096))
            with patch.object(q._os, 'read', side_effect=partial):
                self.assertEqual(q._hash_file(stream.fileno(), len(raw)), hashlib.sha256(raw).hexdigest())
            self.assertEqual(calls[-1], 1)
            for size in (len(raw) - 1, len(raw) + 1):
                stream.seek(0)
                with self.assertRaises(OSError):
                    q._hash_file(stream.fileno(), size)

    def test_unexpected_read_types_sizes_and_exact_typed_eof(self):
        for chunks in ([b''], [None], [bytearray(b'x')], [b'xx'],
                       [b'x', b'x'], [b'x', bytearray()], [b'x', None]):
            with self.subTest(chunks=chunks), patch.object(q._os, 'read', side_effect=chunks), \
                 self.assertRaises(OSError):
                q._hash_file(1, 1)
        for size in (True, 0, -1, 1.0, None):
            with self.subTest(size=size), patch.object(q._os, 'read') as read, self.assertRaises(OSError):
                q._hash_file(1, size)
            read.assert_not_called()

    def test_production_size_stream_without_production_size_allocation(self):
        remaining = COSIGN_BINARY_SIZE
        calls = []
        expected = hashlib.sha256()
        def production_stream(fd, maximum):
            nonlocal remaining
            self.assertLessEqual(maximum, 65536)
            calls.append(maximum)
            chunk = b'x' * min(remaining, maximum)
            expected.update(chunk)
            remaining -= len(chunk)
            return chunk
        with patch.object(q._os, 'read', side_effect=production_stream):
            self.assertEqual(q._hash_file(1, COSIGN_BINARY_SIZE), expected.hexdigest())
        self.assertEqual(remaining, 0)
        self.assertEqual(calls[-1], 1)
        self.assertGreater(len(calls), 2000)


class SeparationTests(unittest.TestCase):
    def test_no_network_environment_execution_or_host_mutation(self):
        source = Path(q.__file__).read_text()
        tree = ast.parse(source)
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports |= {item.name for node in ast.walk(tree) if isinstance(node, ast.Import) for item in node.names}
        self.assertEqual(imports, {'dataclasses', 'hashlib', 'os', 'stat', None,
                                   'broker_service_config', 'sigstore_authority_provenance'})
        operations = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertTrue(operations.isdisjoint({'write', 'read_bytes', 'chmod', 'chown', 'mkdir',
                                              'unlink', 'replace', 'environ', 'getenv', 'Popen',
                                              'run', 'urlopen', 'sha1'}))
        for forbidden in ('TUF_MIRROR', 'TUF_ROOT', 'cosign initialize', 'expected_workflow_sha',
                          'latest', 'PRIVATE KEY', 'Bearer ', 'password', 'session_token'):
            self.assertNotIn(forbidden, source)

    def test_installed_sources_historical_generations_and_activation_unchanged(self):
        paths = {item.repository_path for item in DevApplicationSourceSet().files}
        self.assertEqual(len(paths), 41)
        self.assertNotIn('deployment/sigstore_toolchain_qualification.py', paths)
        self.assertEqual((len(application_manifest._predecessor_paths()), len(application_manifest._paths())), (28, 31))
        self.assertEqual(dev_post_c31_application_update.PREDECESSOR, '3ef02a6d61d20df3a1495b290c20807162b65b06')
        self.assertEqual(dev_post_c31_application_update.TARGET, 'c04e66008cff556315603a9de59dacb4679787d4')
        self.assertIs(json.loads((ROOT / 'deployment/environments/dev.json').read_bytes())
                      ['activation']['deployment_enabled'], False)


if __name__ == '__main__':
    unittest.main()
