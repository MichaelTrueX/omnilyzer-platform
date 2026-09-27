"""C32M sandbox/mocked-root tests: production paths are never mutated."""

import ast
import builtins
from contextlib import ExitStack, contextmanager
from dataclasses import fields, FrozenInstanceError
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

from deployment import sigstore_static_installation as installer
from deployment import broker_service_config as config
from deployment import sigstore_authority_provenance as provenance
from deployment import host_provisioning_contract as historical
from deployment.tests.test_broker_service_config import configuration_values
from deployment.tests.test_sigstore_toolchain_qualification import status_changed

ROOT = Path(__file__).resolve().parents[2]
ERROR = 'DEV Sigstore static resource installation is unavailable'
BINARY_NAME = 'cosign-linux-amd64'
ROOT_NAME = 'sigstore-public-good-trusted-root.json'
BINARY = b'synthetic executable\0' * 12000
TRUSTED_ROOT = (ROOT / provenance.DevSigstoreVerificationProvenance().trusted_root.retained_target_path).read_bytes()


def configuration():
    return config.DevBrokerServiceConfiguration(**configuration_values(
        **provenance.DevSigstoreVerificationProvenance().broker_service_configuration_kwargs()))


class Sandbox:
    def __init__(self, root):
        self.root = root
        self.stage = root / 'staging'
        self.stage.mkdir(mode=0o700)
        self.source_paths = (self.stage / BINARY_NAME, self.stage / ROOT_NAME)
        for path, raw in zip(self.source_paths, (BINARY, TRUSTED_ROOT), strict=True):
            path.write_bytes(raw)
            path.chmod(0o600)
        self.parents = (root / 'opt' / 'deployment', root / 'etc' / 'deployment')
        for path in self.parents:
            path.parent.mkdir(mode=0o755)
            path.mkdir(mode=0o755)
        self.leaves = (self.parents[0] / 'tools', self.parents[1] / 'broker')
        self.targets = (self.leaves[0] / 'cosign-v3.1.2-linux-amd64',
                        self.leaves[1] / 'sigstore-trusted-root.json')
        self.artifacts = tuple((str(path), mode, len(raw), hashlib.sha256(raw).hexdigest())
                               for path, mode, raw in zip(self.targets, (0o540, 0o640), (BINARY, TRUSTED_ROOT), strict=True))
        self.ownership = {}
        self.overrides = {}
        self.events = []
        self.opened = []
        self.original_stat, self.original_fstat = os.stat, os.fstat
        self.original_open, self.original_read = os.open, os.read
        self.original_write = os.write
        self.original_fchmod, self.original_fsync = os.fchmod, os.fsync
        self.original_mkdir, self.original_rmdir = os.mkdir, os.rmdir
        self.original_link, self.original_unlink = os.link, os.unlink
        for path in (self.stage, *self.source_paths):
            self.ownership[self.key(path)] = (3001, 3002)

    def key(self, path):
        value = self.original_stat(path, follow_symlinks=False)
        return value.st_dev, value.st_ino

    def fd_path(self, fd):
        return Path(os.readlink('/proc/self/fd/' + str(fd)))

    def status(self, value):
        key = value.st_dev, value.st_ino
        uid, gid = self.ownership.get(key, (0, 0))
        # Model protected destination ancestors even though the sandbox is /tmp.
        mode = stat.S_IFDIR | 0o755 if key == self.key('/tmp') else value.st_mode
        return status_changed(value, **(dict(st_uid=uid, st_gid=gid, st_mode=mode)
                                        | self.overrides.get(key, {})))

    def stat(self, *args, **kwargs):
        return self.status(self.original_stat(*args, **kwargs))

    def fstat(self, descriptor):
        return self.status(self.original_fstat(descriptor))

    def open(self, name, flags, *args, **kwargs):
        if flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR):
            assert 'dir_fd' in kwargs and self.fd_path(kwargs['dir_fd']).is_relative_to(self.root)
        fd = self.original_open(name, flags, *args, **kwargs)
        self.opened.append(fd)
        self.events.append(('open', str(self.fd_path(fd)), flags, fd))
        return fd

    def write(self, fd, raw):
        assert self.fd_path(fd).is_relative_to(self.root) and len(raw) <= 65536
        self.events.append(('write', fd, len(raw)))
        return self.original_write(fd, raw)

    def read(self, fd, size):
        assert 0 < size <= 65536
        self.events.append(('read', str(self.fd_path(fd)), size, fd))
        return self.original_read(fd, size)

    def chown(self, fd, uid, gid):
        assert self.fd_path(fd).is_relative_to(self.root)
        current = self.original_fstat(fd)
        self.ownership[current.st_dev, current.st_ino] = (uid, gid)
        self.events.append(('chown', uid, gid))

    def chmod(self, fd, mode):
        assert self.fd_path(fd).is_relative_to(self.root)
        self.events.append(('chmod', mode))
        return self.original_fchmod(fd, mode)

    def fsync(self, fd):
        assert self.fd_path(fd).is_relative_to(self.root)
        self.events.append(('sync', str(self.fd_path(fd))))
        return self.original_fsync(fd)

    def mutation_path(self, name, directory=None):
        path = self.fd_path(directory) / name if directory is not None else Path(name)
        assert path.is_relative_to(self.root), 'mutation escaped sandbox'
        return str(path)

    def mkdir(self, name, mode=0o777, *, dir_fd=None):
        self.events.append(('mkdir', self.mutation_path(name, dir_fd)))
        return self.original_mkdir(name, mode, dir_fd=dir_fd)

    def rmdir(self, name, *, dir_fd=None):
        self.events.append(('rmdir', self.mutation_path(name, dir_fd)))
        return self.original_rmdir(name, dir_fd=dir_fd)

    def unlink(self, name, *, dir_fd=None):
        self.events.append(('unlink', self.mutation_path(name, dir_fd)))
        return self.original_unlink(name, dir_fd=dir_fd)

    def link(self, source, destination, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):
        source_path = self.mutation_path(source, src_dir_fd)
        destination_path = self.mutation_path(destination, dst_dir_fd)
        self.events.append(('link', source_path, destination_path))
        return self.original_link(source, destination, src_dir_fd=src_dir_fd,
                                  dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks)

    def exact(self, index):
        self.leaves[index].mkdir(mode=0o750, exist_ok=True)
        self.ownership[self.key(self.leaves[index])] = (0, 1002)
        self.targets[index].write_bytes((BINARY, TRUSTED_ROOT)[index])
        self.targets[index].chmod((0o540, 0o640)[index])
        self.ownership[self.key(self.targets[index])] = (0, 1002)

    def temporary(self, index=0):
        return self.leaves[index] / installer._TEMPORARY


class InstallerTests(unittest.TestCase):
    @contextmanager
    def sandbox(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            box = Sandbox(Path(directory))
            for name, value in (
                ('COSIGN_TOOLS_DIRECTORY', str(box.leaves[0])),
                ('PRODUCTION_COSIGN_PATH', str(box.targets[0])),
                ('BROKER_SERVICE_CONFIG_DIRECTORY', str(box.leaves[1])),
                ('PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH', str(box.targets[1])),
            ):
                stack.enter_context(patch.object(config, name, value))
            stack.enter_context(patch.object(installer._resources, '_artifacts', return_value=box.artifacts))
            stack.enter_context(patch.object(installer._qualification, '_artifacts', return_value=(
                (BINARY_NAME, len(BINARY), hashlib.sha256(BINARY).hexdigest()),
                (ROOT_NAME, len(TRUSTED_ROOT), hashlib.sha256(TRUSTED_ROOT).hexdigest()))))
            # Keep the production C23 constructor out of the sandbox authority seam.
            parent_requirements = tuple(historical.HostPathRequirement(str(path), 'directory', 0o755, 0, 0,
                                        'must-exist-before-activation') for path in box.parents)
            stack.enter_context(patch.object(installer._historical, 'DevHostProvisioningContract',
                                            return_value=SimpleNamespace(path_requirements=lambda: parent_requirements)))
            for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                stack.enter_context(patch.object(os, name, return_value=0))
            for name, operation in (('stat', box.stat), ('fstat', box.fstat), ('open', box.open),
                                    ('read', box.read), ('write', box.write), ('fchown', box.chown),
                                    ('fchmod', box.chmod), ('fsync', box.fsync), ('mkdir', box.mkdir),
                                    ('rmdir', box.rmdir), ('link', box.link), ('unlink', box.unlink)):
                stack.enter_context(patch.object(os, name, side_effect=operation))
            lock = installer._orchestration._ProcessLock((), -1)
            box.acquire = stack.enter_context(patch.object(installer._orchestration, '_acquire_process_lock', return_value=lock))
            box.release = stack.enter_context(patch.object(installer._orchestration, '_release_process_lock', return_value=None))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess')))
            stack.enter_context(patch.object(subprocess, 'run', side_effect=AssertionError('subprocess')))
            stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('network')))
            yield box
            for fd in box.opened:
                with self.assertRaises(OSError):
                    box.original_fstat(fd)

    def install(self, box):
        return installer.install_dev_sigstore_static_resources(staging_directory=str(box.stage), configuration=configuration())

    def reject(self, box):
        with self.assertRaises(installer.SigstoreStaticInstallationError) as caught:
            self.install(box)
        self.assertEqual(str(caught.exception), ERROR)
        self.assertIsNone(caught.exception.__cause__)

    def test_complete_install_streams_same_descriptors_and_exact_authority(self):
        with self.sandbox() as box:
            evidence = self.install(box)
            self.assertEqual((evidence.operation, evidence.broker_gid), ('installed', 1002))
            for index, item in enumerate((evidence.cosign, evidence.trusted_root)):
                self.assertEqual(box.targets[index].read_bytes(), (BINARY, TRUSTED_ROOT)[index])
                self.assertEqual((item.path, item.size, item.sha256),
                                 (box.artifacts[index][0], box.artifacts[index][2], box.artifacts[index][3]))
                self.assertEqual(item.fingerprint[3:6], (1, 0, 1002))
                self.assertEqual(stat.S_IMODE(item.fingerprint[0]), (0o540, 0o640)[index])
                self.assertFalse(box.temporary(index).exists())
                opens = [event for event in box.events if event[:2] == ('open', str(box.source_paths[index]))]
                self.assertEqual(len(opens), 1)
                reads = [event for event in box.events if event[:2] == ('read', str(box.source_paths[index]))]
                self.assertGreater(len(reads), 2)
                self.assertEqual({event[3] for event in reads}, {opens[0][3]})
                flags = opens[0][2]
                self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            self.assertIn(('chown', 0, 1002), box.events)
            self.assertIn(('chmod', 0o540), box.events)
            self.assertIn(('chmod', 0o640), box.events)
            box.acquire.assert_called_once_with()
            box.release.assert_called_once()
            self.assertFalse(any(box.root.rglob('dev.json')))

    def test_exact_prefix_resumes_and_complete_state_has_no_writes(self):
        for complete in (False, True):
            with self.subTest(complete=complete), self.sandbox() as box:
                box.exact(0)
                original = box.key(box.targets[0])
                if complete:
                    box.exact(1)
                box.events.clear()
                evidence = self.install(box)
                self.assertEqual(evidence.operation, 'already-installed' if complete else 'installed')
                self.assertEqual(box.key(box.targets[0]), original)
                if complete:
                    self.assertFalse(any(event[0] in ('write', 'chmod', 'chown', 'link', 'unlink', 'mkdir', 'rmdir')
                                         for event in box.events))

    def test_out_of_order_exact_root_rejected_before_mutation(self):
        with self.sandbox() as box:
            box.exact(1)
            self.reject(box)
            self.assertFalse(box.leaves[0].exists())
            self.assertFalse(any(event[0] in ('write', 'chmod', 'chown') for event in box.events))

    def test_both_destinations_preflight_before_any_publication(self):
        with self.sandbox() as box:
            box.exact(1)
            box.targets[1].chmod(0o644)
            self.reject(box)
            self.assertFalse(box.leaves[0].exists())

    def test_root_identity_exact_builtins_before_io_or_lock(self):
        for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
            for bad in (1, True, False, 0.0, '0', None):
                with self.subTest(name=name, bad=bad), self.sandbox() as box:
                    with patch.object(os, name, return_value=bad):
                        self.reject(box)
                    box.acquire.assert_not_called()
                    self.assertEqual(box.opened, [])

    def test_lock_acquisition_and_release_fail_closed(self):
        with self.sandbox() as box:
            box.acquire.side_effect = BlockingIOError('private lock details')
            self.reject(box)
            self.assertEqual(box.opened, [])
            box.release.assert_not_called()
        with self.sandbox() as box:
            box.release.side_effect = OSError('private unlock details')
            self.reject(box)
            self.assertTrue(all(path.exists() for path in box.targets))

    def test_staging_only_two_names_and_no_evidence_input(self):
        with self.sandbox() as box:
            (box.stage / 'extra').write_bytes(b'extra')
            self.reject(box)
            self.assertFalse(any(path.exists() for path in box.leaves))
        with self.sandbox() as box:
            evidence = object.__new__(installer._qualification.DevSigstoreToolchainEvidence)
            with self.assertRaises(installer.SigstoreStaticInstallationError):
                installer.install_dev_sigstore_static_resources(staging_directory=evidence, configuration=configuration())
            box.acquire.assert_not_called()

    def test_source_metadata_rejects_wrong_owner_mode_links_size_and_type(self):
        changes = ({'st_uid': 0}, {'st_gid': 0}, {'st_uid': 9000}, {'st_gid': 9000},
                   {'st_mode': stat.S_IFREG | 0o644}, {'st_mode': stat.S_IFREG | 0o540},
                   {'st_mode': stat.S_IFDIR | 0o600}, {'st_mode': stat.S_IFLNK | 0o600},
                   {'st_nlink': 2}, {'st_size': 0}, {'st_size': len(BINARY)-1},
                   {'st_size': len(BINARY)+1}, {'st_size': 134217728}, {'st_size': True},
                   {'st_size': float(len(BINARY))})
        for change in changes:
            with self.subTest(change=change), self.sandbox() as box:
                box.overrides[box.key(box.source_paths[0])] = change
                self.reject(box)
                self.assertFalse(any(event[0] == 'read' for event in box.events))
                self.assertFalse(box.leaves[0].exists())

    def test_source_stage_and_ancestor_ownership_permissions(self):
        for change in ({'st_uid': 0}, {'st_gid': 0}, {'st_mode': stat.S_IFDIR | 0o750}):
            with self.subTest(change=change), self.sandbox() as box:
                box.overrides[box.key(box.stage)] = change
                self.reject(box)
        for change in ({'st_uid': 9000}, {'st_mode': stat.S_IFDIR | 0o777}):
            with self.subTest(change=change), self.sandbox() as box:
                box.overrides[box.key(box.root)] = change
                self.reject(box)
        with self.sandbox() as box:
            box.ownership[box.key(box.root)] = (3001, 9000)
            owned = []
            try:
                model = installer._resources.DevSigstoreResourceContract(configuration=configuration())
                installer._source(str(box.stage), model.file_requirements(), owned)
            finally:
                installer._mechanics._close(owned)

    def test_symlink_stage_component_and_file_hardlink_rejected(self):
        for kind in ('component', 'file', 'hardlink'):
            with self.subTest(kind=kind), self.sandbox() as box:
                if kind == 'component':
                    real = box.stage.with_name('actual-stage')
                    box.stage.rename(real)
                    box.stage.symlink_to(real, target_is_directory=True)
                elif kind == 'file':
                    box.source_paths[0].unlink()
                    box.source_paths[0].symlink_to(box.source_paths[1])
                else:
                    os.link(box.source_paths[0], box.root / 'extra-link')
                self.reject(box)
                self.assertFalse(box.leaves[0].exists())

    def test_both_source_digests_required_before_mutation(self):
        for index in range(2):
            with self.subTest(index=index), self.sandbox() as box:
                path = box.source_paths[index]
                raw = path.read_bytes()
                path.write_bytes(b'x' + raw[1:])
                self.reject(box)
                self.assertFalse(box.leaves[0].exists())

    def test_unexpected_leaf_metadata_is_never_repaired(self):
        for index in range(2):
            for change in ({'st_uid': 9000}, {'st_gid': 0}, {'st_mode': stat.S_IFDIR | 0o755}):
                with self.subTest(index=index, change=change), self.sandbox() as box:
                    box.exact(index)
                    box.overrides[box.key(box.leaves[index])] = change
                    self.reject(box)
                    self.assertFalse(any(event[0] in ('write', 'chmod', 'chown') for event in box.events))

    def test_parent_exact_root_root_0755_required_and_not_created(self):
        for change in ({'st_uid': 9000}, {'st_gid': 1002}, {'st_mode': stat.S_IFDIR | 0o700},
                       {'st_mode': stat.S_IFDIR | 0o775}):
            with self.subTest(change=change), self.sandbox() as box:
                box.overrides[box.key(box.parents[0])] = change
                self.reject(box)
                self.assertFalse(box.leaves[0].exists())
        with self.sandbox() as box:
            box.parents[0].rmdir()
            self.reject(box)
            self.assertFalse(box.parents[0].exists())

    def test_unexpected_existing_file_never_overwritten(self):
        for change in ({'st_uid': 9000}, {'st_gid': 0}, {'st_mode': stat.S_IFREG | 0o550},
                       {'st_nlink': 2}, {'st_size': len(BINARY)-1}, {'st_mode': stat.S_IFLNK | 0o540}):
            with self.subTest(change=change), self.sandbox() as box:
                box.exact(0)
                inode = box.key(box.targets[0])
                box.overrides[inode] = change
                self.reject(box)
                self.assertEqual(box.key(box.targets[0]), inode)
                self.assertFalse(any(event[0] in ('write', 'chmod', 'chown') for event in box.events))
        with self.sandbox() as box:
            box.exact(0)
            box.targets[0].chmod(0o600)
            box.targets[0].write_bytes(b'x' + BINARY[1:])
            box.targets[0].chmod(0o540)
            self.reject(box)

    def test_preexisting_temporary_residue_fails_closed_even_complete(self):
        with self.sandbox() as box:
            box.exact(0)
            box.exact(1)
            box.temporary().write_bytes(b'unknown residue')
            self.reject(box)
            self.assertEqual(box.temporary().read_bytes(), b'unknown residue')

    def test_publication_flags_metadata_and_durability(self):
        with self.sandbox() as box:
            original_link, original_unlink = os.link, os.unlink
            events = []
            def link(*args, **kwargs):
                events.append(('link', args, kwargs))
                return original_link(*args, **kwargs)
            def unlink(*args, **kwargs):
                events.append(('unlink', args, kwargs))
                return original_unlink(*args, **kwargs)
            with patch.object(os, 'link', side_effect=link), patch.object(os, 'unlink', side_effect=unlink), \
                 patch.object(os, 'replace', side_effect=AssertionError('overwrite')):
                self.install(box)
            for path in box.targets:
                temporary = path.parent / installer._TEMPORARY
                creation = [event for event in box.events if event[:2] == ('open', str(temporary)) and event[2] & os.O_CREAT]
                self.assertEqual(len(creation), 1)
                self.assertEqual(creation[0][2], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.assertIn(('sync', str(temporary)), box.events)
                self.assertIn(('sync', str(path.parent)), box.events)
                self.assertIn(('sync', str(path.parent.parent)), box.events)
                self.assertEqual(box.stat(path).st_nlink, 1)
            self.assertEqual([event[0] for event in events], ['link', 'unlink', 'link', 'unlink'])
            self.assertTrue(all(event[2]['follow_symlinks'] is False for event in events if event[0] == 'link'))

    def test_destination_bytes_independently_hashed(self):
        with self.sandbox() as box:
            def corrupt(fd, raw):
                return box.write(fd, b'x' + raw[1:])
            with patch.object(os, 'write', side_effect=corrupt):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())
            self.assertFalse(box.temporary().exists())

    def test_target_appears_at_link_is_not_overwritten(self):
        with self.sandbox() as box:
            original = os.link
            def race(*args, **kwargs):
                box.targets[0].write_bytes(b'race target')
                return original(*args, **kwargs)
            with patch.object(os, 'link', side_effect=race):
                self.reject(box)
            self.assertEqual(box.targets[0].read_bytes(), b'race target')
            self.assertFalse(box.temporary().exists())

    def test_replaced_temporary_never_blindly_removed(self):
        with self.sandbox() as box:
            original = os.link
            def substitute(*args, **kwargs):
                box.temporary().rename(box.leaves[0] / 'retained-original')
                box.temporary().write_bytes(b'replacement')
                return original(*args, **kwargs)
            with patch.object(os, 'link', side_effect=substitute):
                self.reject(box)
            self.assertEqual(box.temporary().read_bytes(), b'replacement')

    def test_final_replaced_after_link_rejected(self):
        with self.sandbox() as box:
            original = os.link
            def substitute(*args, **kwargs):
                result = original(*args, **kwargs)
                box.targets[0].unlink()
                box.targets[0].write_bytes(b'final replacement')
                return result
            with patch.object(os, 'link', side_effect=substitute):
                self.reject(box)
            self.assertEqual(box.targets[0].read_bytes(), b'final replacement')

    def test_source_mutation_during_copy_detected_and_own_temp_cleaned(self):
        with self.sandbox() as box:
            mutated = False
            def mutate(fd, raw):
                nonlocal mutated
                if not mutated:
                    mutated = True
                    box.source_paths[0].write_bytes(b'x' + BINARY[1:])
                return box.write(fd, raw)
            with patch.object(os, 'write', side_effect=mutate):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())
            self.assertFalse(box.temporary().exists())

    def test_source_path_replaced_after_qualification_held_bytes_not_substituted(self):
        with self.sandbox() as box:
            original = installer._publish
            held = []
            def race(source, fd, destination, owned):
                box.source_paths[0].rename(box.root / 'held-original')
                box.source_paths[0].write_bytes(b'x' * len(BINARY))
                os.lseek(fd, 0, os.SEEK_SET)
                held.append(box.original_read(fd, 32))
                return original(source, fd, destination, owned)
            with patch.object(installer, '_publish', side_effect=race):
                self.reject(box)
            self.assertEqual(held, [BINARY[:32]])
            self.assertFalse(box.targets[0].exists())

    def test_source_mutation_after_copy_before_revalidation_rejected(self):
        with self.sandbox() as box:
            original = os.fchown
            def mutate(*args):
                if stat.S_ISREG(box.original_fstat(args[0]).st_mode):
                    box.source_paths[0].write_bytes(BINARY)
                return original(*args)
            with patch.object(os, 'fchown', side_effect=mutate):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())

    def test_directory_replacement_source_or_destination_rejected(self):
        for source_side in (False, True):
            with self.subTest(source_side=source_side), self.sandbox() as box:
                original = os.fchown
                replaced = False
                def replace(*args):
                    nonlocal replaced
                    if not replaced and stat.S_ISREG(box.original_fstat(args[0]).st_mode):
                        replaced = True
                        path = box.stage if source_side else box.leaves[0]
                        path.rename(path.with_name('held-original-directory'))
                        path.mkdir(mode=0o700)
                    return original(*args)
                with patch.object(os, 'fchown', side_effect=replace):
                    self.reject(box)
                self.assertFalse(box.targets[0].exists())

    def test_second_failure_keeps_published_exact_prefix_and_resumes(self):
        with self.sandbox() as box:
            original = installer._publish
            def fail_second(source, descriptor, destination, owned):
                if destination.file.resource.path == str(box.targets[1]):
                    raise OSError('second resource failure')
                return original(source, descriptor, destination, owned)
            with patch.object(installer, '_publish', side_effect=fail_second):
                self.reject(box)
            self.assertEqual(box.targets[0].read_bytes(), BINARY)
            self.assertEqual(box.stat(box.targets[0]).st_nlink, 1)
            self.assertFalse(box.targets[1].exists())
            self.assertEqual(self.install(box).operation, 'installed')

    def test_fsync_and_cleanup_failure_fail_closed(self):
        with self.sandbox() as box:
            with patch.object(os, 'fsync', side_effect=OSError('private fsync')):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())
        with self.sandbox() as box:
            original = os.unlink
            def fail(*args, **kwargs):
                if args[0] == installer._TEMPORARY:
                    raise OSError('private cleanup')
                return original(*args, **kwargs)
            with patch.object(os, 'unlink', side_effect=fail):
                self.reject(box)
            self.assertTrue(box.temporary().exists())

    def test_close_failure_and_control_exception_release_lock(self):
        with self.sandbox() as box:
            original = installer._mechanics._close
            def fail(owned):
                original(owned)
                return True, None
            with patch.object(installer._mechanics, '_close', side_effect=fail):
                self.reject(box)
            box.release.assert_called_once()
        with self.sandbox() as box:
            with patch.object(installer, '_source', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                self.install(box)
            box.release.assert_called_once()

    def test_production_sizes_rejected_before_streaming(self):
        for bad in (0, 134217728, 141150459, 141150461, 2**63-1, True, 141150460.0):
            with self.subTest(size=bad), self.sandbox() as box:
                value = provenance.DevSigstoreVerificationProvenance()
                artifacts = (
                    (str(box.targets[0]), 0o540, value.cosign.asset_size, value.cosign.asset_sha256),
                    (str(box.targets[1]), 0o640, value.trusted_root.target_size, value.trusted_root.target_sha256))
                sources = ((BINARY_NAME, value.cosign.asset_size, value.cosign.asset_sha256),
                           (ROOT_NAME, value.trusted_root.target_size, value.trusted_root.target_sha256))
                box.overrides[box.key(box.source_paths[0])] = {'st_size': bad}
                with patch.object(installer._resources, '_artifacts', return_value=artifacts), \
                     patch.object(installer._qualification, '_artifacts', return_value=sources):
                    self.reject(box)
                self.assertFalse(any(event[0] == 'read' for event in box.events))

    def test_trusted_root_size_and_owner_prevent_mutation(self):
        for change in ({'st_size': 6786}, {'st_size': 6788}, {'st_gid': 0}, {'st_uid': 9000},
                       {'st_mode': stat.S_IFREG | 0o644}):
            with self.subTest(change=change), self.sandbox() as box:
                box.overrides[box.key(box.source_paths[1])] = change
                self.reject(box)
                self.assertFalse(box.leaves[0].exists())

    def test_root_owned_sticky_source_parent_is_allowed(self):
        with self.sandbox() as box:
            box.overrides[box.key('/tmp')] = {'st_mode': stat.S_IFDIR | 0o1777}
            owned = []
            try:
                model = installer._resources.DevSigstoreResourceContract(configuration=configuration())
                installer._source(str(box.stage), model.file_requirements(), owned)
            finally:
                installer._mechanics._close(owned)

    def test_copy_requires_exact_eof_short_and_bounded_typed_reads(self):
        for wrong in (b'', b'x', None, bytearray(b'x'), b'x' * 65537):
            with self.subTest(wrong=type(wrong), length=len(wrong) if wrong is not None else 0), self.sandbox() as box:
                original = installer._publish
                def break_read(source, fd, destination, owned):
                    first = True
                    def read(descriptor, maximum):
                        nonlocal first
                        if descriptor == fd:
                            raw = wrong if first else b''
                            first = False
                            return raw
                        return box.read(descriptor, maximum)
                    with patch.object(os, 'read', side_effect=read):
                        return original(source, fd, destination, owned)
                with patch.object(installer, '_publish', side_effect=break_read):
                    self.reject(box)
                self.assertFalse(box.targets[0].exists())
                self.assertFalse(box.temporary().exists())
        with self.sandbox() as box:
            original = installer._publish
            def extra_eof(source, fd, destination, owned):
                def read(descriptor, maximum):
                    raw = box.read(descriptor, maximum)
                    return b'extra' if descriptor == fd and raw == b'' else raw
                with patch.object(os, 'read', side_effect=read):
                    return original(source, fd, destination, owned)
            with patch.object(installer, '_publish', side_effect=extra_eof):
                self.reject(box)

    def test_copy_stream_digest_and_destination_size_required(self):
        with self.sandbox() as box:
            original = installer._publish
            def corrupt(source, fd, destination, owned):
                def read(descriptor, maximum):
                    raw = box.read(descriptor, maximum)
                    return b'x' + raw[1:] if descriptor == fd and raw else raw
                with patch.object(os, 'read', side_effect=read):
                    return original(source, fd, destination, owned)
            with patch.object(installer, '_publish', side_effect=corrupt):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())
        with self.sandbox() as box:
            def short_write(fd, raw):
                # Lie about a successful write; destination size must catch it.
                box.original_write(fd, raw[:-1])
                return len(raw)
            with patch.object(os, 'write', side_effect=short_write):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())

    def test_temp_substitution_before_independent_reader_rejected(self):
        with self.sandbox() as box:
            original = installer._verify_file
            def substitute(directory, name, requirement, owned, **kwargs):
                if name == installer._TEMPORARY:
                    box.temporary().rename(box.leaves[0] / 'original')
                    box.temporary().write_bytes(BINARY)
                return original(directory, name, requirement, owned, **kwargs)
            with patch.object(installer, '_verify_file', side_effect=substitute):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())
            self.assertEqual(box.temporary().read_bytes(), BINARY)

    def test_destination_hash_metadata_mutation_before_link_rejected(self):
        with self.sandbox() as box:
            original = installer._revalidate_source
            def mutate(source):
                if box.temporary().exists():
                    box.temporary().chmod(0o600)
                    box.temporary().write_bytes(b'x' + BINARY[1:])
                    box.temporary().chmod(0o540)
                return original(source)
            with patch.object(installer, '_revalidate_source', side_effect=mutate):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())
            self.assertFalse(box.temporary().exists())

    def test_directory_metadata_change_after_publish_rejected(self):
        with self.sandbox() as box:
            original = os.link
            def mutate(*args, **kwargs):
                result = original(*args, **kwargs)
                box.leaves[0].chmod(0o755)
                return result
            with patch.object(os, 'link', side_effect=mutate):
                self.reject(box)
            self.assertEqual(box.targets[0].read_bytes(), BINARY)

    def test_directory_creation_no_named_open_substitution(self):
        with self.sandbox() as box:
            original = os.open
            def race(name, flags, *args, **kwargs):
                if name == 'tools':
                    box.leaves[0].rename(box.parents[0] / 'created-original')
                    box.leaves[0].mkdir(mode=0o700)
                return original(name, flags, *args, **kwargs)
            with patch.object(os, 'open', side_effect=race):
                self.reject(box)
            self.assertFalse(box.targets[0].exists())
            self.assertTrue(box.leaves[0].exists())

    def test_full_source_entry_set_rechecked_after_stream(self):
        with self.sandbox() as box:
            original = installer._qualification._hash_file
            def extra(fd, size):
                result = original(fd, size)
                if size == len(TRUSTED_ROOT):
                    (box.stage / 'extra').write_bytes(b'new extra')
                return result
            with patch.object(installer._qualification, '_hash_file', side_effect=extra):
                self.reject(box)
            self.assertFalse(box.leaves[0].exists())

    def test_post_link_fsync_failure_leaves_exact_resumable_prefix(self):
        with self.sandbox() as box:
            fail_once = True
            def fail(fd):
                nonlocal fail_once
                if fail_once and box.targets[0].exists() and box.fd_path(fd) == box.leaves[0]:
                    fail_once = False
                    raise OSError('directory durability failure')
                return box.fsync(fd)
            with patch.object(os, 'fsync', side_effect=fail):
                self.reject(box)
            self.assertEqual(box.targets[0].read_bytes(), BINARY)
            self.assertEqual(box.stat(box.targets[0]).st_nlink, 1)
            self.assertFalse(box.temporary().exists())
            self.assertEqual(self.install(box).operation, 'installed')

    def test_named_open_source_inode_substitution_rejected_before_hash(self):
        with self.sandbox() as box:
            inode = box.key(box.source_paths[0])[1]
            def substitute(fd):
                value = box.fstat(fd)
                return status_changed(value, st_ino=inode+1) if value.st_ino == inode else value
            with patch.object(os, 'fstat', side_effect=substitute):
                self.reject(box)
            self.assertFalse(any(event[0] == 'read' for event in box.events))

    def test_existing_destination_symlink_hardlink_and_reader_substitution(self):
        for kind in ('symlink', 'hardlink', 'reader'):
            with self.subTest(kind=kind), self.sandbox() as box:
                box.exact(0)
                original_inode = box.key(box.targets[0])[1]
                if kind == 'symlink':
                    box.targets[0].unlink()
                    box.targets[0].symlink_to(box.source_paths[0])
                    self.reject(box)
                elif kind == 'hardlink':
                    os.link(box.targets[0], box.root / 'extra-link')
                    self.reject(box)
                else:
                    def substitute(fd):
                        value = box.fstat(fd)
                        return status_changed(value, st_ino=original_inode+1) if value.st_ino == original_inode else value
                    with patch.object(os, 'fstat', side_effect=substitute):
                        self.reject(box)
                self.assertFalse(box.targets[1].exists())
                self.assertFalse(any(event[0] in ('write', 'chown', 'chmod') for event in box.events))

    def test_process_identity_revalidated_before_mutation(self):
        with self.sandbox() as box:
            with patch.object(installer, '_root', side_effect=(None, OSError('identity changed'))):
                self.reject(box)
            self.assertFalse(box.leaves[0].exists())
            box.release.assert_called_once()


class PublicAuthorityTests(unittest.TestCase):
    def test_exact_public_boundary_and_no_overrides(self):
        self.assertEqual(tuple(inspect.signature(installer.install_dev_sigstore_static_resources).parameters),
                         ('staging_directory', 'configuration'))
        for name in ('destination', 'filename', 'mode', 'uid', 'gid', 'sha256', 'size', 'url', 'temporary'):
            with self.subTest(name=name), self.assertRaises(TypeError):
                installer.install_dev_sigstore_static_resources(staging_directory='/stage', configuration=configuration(), **{name: 'caller'})
        self.assertEqual({name for name in vars(installer) if not name.startswith('_')}, set(installer.__all__))

    def test_exact_reviewed_production_authorities(self):
        model = installer._resources.DevSigstoreResourceContract(configuration=configuration())
        self.assertEqual(tuple((item.resource.path, item.size, item.sha256) for item in model.file_requirements()), (
            ('/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64', 141150460,
             'f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf'),
            ('/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json', 6787,
             '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66')))

    def test_import_inert_no_cli_network_subprocess_or_environment_authority(self):
        source = Path(installer.__file__).read_text()
        namespace = {'__name__': installer.__name__, '__package__': 'deployment'}
        with ExitStack() as stack:
            for owner, name in ((os, 'open'), (os, 'mkdir'), (os, 'getuid'), (os, 'write'),
                                (builtins, 'open'), (socket, 'socket'), (subprocess, 'Popen')):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
            exec(compile(source, installer.__file__, 'exec'), namespace)
        tree = ast.parse(source)
        calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {'replace', 'rename', 'getenv', 'system', 'Popen', 'run', 'qualify_dev_sigstore_toolchain'})
        self.assertNotIn('__main__', source)

    def test_invalid_and_forged_configuration_rejected_before_lock(self):
        for value in (None, {}, configuration().installation_contract()):
            with patch.object(installer, '_root'), patch.object(installer._orchestration, '_acquire_process_lock') as lock:
                with self.assertRaises(installer.SigstoreStaticInstallationError):
                    installer.install_dev_sigstore_static_resources(staging_directory='/stage', configuration=value)
                lock.assert_not_called()
        value = configuration()
        object.__setattr__(value.installation_contract(), 'broker_required_group_gids', (value.executor_gid,))
        with patch.object(installer, '_root'), patch.object(installer._orchestration, '_acquire_process_lock') as lock:
            with self.assertRaises(installer.SigstoreStaticInstallationError):
                installer.install_dev_sigstore_static_resources(staging_directory='/stage', configuration=value)
            lock.assert_not_called()

    def test_canonical_absolute_staging_directory_only(self):
        for path in ('', '/', 'relative', '//tmp/stage', '/tmp/../stage', '/tmp/stage/', None, True):
            with self.subTest(path=path), patch.object(installer, '_root'), \
                 patch.object(installer._orchestration, '_acquire_process_lock') as lock:
                with self.assertRaises(installer.SigstoreStaticInstallationError):
                    installer.install_dev_sigstore_static_resources(staging_directory=path, configuration=configuration())
                lock.assert_not_called()

    def test_installed_evidence_is_immutable_revalidated_and_narrow(self):
        from deployment.tests.test_sigstore_resource_contract import configuration as reviewed_configuration
        model = installer._resources.DevSigstoreResourceContract(configuration=reviewed_configuration())
        evidence = []
        for item in model.file_requirements():
            fp = (stat.S_IFREG | item.resource.mode, 100, 200, 1, 0, 1002, item.size, 300, 400)
            evidence.append(installer.SigstoreStaticFileInstallationEvidence(item.resource.path, item.size, item.sha256, fp))
        value = installer.DevSigstoreStaticInstallationEvidence('installed', 1002, *evidence)
        for item in (value, *evidence):
            for field in fields(item):
                with self.assertRaises(FrozenInstanceError):
                    setattr(item, field.name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(item, field.name)
        for bad in ('latest', 'trusted', True, None):
            with self.assertRaises(ValueError):
                installer.DevSigstoreStaticInstallationEvidence(bad, 1002, *evidence)
        with self.assertRaises(ValueError):
            installer.DevSigstoreStaticInstallationEvidence('installed', True, *evidence)
        object.__setattr__(evidence[0], 'size', True)
        with self.assertRaises(ValueError):
            value.__post_init__()
        self.assertEqual({item.name for item in fields(value)}, {'operation', 'broker_gid', 'cosign', 'trusted_root'})

    def test_source_set_history_and_workflow_remain_nonlive(self):
        from deployment.application_source_set import DevApplicationSourceSet
        from deployment import application_manifest, dev_post_c31_application_update
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 31)
        self.assertNotIn('deployment/sigstore_static_installation.py', paths)
        self.assertEqual((len(application_manifest._predecessor_paths()), len(application_manifest._paths())), (28, 31))
        self.assertEqual(dev_post_c31_application_update.PREDECESSOR, '3ef02a6d61d20df3a1495b290c20807162b65b06')
        self.assertEqual(dev_post_c31_application_update.TARGET, 'c04e66008cff556315603a9de59dacb4679787d4')
        self.assertIs(json.loads((ROOT / 'deployment/environments/dev.json').read_text())['activation']['deployment_enabled'], False)
        workflow = (ROOT / '.github/workflows/platform-promote.yml').read_text()
        self.assertNotIn('id-token: write', workflow)
        self.assertNotIn('environment: task014-dev', workflow)


if __name__ == '__main__':
    unittest.main()
