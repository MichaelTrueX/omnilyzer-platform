"""File: deployment/tests/accept_task014_analytics_recovery.py

Purpose: Native systemd255 recovery/socket/mount tests on an ephemeral CI VM.
Related: deployment/analytics_service_recovery.py; task014-c34d-review.yml.
Never runnable on omnilyzerdev; no DEV credentials, images, DB or network.
Creates only uniquely named /run test units and cleans its own exact paths.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from deployment.analytics_service_recovery import AnalyticsServiceControl, resume_analytics


CHILD = r'''
import os,socket,stat,http.client
base=os.path.dirname(__file__)
parent=base+'/deployment';leaf=parent+'/rootless-docker'
assert os.getuid()==65534 and os.getgid()==65534
assert os.environ['LISTEN_FDS']=='1'
assert os.environ['LISTEN_FDNAMES']=='omnilyzer-analytics-executor'
assert int(os.environ['LISTEN_PID'])==os.getpid()
listener=socket.socket(fileno=3);listener.settimeout(5)
assert listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1
assert listener.getsockname()==parent+'/analytics.sock'
def check():
    for path,uid,gid,mode in [(parent,0,0,0o755),(leaf,65534,65534,0o700)]:
        m=os.lstat(path)
        assert (m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode))==(uid,gid,mode)
    mounts={}
    for line in open('/proc/self/mountinfo'):
        left,right=line.split(' - ',1);a=left.split();b=right.split()
        mounts[a[4]]=(a[5].split(','),b[0])
    assert mounts[parent][1]==mounts[leaf][1]=='tmpfs'
    for path in [parent+'/analytics.sock',leaf+'/docker.sock']:
        assert 'ro' in mounts[path][0]
        assert stat.S_ISSOCK(os.lstat(path).st_mode)
    assert os.stat(leaf+'/docker.sock').st_ino==os.stat(base+'/docker.sock').st_ino
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2)
    try:
        s.connect(leaf+'/docker.sock');c=http.client.HTTPConnection('localhost',timeout=2);c.sock=s
        c.request('GET','/_ping');r=c.getresponse();assert r.status==200 and r.read(3)==b'OK';c.close()
    finally:s.close()
connection,_=listener.accept();connection.settimeout(8)
try:
    check();connection.sendall(b'READY\n')
    for _ in range(2):
        assert connection.recv(16)==b'CHECK\n'
        check();connection.sendall(b'CHECKED\n')
    assert connection.recv(16)==b'FINISH\n'
finally:connection.close();listener.close()
'''


class Ping(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        request = self.request.recv(4096)
        if not request.startswith(b'GET /_ping HTTP/'):
            raise AssertionError('unexpected_test_api_request')
        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')


class NativeRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or socket.gethostname().split('.')[0] == 'omnilyzerdev':
            raise RuntimeError('ephemeral_root_ci_only')
        version = subprocess.check_output(['/usr/bin/systemctl', '--version'], text=True).splitlines()[0]
        if not version.startswith('systemd 255 '):
            raise RuntimeError('native_systemd255_required:' + version)
        if not Path('/run/systemd/system').is_dir():
            raise RuntimeError('native_manager_required')
        print('NATIVE_SERVICE_MANAGER', version, flush=True)

    def setUp(self):
        self.prefix = 'omnilyzer-task014-ci-' + uuid.uuid4().hex[:12]
        self.base = Path('/run') / self.prefix
        self.base.mkdir(mode=0o755)
        self.base.chmod(0o755)
        (self.base / 'deployment').mkdir(mode=0o755)
        (self.base / 'state').mkdir(mode=0o755)
        self.child = self.base / 'child.py'
        self.child.write_text(CHILD);self.child.chmod(0o644)
        self.units = (self.prefix + '-broker.service', self.prefix + '-analytics.socket', self.prefix + '-analytics.service')
        self.paths = {u: Path('/run/systemd/system') / u for u in self.units}
        self.audit = []
        self.control = AnalyticsServiceControl(*self.units, audit=self.audit.append)
        self.parent = self.base / 'deployment'
        self.leaf = self.parent / 'rootless-docker'
        self.runtime_unit = self.prefix + '-canary-runtime.service'
        self.server = socketserver.UnixStreamServer(str(self.base / 'docker.sock'), Ping)
        os.chown(self.base / 'docker.sock', 65534, 65534)
        (self.base / 'docker.sock').chmod(0o1660)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
        self.thread.start()
        self.broker_bytes = '[Service]\nType=exec\nUser=65534\nGroup=65534\nNoNewPrivileges=yes\nExecStart=/usr/bin/sleep infinity\n'
        self.socket_bytes = f'[Socket]\nListenStream={self.parent}/analytics.sock\nSocketUser=65534\nSocketGroup=65534\nSocketMode=0660\nRemoveOnStop=yes\nFileDescriptorName=omnilyzer-analytics-executor\n'
        self.executor_bytes = f'''[Unit]
Requires={self.units[1]}
After={self.units[1]}
[Service]
Type=exec
User=65534
Group=65534
ExecStart=/usr/bin/python3 -I -B {self.child}
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths={self.base}/state
TemporaryFileSystem={self.parent}:mode=0755,uid=0,gid=0 {self.leaf}:mode=0700,uid=65534,gid=65534
BindReadOnlyPaths={self.base}/docker.sock:{self.leaf}/docker.sock {self.parent}/analytics.sock:{self.parent}/analytics.sock
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
'''
        for unit, data in zip(self.units, (self.broker_bytes, self.socket_bytes, self.executor_bytes), strict=True):
            self.paths[unit].write_text(data);self.paths[unit].chmod(0o644)
        self.expected = {
            self.units[0]: {'User': '65534', 'ExecStart': '/usr/bin/sleep infinity', 'ExecStartPost': '', 'NoNewPrivileges': 'yes'},
            self.units[1]: {'FragmentPath': str(self.paths[self.units[1]])},
            self.units[2]: {'User': '65534', 'ExecStart': '/usr/bin/python3 -I -B ' + str(self.child), 'ProtectSystem': 'strict', 'ReadWritePaths': str(self.base / 'state')},
        }
        self.addCleanup(self.clean)
        self.control.reload_and_verify(self.expected)

    def clean(self):
        result = self._outcome.result
        if any(test is self for test, _ in result.errors + result.failures):
            for entry in self.audit[-12:]:
                print('NATIVE_FIXTURE_AUDIT', json.dumps(entry.__dict__, sort_keys=True), flush=True)
        self.control.stop_and_confirm()
        subprocess.run(['/usr/bin/systemctl', 'stop', self.runtime_unit], capture_output=True)
        self.control.clear_failed_counters()
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
        for path in self.paths.values():path.unlink()
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, capture_output=True)
        # Only the exact random test directory owned by this case is removed.
        assert self.base.parent == Path('/run') and self.base.name == self.prefix
        shutil.rmtree(self.base)

    def native_probe(self):
        anchor = self.parent.stat().st_ino
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10);client.connect(str(self.parent / 'analytics.sock'))
            self.assertEqual(client.recv(16), b'READY\n')
            for _ in range(2):
                result = subprocess.run([
                    '/usr/bin/systemd-run', '--quiet', '--wait', '--collect', '--unit=' + self.runtime_unit,
                    '--property=Type=oneshot', '--property=User=65534', '--property=Group=65534',
                    '--property=RuntimeDirectory=' + str(self.leaf.relative_to('/run')),
                    '--property=RuntimeDirectoryMode=0700', '/usr/bin/true',
                ], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.leaf.exists())
                self.assertEqual(self.parent.stat().st_ino, anchor)
                client.sendall(b'CHECK\n');self.assertEqual(client.recv(16), b'CHECKED\n')
            client.sendall(b'FINISH\n')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = self.control.properties(self.units[2], 'ActiveState', 'ExecMainStatus')
            if state['ActiveState'] == 'inactive':break
            time.sleep(0.05)
        self.assertEqual(state, {'ActiveState': 'inactive', 'ExecMainStatus': '0'})

    def test_real_socket_activation_mounts_and_canary_cleanup(self):
        phases = []
        result = resume_analytics(
            self.control, no_application=lambda: None, prepare=lambda: None,
            restore=lambda: self.fail('unexpected_restore'), expected=self.expected,
            probe=self.native_probe, checkpoint=phases.append,
        )
        self.assertEqual(result['status'], 'ready_for_signed_task014', result)
        self.assertLess(phases.index('manager_reloaded_and_verified'), phases.index('native_probe_passed'))
        self.assertEqual(self.control.properties(self.units[0], 'ActiveState')['ActiveState'], 'active')

    def test_unloaded_existing_units_do_not_block_stop_or_counter_cleanup(self):
        self.control.stop_and_confirm()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            listing = subprocess.check_output(['/usr/bin/systemctl', 'list-units', '--all', '--plain', '--no-legend', self.units[2]], text=True)
            if not listing.strip():break
            time.sleep(0.05)
        self.assertFalse(listing.strip(), 'inactive_fixture_not_unloaded')
        result = self.control.call('reset-failed', self.units[2])
        self.assertNotEqual(result.returncode, 0, 'native_unloaded_unit_reset_must_reproduce_error')
        self.assertTrue(result.stderr.strip())
        self.control.stop_and_confirm()
        self.control.clear_failed_counters()
        self.control.require_stopped()

    def test_failed_start_after_publication_restores_loaded_config_and_stops(self):
        phases = [];published = self.base / 'publication'
        bad = self.broker_bytes + 'ExecStartPost=/usr/bin/false\n'
        expected = copy.deepcopy(self.expected)
        expected[self.units[0]]['ExecStartPost'] = '/usr/bin/false'
        def prepare():
            published.write_text('new');self.paths[self.units[0]].write_text(bad)
        def restore():
            published.write_text('old');self.paths[self.units[0]].write_text(self.broker_bytes)
        result = resume_analytics(
            self.control, no_application=lambda: None, prepare=prepare, restore=restore,
            expected=expected, restored_expected=self.expected, probe=self.native_probe,
            checkpoint=phases.append,
        )
        self.assertEqual(result['status'], 'stopped_recovered', result)
        self.assertIn('start_' + self.units[0], result['primary_error'])
        self.assertEqual(published.read_text(), 'old')
        self.control.require_stopped()
        self.assertEqual(self.control.properties(self.units[0], 'ExecStart')['ExecStart'], '/usr/bin/sleep infinity')
        errors = [entry for entry in self.audit if entry.operation == 'start' and entry.returncode]
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].stderr)

    def test_restore_failure_preserves_original_start_error(self):
        bad = self.broker_bytes + 'ExecStartPost=/usr/bin/false\n'
        expected = copy.deepcopy(self.expected);expected[self.units[0]]['ExecStartPost'] = '/usr/bin/false'
        def restore():raise RuntimeError('injected_restore_failure')
        result = resume_analytics(
            self.control, no_application=lambda: None,
            prepare=lambda: self.paths[self.units[0]].write_text(bad),
            restore=restore, expected=expected, probe=self.native_probe, checkpoint=lambda phase: None,
        )
        self.assertEqual(result['status'], 'manual_recovery_required')
        self.assertIn('start_' + self.units[0], result['primary_error'])
        self.assertEqual(result['recovery_errors'], ['RuntimeError:injected_restore_failure'])
        self.control.require_stopped()

    def test_manager_reload_precedes_activation_of_changed_unit(self):
        # Keep the executor loaded through its active socket dependency.
        self.control.start(self.units[1])
        prior = self.control.properties(self.units[2], 'ReadWritePaths')['ReadWritePaths']
        second = self.base / 'second-state';second.mkdir(mode=0o755)
        self.paths[self.units[2]].write_text(self.executor_bytes.replace(str(self.base / 'state'), str(second)))
        cached = self.control.properties(self.units[2], 'ReadWritePaths', 'NeedDaemonReload')
        self.assertEqual(cached['ReadWritePaths'], prior)
        self.assertEqual(cached['NeedDaemonReload'], 'yes')
        self.control.stop_and_confirm()
        expected = copy.deepcopy(self.expected);expected[self.units[2]]['ReadWritePaths'] = str(second)
        self.control.reload_and_verify(expected)
        self.assertEqual(self.control.properties(self.units[2], 'ReadWritePaths')['ReadWritePaths'], str(second))

    def test_invalid_loaded_configuration_blocks_socket_activation(self):
        self.paths[self.units[2]].write_text('[Service]\nType=exec\n')
        result = resume_analytics(
            self.control, no_application=lambda: None, prepare=lambda: None,
            restore=lambda: self.paths[self.units[2]].write_text(self.executor_bytes),
            expected=self.expected, probe=lambda: self.fail('invalid_unit_was_activated'),
            checkpoint=lambda phase: None,
        )
        self.assertEqual(result['status'], 'stopped_recovered', result)
        self.assertFalse(any(r.operation == 'start' for r in self.audit))
        self.control.require_stopped()

    def test_delayed_post_exec_exit_is_not_accepted_as_ready(self):
        script = self.base / 'delayed-exit.py'
        script.write_text('import time\ntime.sleep(0.2)\nraise SystemExit(1)\n');script.chmod(0o644)
        command = '/usr/bin/python3 -I -B ' + str(script)
        bad = self.broker_bytes.replace('/usr/bin/sleep infinity', command)
        expected = copy.deepcopy(self.expected);expected[self.units[0]]['ExecStart'] = command
        result = resume_analytics(
            self.control, no_application=lambda: None,
            prepare=lambda: self.paths[self.units[0]].write_text(bad),
            restore=lambda: self.paths[self.units[0]].write_text(self.broker_bytes),
            expected=expected, restored_expected=self.expected, probe=self.native_probe,
            checkpoint=lambda phase: None,
        )
        self.assertEqual(result['status'], 'stopped_recovered', result)
        self.assertIn('broker_not_stable', result['primary_error'])
        self.control.require_stopped()


if __name__ == '__main__':
    unittest.main(verbosity=2)
