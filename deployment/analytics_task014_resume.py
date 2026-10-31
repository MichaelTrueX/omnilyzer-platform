"""File: deployment/analytics_task014_resume.py

Purpose: Owner-local resume of the already installed PR269 Analytics generation.
Related: analytics_service_recovery.py; original root readiness helper02af57b8;
         Task014 issue27; docs/operations/m05-14-task014-analytics-runtime-20261029.md.

No import-time action. Identity repair replaces only the frozen loader source
and its exact source/config authority. Never rebuilds a release, accepts an
unsigned deployment, reads application secrets or writes a database. The exact
owner-reviewed bundle and explicit workflow SHA are the administrative grant.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import tarfile
from urllib import request, error

from deployment.analytics_service_recovery import AnalyticsServiceControl, CommandResult, ServiceFailure, resume_analytics, _capture_command

BASE = Path('/opt/omnilyzer/deployment')
HELPER = BASE / '.analytics-db-review/analytics-task014-readiness-a0022a79.py'
HELPER_SHA = '02af57b81cb6e8a2972b83e5e130fd96a8b60544085f67858d6c5d145b14f39e'
STAGE = BASE / '.analytics-pr269-rollback-20261031/new-inputs'
MANIFEST_SHA = 'f811cba38198a57d924d3c0dc84501ba224ee14de3d0100b5b2a361377033cea'
PRODUCT_COMMIT = '0b8342c63dff6375004d979e8cfdf0d815f214d9'
CURRENT_WORKFLOW = '75091ed2bd38bb7591859b2f615eb572f65e8668'
ORIGINAL_BROKER = BASE / '.analytics-pr264-rollback-20261030/broker-dev.json'
ORIGINAL_BROKER_SHA = '024fd4df2d1aba346889a42ef64b122e7ee0728961f89dc349beee1e7c353037'
ORIGINAL_EXECUTOR_SHA = 'c8ae7b8ba2be4c5326e031a9e421ed8a760417e7112c9423e8e90340b68fd46e'
BROKER_UNIT_SHA = '594c3038451ad867e80e1361bef81711814e7aec1a727f33e85de9fd590bf0c2'
PRIVATE = BASE / '.analytics-pr269-resume-20261031'
PUBLIC = BASE / 'analytics-task014-resume-result.json'
BROKER = 'omnilyzer-deployment-broker.service'
LISTENER = 'omnilyzer-deployment-analytics-executor.socket'
EXECUTOR = 'omnilyzer-deployment-analytics-executor.service'
PROBE = 'omnilyzer-task014-analytics-resume-probe.service'


def require(ok, code):
    if not ok:
        raise ServiceFailure(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def safe_parent(path):
    for parent in reversed(path.parents):
        m = parent.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and not stat.S_IMODE(m.st_mode) & 0o022, 'unsafe_root_parent')


def load_helper():
    safe_parent(HELPER)
    m = HELPER.lstat()
    require(stat.S_ISREG(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode), m.st_nlink) == (0, 0, 0o400, 1), 'readiness_helper_metadata')
    fd = os.open(HELPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(fd, 65537)
        require(len(raw) == m.st_size <= 65536 and digest(raw) == HELPER_SHA, 'readiness_helper_hash')
        require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (m.st_dev, m.st_ino), 'readiness_helper_identity')
    finally:
        os.close(fd)
    spec = importlib.util.spec_from_loader('immutable_task014_readiness', loader=None)
    helper = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(HELPER), 'exec'), helper.__dict__)
    return helper


@contextmanager
def provisioning_lock():
    safe_parent(Path('/usr/bin/child'))
    fd = os.open('/usr/bin', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(before.st_uid == 0 and stat.S_IMODE(before.st_mode) == 0o755, 'provisioning_lock_metadata')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
        after = Path('/usr/bin').lstat()
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), 'provisioning_lock_changed')
    finally:
        os.close(fd)


def atomic_file(helper, path, raw, *, group, mode, expected=None, temporary_suffix='.resume-next'):
    """Publish only a fixed root target; reject unknown existing/temp bytes."""
    safe_parent(path)
    if expected is None:
        require(not path.exists() and not path.is_symlink(), 'unexpected_existing_target')
    else:
        require(helper.bounded_file(path, 8 << 20, owner=0, group=group, mode=mode) == expected, 'target_preimage_changed')
    require(temporary_suffix in ('.resume-next', '.resume-recovery-next'), 'invalid_atomic_scope')
    temporary = path.with_name(path.name + temporary_suffix)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    identity = os.fstat(fd)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'atomic_short_write');view = view[count:]
        os.fchown(fd, 0, group);os.fchmod(fd, mode);os.fsync(fd)
        require(helper.bounded_file(temporary, 8 << 20, owner=0, group=group, mode=mode) == raw, 'atomic_staged_bytes')
        if expected is not None:
            require(helper.bounded_file(path, 8 << 20, owner=0, group=group, mode=mode) == expected, 'target_preimage_changed')
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        os.close(fd)
        if temporary.exists() or temporary.is_symlink():
            m = temporary.lstat()
            require((m.st_dev, m.st_ino) == (identity.st_dev, identity.st_ino), 'unknown_atomic_temporary')
            temporary.unlink()


def closed_tree(helper, root, expected, *, preserved_temporaries=()):
    require(set(preserved_temporaries).issubset({'deployment/analytics_executor_service_config.py.resume-next'}), 'invalid_preserved_source_temporary')
    actual = set();directories = set()
    allowed_dirs = {str(p) for name in expected for p in Path(name).parents if str(p) != '.'}
    for base, children, files in os.walk(root, followlinks=False):
        m = Path(base).lstat()
        require(stat.S_ISDIR(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (0, 0, 0o755), 'source_directory_metadata')
        for name in children:
            p = Path(base) / name;require(not p.is_symlink(), 'source_directory_symlink');directories.add(str(p.relative_to(root)))
        for name in files:
            relative = str((Path(base) / name).relative_to(root))
            if relative in preserved_temporaries:continue
            require(relative in expected, 'unlisted_source_file')
            helper.installed_source(root, relative, expected[relative]);actual.add(relative)
    require(actual == set(expected) and len(actual) == 70 and directories == allowed_dirs, 'source_closed_set')


def signer_file(path, expected, size, mode):
    safe_parent(path);m = path.lstat()
    require(stat.S_ISREG(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode), m.st_nlink) == (0, 990, mode, 1) and m.st_size == size, 'signer_metadata')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC);h = hashlib.sha256()
    try:
        count = 0
        while True:
            raw = os.read(fd, 262144)
            if not raw:break
            count += len(raw);require(count <= size, 'signer_resource_grew');h.update(raw)
        after = os.fstat(fd)
        require((m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and h.hexdigest() == expected, 'signer_hash_or_identity')
    finally:os.close(fd)


def no_application(helper):
    output = helper.command((*helper.DOCKER, 'ps', '-a', '--filter', 'label=com.docker.compose.project=omnilyzer-analytics-dev', '--format', '{{.ID}}'))
    require(not output.strip(), 'application_present_no_metadata_recovery')


def inspect_generation(helper, control, target, *, recovering=False):
    """Continue all independent checks; never adopt observed values as pins."""
    checks = [];assets = {};model = None;base = None
    def check(name, action):
        try:
            value = action();checks.append({'name': name, 'status': 'PASS'});return value
        except Exception as failure:
            code = str(failure)
            code = code if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,95}', code) else 'see_private_audit'
            checks.append({'name': name, 'status': 'FAIL', 'category': type(failure).__name__, 'code': code});return None
    def retained():
        safe_parent(STAGE / 'manifest.json');m = STAGE.lstat()
        require((m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (0, 0, 0o700), 'retained_stage_metadata')
        helper.bounded_file(STAGE / 'manifest.json', 16384, owner=0, group=0, mode=0o600)
        return helper.stage_manifest(STAGE, MANIFEST_SHA, PRODUCT_COMMIT)
    manifest = check('retained_exact_generation', retained)
    if manifest is not None:
        for i, row in enumerate(manifest['assets']):
            raw = check('retained_asset_' + str(i), lambda r=row: helper.bounded_file(STAGE / r['name'], 1048576, owner=0, group=0, mode=0o600))
            if raw is not None:
                check('retained_digest_' + str(i), lambda r=row,b=raw: require(digest(b) == r['sha256'] and len(b) == r['size'], 'retained_asset_hash'))
                assets[i] = raw
                check('installed_asset_' + str(i), lambda i=i,b=raw: require(helper.bounded_file(Path(helper.DESTINATIONS[i]), 1048576, owner=0, group=helper.GROUPS[i], mode=helper.MODES[i]) == b, 'installed_asset_changed'))
    if 7 in assets:
        pair = check('closed_source_archive', lambda: helper.source_model(assets[7], PRODUCT_COMMIT))
        if pair is not None:
            model, expected = pair
            for name, sha in sorted(expected.items()):
                check('analytics_source:' + name, lambda n=name,s=sha: helper.installed_source(helper.SOURCE_ROOT, n, s))
            check('closed_live_70_sources', lambda: closed_tree(helper, helper.SOURCE_ROOT, expected))
            for name, sha in sorted({**model['inherited_canary_sha256'], **model['shared_preimage_sha256']}.items()):
                check('original_canary:' + name, lambda n=name,s=sha: helper.installed_source(helper.CANARY_ROOT, n, s))
    def original():
        raw = helper.bounded_file(ORIGINAL_BROKER, 4096, owner=0, group=0, mode=0o600)
        require(digest(raw) == ORIGINAL_BROKER_SHA, 'original_broker_authority_hash')
        return json.loads(raw, object_pairs_hook=helper.unique)
    base = check('original_broker_authority', original)
    before = None;after = None
    if base is not None:
        before = canonical({**base, 'expected_workflow_sha': CURRENT_WORKFLOW})
        after = canonical({**base, 'expected_workflow_sha': target})
        check('frozen_broker_preimage', lambda: require(helper.bounded_file(helper.BROKER_CONFIG, 4096, owner=0, group=990, mode=0o640) in ((before, after) if recovering else (before,)), 'broker_preimage_changed'))
        check('signer_binary', lambda: signer_file(Path('/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64'), base['cosign_binary_sha256'], 141150460, 0o540))
        root = Path('/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json')
        check('trusted_root', lambda: (require(0 < root.lstat().st_size <= 1048576, 'trusted_root_size'), signer_file(root, base['sigstore_trusted_root_sha256'], root.lstat().st_size, 0o640)))
    check('original_executor_unchanged', lambda: require(digest(helper.bounded_file(helper.EXECUTOR_CONFIG, 4096, owner=0, group=991, mode=0o640)) == ORIGINAL_EXECUTOR_SHA, 'original_executor_changed'))
    check('original_broker_unit', lambda: require(digest(helper.bounded_file(Path('/etc/systemd/system/' + BROKER), 16384, owner=0, group=0, mode=0o644)) == BROKER_UNIT_SHA, 'broker_unit_changed'))
    check('stopped_control_plane', control.require_stopped)
    check('original_canary_socket', lambda: helper.service_state('omnilyzer-deployment-executor.socket', 'active'))
    check('original_canary_executor_idle', lambda: helper.service_state('omnilyzer-deployment-executor.service', 'inactive'))
    for name in ('blob-verifier', 'oci-verifier'):
        def verifier_workspace(kind=name):
            path = Path('/run/omnilyzer/deployment/dev') / kind;safe_parent(path)
            m = path.lstat();require(stat.S_ISDIR(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (990, 990, 0o700), 'verifier_workspace_metadata')
        check('verifier_workspace:' + name, verifier_workspace)
    check('secret_directory_metadata', helper.secret_directory_metadata)
    for name in ('COLLECTOR_DATABASE_URL', 'DATABASE_URL', 'JWT_REFRESH_SECRET', 'JWT_SECRET'):
        check('secret_metadata:' + name, lambda n=name: helper.secret_file_metadata(n))
    pg = check('postgres_identity', helper.postgres_state);check('postgres_internal_network', helper.postgres_network)
    for kind in ('force_rls', 'restricted_roles'):
        if pg is not None:check('postgres_' + kind, lambda k=kind: helper.postgres_count(k))
        else:checks.append({'name': 'postgres_' + kind, 'status': 'BLOCKED', 'dependency': 'postgres_identity'})
    check('no_application', lambda: no_application(helper))
    def legacy_phase():
        raw = helper.bounded_file(STAGE.parent / 'journal.json', 4096, owner=0, group=0, mode=0o600)
        value = json.loads(raw, object_pairs_hook=helper.unique)
        require(value == {'operation': 'pr269-namespace-transition', 'phase': 'workflow_only_authority_published', 'product_commit': PRODUCT_COMMIT, 'workflow_commit': CURRENT_WORKFLOW} and canonical(value) == raw, 'unexpected_legacy_phase')
    check('owner_captured_transition_phase', legacy_phase)
    failed = [row for row in checks if row['status'] != 'PASS']
    print(json.dumps({'operation': 'read_only_resume_preflight', 'checks': checks, 'mismatches': len(failed), 'secret_contents_read': False, 'database_writes': False}), flush=True)
    require(not failed and len(assets) == 8 and model is not None and before is not None, 'complete_preflight_failed')
    return assets, before, after


def expected_runtime(assets):
    """Disk bytes are already frozen; compare their effective native settings."""
    return {
        BROKER: {'FragmentPath': '/etc/systemd/system/' + BROKER, 'WorkingDirectory': str(BASE / 'analytics-app'), 'User': 'omnilyzer-broker', 'Group': 'omnilyzer-broker', 'ExecStart': str(BASE / 'venv/bin/python') + ' -m deployment.analytics_broker_service_entrypoint', 'NoNewPrivileges': 'yes', 'ProtectSystem': 'strict', 'DropInPaths': '/etc/systemd/system/' + BROKER + '.d/analytics-enabled.conf'},
        LISTENER: {'FragmentPath': '/etc/systemd/system/' + LISTENER, 'DropInPaths': ''},
        EXECUTOR: {'FragmentPath': '/etc/systemd/system/' + EXECUTOR, 'WorkingDirectory': str(BASE / 'analytics-app'), 'User': 'omnilyzer-executor', 'Group': 'omnilyzer-executor', 'ExecStart': str(BASE / 'venv/bin/python') + ' -m deployment.analytics_executor_service_entrypoint', 'NoNewPrivileges': 'yes', 'PrivateTmp': 'yes', 'PrivateDevices': 'yes', 'ProtectHome': 'yes', 'ProtectSystem': 'strict', 'ReadWritePaths': '/var/lib/omnilyzer/deployment', 'TemporaryFileSystem': '/run/omnilyzer/deployment:mode=0755,uid=0,gid=0 /run/omnilyzer/deployment/rootless-docker:mode=0700,uid=991,gid=991', 'BindReadOnlyPaths': '/run/user/991/docker.sock:/run/omnilyzer/deployment/rootless-docker/docker.sock:rbind /run/omnilyzer/deployment/analytics-executor.sock:/run/omnilyzer/deployment/analytics-executor.sock:rbind', 'CapabilityBoundingSet': '', 'AmbientCapabilities': '', 'SupplementaryGroups': 'omnilyzer-replay', 'DropInPaths': '/etc/systemd/system/' + EXECUTOR + '.d/rootless-runtime.conf'},
    }


def broker_http_ready():
    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):return None
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        opener.open('http://127.0.0.1:3031/', timeout=3)
    except error.HTTPError as refused:
        require(refused.code == 403, 'broker_http_not_ready');return
    raise ServiceFailure('broker_http_not_ready')


CONTEXT_CHILD = r'''
import os,sys,json,stat,socket,http.client
assert os.getuid()==os.geteuid()==991 and os.getgid()==991
sys.path.insert(0,'/opt/omnilyzer/deployment/analytics-app')
from deployment.analytics_executor_service_config import load_analytics_executor_service_config
source,identities=load_analytics_executor_service_config()
expected=json.loads(sys.argv[1]);assert source['reviewed_installed_commit']==expected.pop('product_commit')
assert set(identities)=={'expected_replay_directory_uid','expected_replay_directory_gid','expected_broker_uid','expected_broker_gid','expected_executor_uid','expected_executor_gid','expected_socket_owner_uid','expected_socket_group_gid'}
parent='/run/omnilyzer/deployment';leaf=parent+'/rootless-docker'
mounts={}
for line in open('/proc/self/mountinfo'):
    left,right=line.split(' - ',1);a=left.split();b=right.split();mounts[a[4]]=(a[5].split(','),b[0])
for path,uid,gid,mode in [(parent,0,0,0o755),(leaf,991,991,0o700)]:
    m=os.lstat(path)
    assert stat.S_ISDIR(m.st_mode) and (m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode))==(uid,gid,mode)
    assert mounts[path][1]=='tmpfs' and 'rw' in mounts[path][0]
for name,path in [('listener',parent+'/analytics-executor.sock'),('daemon',leaf+'/docker.sock')]:
    m=os.lstat(path)
    assert stat.S_ISSOCK(m.st_mode) and [m.st_dev,m.st_ino,m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode)]==expected[name]
    assert 'ro' in mounts[path][0]
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(3)
try:
    s.connect(leaf+'/docker.sock');c=http.client.HTTPConnection('localhost',timeout=3);c.sock=s
    c.request('GET','/_ping');r=c.getresponse();assert r.status==200 and r.read(3)==b'OK';c.close()
finally:s.close()
print('NATIVE_CONTEXT_PASS',flush=True)
'''

NEGATIVE_CLIENT = r'''
import os,socket
os.setgroups([990,992,993]);os.setgid(990);os.setuid(990)
assert os.getuid()==os.geteuid()==990 and os.getgid()==990
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5)
try:
    s.connect('/run/omnilyzer/deployment/analytics-executor.sock')
    s.sendall(b'FAIL');s.shutdown(socket.SHUT_WR)
    try:assert s.recv(129)==b''
    except ConnectionResetError:pass
finally:s.close()
print('INVALID_CREDENTIAL_CLOSED',flush=True)
'''


def native_command(argv, label, records, timeout=30):
    """Capture only fixed reviewed probe commands with the tested pipe bounds."""
    try:
        record = _capture_command(label, tuple(argv), timeout)
    except ServiceFailure as failure:
        if failure.result is not None:records.append(failure.result)
        raise
    records.append(record)
    if record.returncode:raise ServiceFailure(label, record)
    return record.stdout.encode('utf-8')


def native_probe(helper, control, assets, checkpoint, records, *, product_commit=PRODUCT_COMMIT):
    """Actual executor context plus real FD3 entrypoint rejection, no release."""
    probe_state = helper.command(('/usr/bin/systemctl', 'show', PROBE, '-p', 'LoadState')).strip()
    require(probe_state == b'LoadState=not-found', 'probe_unit_already_present')
    expected = {'product_commit': product_commit}
    for name, path, uid, gid, mode in (
        ('listener', Path('/run/omnilyzer/deployment/analytics-executor.sock'), 991, 993, 0o660),
        ('daemon', Path('/run/user/991/docker.sock'), 991, 991, 0o1660),
    ):
        m = path.lstat();require(stat.S_ISSOCK(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode), m.st_nlink) == (uid, gid, mode, 1), 'native_socket_metadata')
        expected[name] = [m.st_dev, m.st_ino, m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)]
    properties = {}
    for raw in (assets[3], assets[4]):
        section = None
        for row in raw.decode('ascii').splitlines():
            if not row or row.startswith('#'):continue
            if row.startswith('['):section = row;continue
            if section != '[Service]':continue
            key, value = row.split('=', 1)
            if key == 'ExecStart':continue
            if key in properties:
                require(key == 'BindReadOnlyPaths', 'duplicate_probe_property');properties[key] += ' ' + value
            else:properties[key] = value
    argv = ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect', '--unit=' + PROBE]
    argv += ['--property=' + key + '=' + value for key, value in properties.items()]
    argv += [str(BASE / 'venv/bin/python'), '-I', '-B', '-c', CONTEXT_CHILD, json.dumps(expected, separators=(',', ':'))]
    primary = None
    try:
        require(native_command(argv, 'native_executor_context', records) == b'NATIVE_CONTEXT_PASS\n', 'native_context_response')
    except BaseException as failure:
        primary = failure
    finally:
        try:
            state = helper.command(('/usr/bin/systemctl', 'show', PROBE, '-p', 'LoadState')).strip()
            if state != b'LoadState=not-found':
                identity = helper.command(('/usr/bin/systemctl', 'show', PROBE, '-p', 'Transient', '-p', 'FragmentPath')).decode().splitlines()
                require(dict(row.split('=', 1) for row in identity) == {'Transient': 'yes', 'FragmentPath': '/run/systemd/transient/' + PROBE}, 'unknown_probe_unit')
                try:native_command(('/usr/bin/systemctl', 'stop', PROBE), 'stop_owned_context_probe', records)
                except ServiceFailure:
                    require(helper.command(('/usr/bin/systemctl', 'show', PROBE, '-p', 'LoadState')).strip() == b'LoadState=not-found', 'context_probe_stop_unconfirmed')
        except BaseException as cleanup:
            if primary is None:primary = cleanup
            else:primary.add_note('probe_cleanup_failed:' + type(cleanup).__name__)
    if primary is not None:raise primary
    checkpoint('actual_executor_context_passed')
    negative_error = None
    prior_invocation = control.properties(EXECUTOR, 'InvocationID')['InvocationID']
    try:
        require(native_command(('/usr/bin/python3', '-I', '-B', '-c', NEGATIVE_CLIENT), 'actual_fd3_invalid_credential_probe', records, timeout=10) == b'INVALID_CREDENTIAL_CLOSED\n', 'invalid_credential_response')
    except BaseException as failure:
        negative_error = failure
    finally:
        try:
            deadline = time.monotonic() + 3
            while True:
                values = control.properties(EXECUTOR, 'InvocationID', 'ExecMainStatus', 'ActiveState')
                if values['ActiveState'] != 'active' or time.monotonic() >= deadline:break
                time.sleep(0.05)
            invocation = values['InvocationID']
            require(re.fullmatch(r'[a-f0-9]{32}', invocation) and invocation != prior_invocation, 'executor_invocation_not_fresh')
            journal_deadline = time.monotonic() + 3
            while True:
                logs = native_command(('/usr/bin/journalctl', '--no-pager', '-n', '30', '-o', 'cat', '_SYSTEMD_INVOCATION_ID=' + invocation), 'actual_executor_probe_journal', records, timeout=3)
                if b'TASK014_EXECUTOR_FAILURE boundary=handler phase=sealed_fd_receive\n' in logs or time.monotonic() >= journal_deadline:break
                time.sleep(0.1)
        except BaseException as observation_error:
            if negative_error is None:negative_error = observation_error
            else:negative_error.add_note('probe_observation_failed:' + type(observation_error).__name__)
    if negative_error is not None:raise negative_error
    require(b'TASK014_EXECUTOR_FAILURE boundary=handler phase=sealed_fd_receive\n' in logs, 'actual_executor_credential_boundary_not_reached')
    require(values['ActiveState'] == 'failed' and values['ExecMainStatus'] == '1', 'invalid_credential_not_closed')
    control.clear_failed_counters()
    checkpoint('actual_fd3_credential_rejection_passed')


def recovery_temporaries(helper, targets=None):
    """Preserve interrupted normal writes; never adopt or remove their bytes."""
    inventory = []
    if targets is None:
        targets = [(helper.BROKER_CONFIG, 990, 0o640, 4096), (PUBLIC, 0, 0o644, 16384)]
        targets += [(PRIVATE / name, 0, 0o600, 8 << 20) for name in ('broker-before.json', 'broker-target.json', 'audit.json', 'recovery-audit.json')]
    for path, group, mode, limit in targets:
        for suffix in ('.resume-next', '.resume-recovery-next'):
            temporary = path.with_name(path.name + suffix)
            if not temporary.exists() and not temporary.is_symlink():continue
            safe_parent(temporary);m = temporary.lstat()
            require(stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) in ((0, 0, 0o600), (0, group, mode)), 'unsafe_interrupted_publication')
            if m.st_size:
                raw = helper.bounded_file(temporary, limit, owner=0, group=m.st_gid, mode=stat.S_IMODE(m.st_mode))
            else:
                fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                try:
                    raw = os.read(fd, 1);after = os.fstat(fd);named = temporary.lstat()
                    require(raw == b'' and (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns, named.st_ctime_ns), 'interrupted_publication_changed')
                finally:os.close(fd)
            inventory.append({'path': str(temporary), 'size': len(raw), 'sha256': digest(raw)})
            require(suffix == '.resume-next', 'interrupted_recovery_requires_manual_review')
    return inventory


def recovery_intent(helper, control, target):
    """Own the frozen recovery before stopping active post-crash controls."""
    safe_parent(PRIVATE / 'child');m = PRIVATE.lstat()
    require(stat.S_ISDIR(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (0, 0, 0o700), 'private_recovery_directory')
    raw = helper.bounded_file(ORIGINAL_BROKER, 4096, owner=0, group=0, mode=0o600)
    require(digest(raw) == ORIGINAL_BROKER_SHA, 'original_broker_authority_hash')
    base = json.loads(raw, object_pairs_hook=helper.unique)
    before = canonical({**base, 'expected_workflow_sha': CURRENT_WORKFLOW})
    after = canonical({**base, 'expected_workflow_sha': target})
    require(helper.bounded_file(PRIVATE / 'broker-before.json', 4096, owner=0, group=0, mode=0o600) == before, 'retained_workflow_preimage')
    require(helper.bounded_file(PRIVATE / 'broker-target.json', 4096, owner=0, group=0, mode=0o600) == after, 'retained_workflow_target')
    require(helper.bounded_file(helper.BROKER_CONFIG, 4096, owner=0, group=990, mode=0o640) in (before, after), 'unknown_workflow_during_recovery')
    inventory = recovery_temporaries(helper)
    no_application(helper)
    control.stop_and_confirm()
    no_application(helper)
    return inventory


IDENTITY_TARGET = '4a6cae5fb81eed894dee406c45dbd3417448b0d5'
IDENTITY_STAGE = Path('/home/omnigpt/repos/omnilyzer-platform/.m05-14-release-review/analytics-task014-identity-4a6cae5f-20261031')
IDENTITY_MANIFEST = 'e2f23bbecd900178391fc9574e5acd137df511b05626089c60cd8d40b4bd9374'
IDENTITY_PRIVATE = BASE / '.analytics-pr271-identity-20261031'
IDENTITY_SOURCE = 'deployment/analytics_executor_service_config.py'


def identity_inputs(helper, folder, *, protected):
    """Frozen unsigned inputs are data, never self-authorizing source."""
    checks = [];assets = {}
    manifest = helper.stage_manifest(folder, IDENTITY_MANIFEST, IDENTITY_TARGET)
    for i, row in enumerate(manifest['assets']):
        try:
            raw = helper.bounded_file(folder / row['name'], 1048576, **({'owner': 0, 'group': 0, 'mode': 0o600} if protected else {}))
            require(len(raw) == row['size'] and digest(raw) == row['sha256'], 'identity_input_hash')
            assets[i] = raw
        except Exception:checks.append(i)
    print(json.dumps({'operation': 'read_only_identity_inputs', 'mismatched_asset_indices': checks}), flush=True)
    require(not checks and len(assets) == 8, 'identity_inputs_incomplete')
    raw = helper.bounded_file(folder / 'manifest.json', 16384, **({'owner': 0, 'group': 0, 'mode': 0o600} if protected else {}))
    require(digest(raw) == IDENTITY_MANIFEST, 'identity_manifest_changed')
    return assets, raw


def identity_delta(helper, old, new):
    """Only one platform loader changes; immutable application stays fixed."""
    old_model, old_hashes = helper.source_model(old[7], PRODUCT_COMMIT)
    new_model, new_hashes = helper.source_model(new[7], IDENTITY_TARGET)
    require(set(old_hashes) == set(new_hashes) and sorted(p for p in old_hashes if old_hashes[p] != new_hashes[p]) == [IDENTITY_SOURCE], 'identity_source_delta')
    for key in ('inherited_canary_sha256', 'shared_preimage_sha256', 'shared_preimage_commits'):
        require(old_model[key] == new_model[key], 'identity_canary_delta')
    require(all(old[i] == new[i] for i in (3, 4, 5, 6)), 'identity_unit_delta')
    config = json.loads(old[0], object_pairs_hook=helper.unique)
    config['reviewed_installed_commit'] = IDENTITY_TARGET
    config['source_sha256'][IDENTITY_SOURCE] = new_hashes[IDENTITY_SOURCE]
    require(new[0] == new[1] == canonical(config), 'identity_configuration_delta')
    approval = json.loads(old[2], object_pairs_hook=helper.unique)
    with tarfile.open(fileobj=io.BytesIO(new[7]), mode='r:') as tar:
        source_manifest = tar.extractfile('.omnilyzer-analytics-source-review.json').read(16385)
    approval.update(reviewed_commit=IDENTITY_TARGET, archive_sha256=digest(new[7]), manifest_sha256=digest(source_manifest))
    require(new[2] == canonical(approval), 'identity_approval_delta')
    def payload(archive):
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
            return tar.extractfile(IDENTITY_SOURCE).read(1048577)
    old_source, new_source = payload(old[7]), payload(new[7])
    require(digest(old_source) == old_hashes[IDENTITY_SOURCE] and digest(new_source) == new_hashes[IDENTITY_SOURCE], 'identity_loader_hash')
    return old_hashes, new_hashes, old_source, new_source


def publish_identity_files(helper, entries, *, forward, checkpoint):
    """Validate the whole six-file preimage before any atomic publication."""
    currents = []
    for path, group, mode, before, after in entries:
        current = helper.bounded_file(path, 1048576, owner=0, group=group, mode=mode)
        require(current == before if forward else current in (before, after), 'identity_live_preimage')
        currents.append(current)
    for i, ((path, group, mode, before, after), current) in enumerate(zip(entries, currents, strict=True)):
        wanted = after if forward else before
        if current != wanted:
            atomic_file(helper, path, wanted, group=group, mode=mode, expected=current, temporary_suffix='.resume-next' if forward else '.resume-recovery-next')
        checkpoint(('published_' if forward else 'restored_') + str(i))
    for path, group, mode, before, after in entries:
        require(helper.bounded_file(path, 1048576, owner=0, group=group, mode=mode) == (after if forward else before), 'identity_publication_readback')


def preserve_identity_source_temporary(helper, private, inventory):
    """Keep the one interrupted source write as private evidence, not code."""
    source = helper.SOURCE_ROOT / IDENTITY_SOURCE
    temporary = source.with_name(source.name + '.resume-next')
    selected = [row for row in inventory if row['path'] == str(temporary)]
    if not selected:return
    require(recovery_temporaries(helper, [(source, 0, 0o644, 1048576)]) == selected, 'identity_source_temporary_changed')
    destination = private / 'interrupted-source.resume-next'
    safe_parent(destination);m = private.lstat()
    require((m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (0, 0, 0o700), 'identity_evidence_directory')
    require(not destination.exists() and not destination.is_symlink(), 'identity_source_evidence_exists')
    before = temporary.lstat();os.rename(temporary, destination);after = destination.lstat()
    require((before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size), 'identity_evidence_identity')
    for parent in (temporary.parent, private):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)


def repair_identity(args):
    """Fixed one-file source correction through the reviewed lifecycle core."""
    os.umask(0o077);helper = load_helper();records = [];phase = 'identity_preflight';outcome = None
    private = IDENTITY_PRIVATE;retained = private / 'new-inputs'
    with provisioning_lock():
        control = AnalyticsServiceControl(BROKER, LISTENER, EXECUTOR, audit=records.append)
        if not args.recover:
            old, before, after = inspect_generation(helper, control, args.workflow_sha)
            new, manifest = identity_inputs(helper, IDENTITY_STAGE, protected=False)
        else:
            safe_parent(private / 'child');m = private.lstat()
            require((m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (0, 0, 0o700), 'identity_recovery_directory')
            old_manifest = helper.stage_manifest(STAGE, MANIFEST_SHA, PRODUCT_COMMIT)
            old = {i: helper.bounded_file(STAGE / row['name'], 1048576, owner=0, group=0, mode=0o600) for i, row in enumerate(old_manifest['assets'])}
            require(all(digest(old[i]) == row['sha256'] and len(old[i]) == row['size'] for i, row in enumerate(old_manifest['assets'])), 'identity_old_stage_hash')
            new, manifest = identity_inputs(helper, retained, protected=True)
            original = helper.bounded_file(ORIGINAL_BROKER, 4096, owner=0, group=0, mode=0o600)
            require(digest(original) == ORIGINAL_BROKER_SHA, 'identity_original_authority')
            base = json.loads(original, object_pairs_hook=helper.unique)
            before = canonical({**base, 'expected_workflow_sha': CURRENT_WORKFLOW})
            after = canonical({**base, 'expected_workflow_sha': args.workflow_sha})
        old_hashes, new_hashes, old_source, new_source = identity_delta(helper, old, new)
        entries = [(helper.SOURCE_ROOT / IDENTITY_SOURCE, 0, 0o644, old_source, new_source)]
        entries += [(Path(helper.DESTINATIONS[i]), helper.GROUPS[i], helper.MODES[i], old[i], new[i]) for i in (0, 1, 2, 7)]
        entries.append((helper.BROKER_CONFIG, 990, 0o640, before, after))
        if args.recover:
            # Qualify retained intent and every known live byte BEFORE stopping.
            for i, (_path, _group, _mode, prior, following) in enumerate(entries):
                require(helper.bounded_file(private / ('before-' + str(i)), 1048576, owner=0, group=0, mode=0o600) == prior, 'identity_backup_preimage')
                current = helper.bounded_file(_path, 1048576, owner=0, group=_group, mode=_mode)
                require(current in (prior, following), 'identity_unknown_live_generation')
            partial = dict(old_hashes)
            partial[IDENTITY_SOURCE] = digest(helper.bounded_file(entries[0][0], 1048576, owner=0, group=0, mode=0o644))
            inventory = recovery_temporaries(helper, [(p, g, m, 1048576) for p,g,m,_b,_a in entries] + [(private / name, 0, 0o600, 8 << 20) for name in ('audit.json', 'recovery-audit.json')] + [(BASE / 'analytics-task014-identity-result.json', 0, 0o644, 16384)])
            records.append(CommandResult('preserved_interrupted_identity_publications', (), 0, canonical(inventory).decode(), ''))
            allowed = [IDENTITY_SOURCE + '.resume-next'] if any(row['path'] == str(entries[0][0]) + '.resume-next' for row in inventory) else []
            closed_tree(helper, helper.SOURCE_ROOT, partial, preserved_temporaries=allowed)
            no_application(helper);control.stop_and_confirm();no_application(helper)
            preserve_identity_source_temporary(helper, private, inventory)
        else:
            require(not private.exists() and not private.is_symlink(), 'identity_repair_already_attempted')
            safe_parent(private);private.mkdir(mode=0o700);retained.mkdir(mode=0o700)
            for parent in (BASE, private):
                fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:os.fsync(fd)
                finally:os.close(fd)
            for i, raw in new.items():atomic_file(helper, retained / ('asset-' + str(i).zfill(2)), raw, group=0, mode=0o600)
            atomic_file(helper, retained / 'manifest.json', manifest, group=0, mode=0o600)
            for i, (_path, _group, _mode, prior, _following) in enumerate(entries):
                atomic_file(helper, private / ('before-' + str(i)), prior, group=0, mode=0o600)
            verified, _manifest = identity_inputs(helper, retained, protected=True)
            require(verified == new, 'identity_retained_inputs_changed')
        audit_path = private / ('recovery-audit.json' if args.recover else 'audit.json')
        def persist():
            require(len(records) <= 1024, 'identity_audit_count')
            raw = canonical({'operation': 'task014_identity_repair', 'phase': phase, 'workflow_sha': args.workflow_sha, 'records': [r.__dict__ for r in records], 'outcome': outcome})
            require(len(raw) <= 8 << 20, 'identity_audit_size')
            current = helper.bounded_file(audit_path, 8 << 20, owner=0, group=0, mode=0o600) if audit_path.exists() else None
            atomic_file(helper, audit_path, raw, group=0, mode=0o600, expected=current, temporary_suffix='.resume-recovery-next' if args.recover else '.resume-next')
        def audit(record):records.append(record);persist()
        control.audit = audit
        def checkpoint(value):
            nonlocal phase
            phase = value;persist();print('IDENTITY_PHASE', phase, flush=True)
        def generation(wanted, hashes):
            closed_tree(helper, helper.SOURCE_ROOT, hashes)
            for i, raw in wanted.items():
                require(helper.bounded_file(Path(helper.DESTINATIONS[i]), 1048576, owner=0, group=helper.GROUPS[i], mode=helper.MODES[i]) == raw, 'identity_generation_readback')
        def restore():
            publish_identity_files(helper, entries, forward=False, checkpoint=checkpoint)
            generation(old, old_hashes)
        def prepare():
            publish_identity_files(helper, entries, forward=True, checkpoint=checkpoint)
            generation(new, new_hashes)
        def complete(value):
            nonlocal outcome
            outcome = value;persist()
            product = None;workflow = None
            try:
                if value['status'] == 'ready_for_signed_task014':
                    generation(new, new_hashes);wanted = after;product = IDENTITY_TARGET;workflow = args.workflow_sha
                elif value['status'] == 'stopped_recovered':
                    generation(old, old_hashes);wanted = before;product = PRODUCT_COMMIT;workflow = CURRENT_WORKFLOW
                else:wanted = None
                if wanted is not None:require(helper.bounded_file(helper.BROKER_CONFIG, 4096, owner=0, group=990, mode=0o640) == wanted, 'identity_workflow_readback')
            except Exception:
                if value['status'] == 'ready_for_signed_task014':raise
                product = None;workflow = None
            raw = canonical({'status': value['status'], 'phase': phase, 'error_code': public_error(value), 'product_commit': product, 'workflow_sha': workflow, 'requested_workflow_sha': args.workflow_sha, 'application_acceptance': 'NOT_YET_VERIFIED', 'signed_task014_dispatch': False, 'database_or_secret_changes': False})
            result = BASE / 'analytics-task014-identity-result.json'
            current = helper.bounded_file(result, 16384, owner=0, group=0, mode=0o644) if result.exists() else None
            atomic_file(helper, result, raw, group=0, mode=0o644, expected=current, temporary_suffix='.resume-recovery-next' if args.recover else '.resume-next')
            print(raw.decode(), end='', flush=True)
        expected = expected_runtime(old)
        if args.recover:
            restore();inspect_generation(helper, control, args.workflow_sha);control.reload_and_verify(expected)
            outcome = {'status': 'stopped_recovered', 'primary_error': None, 'recovery_errors': []}
            checkpoint('identity_restored_control_plane_stopped')
        else:
            outcome = resume_analytics(control, no_application=lambda: no_application(helper), prepare=prepare, restore=restore, expected=expected, probe=lambda: native_probe(helper, control, new, checkpoint, records, product_commit=IDENTITY_TARGET), checkpoint=checkpoint, broker_ready=broker_http_ready, complete=complete)
        if outcome['status'] != 'ready_for_signed_task014':complete(outcome)
        return 0 if outcome['status'] == 'ready_for_signed_task014' or args.recover and outcome['status'] == 'stopped_recovered' else 1



def main(argv=None):
    parser = argparse.ArgumentParser(description='Owner-local frozen Analytics resume')
    parser.add_argument('--workflow-sha', required=True)
    parser.add_argument('--recover', action='store_true')
    parser.add_argument('--repair-identity', action='store_true')
    args = parser.parse_args(argv)
    require(os.getuid() == os.geteuid() == 0 and socket.gethostname().split('.')[0] == 'omnilyzerdev', 'owner_local_dev_root_required')
    require(re.fullmatch(r'[a-f0-9]{40}', args.workflow_sha) and args.workflow_sha not in (CURRENT_WORKFLOW, '0' * 40), 'explicit_reviewed_workflow_required')
    if args.repair_identity:return repair_identity(args)
    os.umask(0o077);helper = load_helper();records = [];phase = 'preflight';outcome = None
    with provisioning_lock():
        control = AnalyticsServiceControl(BROKER, LISTENER, EXECUTOR, audit=records.append)
        if args.recover:
            inventory = recovery_intent(helper, control, args.workflow_sha)
            records.append(CommandResult('preserved_interrupted_publications', (), 0, canonical(inventory).decode(), ''))
        assets, before, after = inspect_generation(helper, control, args.workflow_sha, recovering=args.recover)
        if args.recover:
            m = PRIVATE.lstat();require((m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (0, 0, 0o700), 'private_recovery_directory')
            require(helper.bounded_file(PRIVATE / 'broker-before.json', 4096, owner=0, group=0, mode=0o600) == before, 'retained_workflow_preimage')
            require(helper.bounded_file(PRIVATE / 'broker-target.json', 4096, owner=0, group=0, mode=0o600) == after, 'retained_workflow_target')
        else:
            require(not PRIVATE.exists() and not PRIVATE.is_symlink(), 'resume_already_attempted')
            safe_parent(PRIVATE);PRIVATE.mkdir(mode=0o700)
            fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:os.fsync(fd)
            finally:os.close(fd)
            atomic_file(helper, PRIVATE / 'broker-before.json', before, group=0, mode=0o600)
            atomic_file(helper, PRIVATE / 'broker-target.json', after, group=0, mode=0o600)
        def persist():
            nonlocal records
            require(len(records) <= 1024, 'audit_record_limit')
            raw = canonical({'operation': 'task014_pr269_resume', 'phase': phase, 'workflow_sha': args.workflow_sha, 'records': [entry.__dict__ for entry in records], 'outcome': outcome})
            require(len(raw) <= 8 << 20, 'audit_size_limit')
            path = PRIVATE / ('recovery-audit.json' if args.recover else 'audit.json')
            previous = helper.bounded_file(path, 8 << 20, owner=0, group=0, mode=0o600) if path.exists() else None
            atomic_file(helper, path, raw, group=0, mode=0o600, expected=previous, temporary_suffix='.resume-recovery-next' if args.recover else '.resume-next')
        def audit(result):
            records.append(result)  # Buffer native evidence BEFORE durable I/O.
            persist()
        control.audit = audit
        def checkpoint(value):
            nonlocal phase
            phase = value;persist();print('RESUME_PHASE', phase, flush=True)
        def restore():
            current = helper.bounded_file(helper.BROKER_CONFIG, 4096, owner=0, group=990, mode=0o640)
            require(current in (before, after), 'unknown_workflow_during_restore')
            if current != before:atomic_file(helper, helper.BROKER_CONFIG, before, group=990, mode=0o640, expected=after, temporary_suffix='.resume-recovery-next')
            require(helper.bounded_file(helper.BROKER_CONFIG, 4096, owner=0, group=990, mode=0o640) == before, 'restored_workflow_not_exact')
        expected = expected_runtime(assets)
        def complete(value):
            nonlocal outcome
            outcome = value;persist()
            current = helper.bounded_file(helper.BROKER_CONFIG, 4096, owner=0, group=990, mode=0o640)
            workflow = args.workflow_sha if value['status'] == 'ready_for_signed_task014' and current == after else CURRENT_WORKFLOW if value['status'] == 'stopped_recovered' and current == before else None
            require(value['status'] != 'ready_for_signed_task014' or workflow == args.workflow_sha, 'ready_workflow_readback_mismatch')
            public = {'status': value['status'], 'phase': phase, 'product_commit': PRODUCT_COMMIT, 'workflow_sha': workflow, 'requested_workflow_sha': args.workflow_sha, 'application_acceptance': 'NOT_YET_VERIFIED', 'signed_task014_dispatch': False, 'database_or_secret_changes': False, 'error_code': public_error(value)}
            raw = canonical(public);previous = helper.bounded_file(PUBLIC, 16384, owner=0, group=0, mode=0o644) if PUBLIC.exists() else None
            atomic_file(helper, PUBLIC, raw, group=0, mode=0o644, expected=previous, temporary_suffix='.resume-recovery-next' if args.recover else '.resume-next')
            print(raw.decode(), end='', flush=True)
        if args.recover:
            no_application(helper);control.stop_and_confirm();no_application(helper);restore();control.reload_and_verify(expected)
            outcome = {'status': 'stopped_recovered', 'primary_error': None, 'recovery_errors': [], 'application_acceptance': False}
            checkpoint('metadata_restored_control_plane_stopped')
        else:
            outcome = resume_analytics(
                control, no_application=lambda: no_application(helper),
                prepare=lambda: atomic_file(helper, helper.BROKER_CONFIG, after, group=990, mode=0o640, expected=before),
                restore=restore, expected=expected,
                probe=lambda: native_probe(helper, control, assets, checkpoint, records),
                checkpoint=checkpoint, broker_ready=broker_http_ready, complete=complete,
            )
        if outcome['status'] != 'ready_for_signed_task014':complete(outcome)
        return 0 if outcome['status'] == 'ready_for_signed_task014' or args.recover and outcome['status'] == 'stopped_recovered' else 1


def public_error(outcome):
    """Detailed exceptions/command output stay in the root-private audit."""
    raw = outcome.get('primary_error')
    if raw is None:return None
    if raw.startswith('ServiceFailure:'):
        code = raw.split(':', 1)[1]
        if re.fullmatch(r'[A-Za-z0-9_.-]{1,180}', code):return code
    return 'operation_failed_see_private_audit'


def build_owner_bundle(service_source, owner_source):
    """Combine exact reviewed source bytes; no host writes or install authority."""
    require(type(service_source) is bytes and type(owner_source) is bytes, 'bundle_source_type')
    text = owner_source.decode('utf-8')
    remove = {
        'from __future__ import annotations',
        'from deployment.analytics_service_recovery import AnalyticsServiceControl, CommandResult, ServiceFailure, resume_analytics, _capture_command',
    }
    rows = text.splitlines(keepends=True)
    require(all(sum(row.rstrip('\r\n') == line for row in rows) == 1 for line in remove), 'bundle_import_contract')
    tail = ''.join(row for row in rows if row.rstrip('\r\n') not in remove).encode('utf-8')
    header = ('# Reviewed service SHA256 ' + digest(service_source) + '\n# Reviewed owner-entry SHA256 ' + digest(owner_source) + '\n').encode('ascii')
    bundle = header + service_source + b'\n\n' + tail
    require(len(bundle) <= 98304, 'owner_bundle_size')
    compile(bundle, 'reviewed_task014_owner_bundle', 'exec')
    return bundle


if __name__ == '__main__':
    raise SystemExit(main())
