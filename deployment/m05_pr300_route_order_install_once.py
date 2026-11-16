"""One source-bound DEV recovery for consumed signed run43827257114.

Retire only its proven-unrouted green, install PR300's one-file correction,
rebind existing root workflow/source authority, preserve replay and backups.
No signing, release dispatch, image build/pull, database or public operation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import traceback
import urllib.request

BASE = '49256c8340eb30feb586bbc6538a1c8d7bfd2cf3'
HEAD = '961301afcda2e62c6e14cc730becc0b4e3b65af1'
TREE = 'c152325af29f69b964e33da94869df26211288bc'
ROOT = Path('/opt/omnilyzer/deployment/analytics-app-candidate')
REL = 'deployment/analytics_loopback_guard.py'
OLD = 'f9fdf88b26d0faaaaf779bc61af3ae8e5b563150f96ed1d424842ffaed14e40c'
NEW = 'b5990fd7ab74163f414db41517b207968d1ca72d2b8ffb90e167d1c8a1637eda'
ACTIVE = '25a193c3c8511d060d8d1d4b7528edf2671a507cb7b97acde86e33d391d0fddb'
FIX = Path('/home/trust/m05-pr300-source-review/analytics_loopback_guard.py')
MANIFEST = Path('/home/trust/m05-pr296-source-install-review/m05_296_source_delta_manifest.json')
MANIFEST_SHA = '989e87539847261cc5b0a955284947df724ec415cc9a0f14a2808bfb05e1224f'
RECEIPT = Path('/var/lib/omnilyzer/deployment/.m05-pr300-route-order-before')
REPLAY = Path('/var/lib/omnilyzer/deployment/authority/replay.sqlite3')
JOURNAL = Path('/var/lib/omnilyzer/deployment/analytics-route')
BLUE = '227318fc3e8f4a9e2c6b6a6a269f4a2de4052c785ac05014d77a30c93fc4fb47'
GREEN = '31490aac1b0aa40fbe19a30fcc126a1303b6ca147a5532f6f19d88e503614ad7'
IMAGE = 'oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1'
CONFIGS = ((Path('/etc/omnilyzer/deployment/broker/dev.json'), 990),
           (Path('/etc/omnilyzer/deployment/dev/analytics-executor.json'), 991),
           (Path('/etc/omnilyzer/deployment/broker/analytics.json'), 990))
BROKER = 'omnilyzer-deployment-broker.service'
SOCKET = 'omnilyzer-deployment-analytics-executor.socket'
EXECUTOR = 'omnilyzer-deployment-analytics-executor.service'
SUPERVISOR = 'omnilyzer-analytics-loopback.service'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent'}
PHASE = 'PREFLIGHT'


def need(value):
    if not value:
        raise ValueError('M05_PR300_PREDICATE_HOLD')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, uid, gid, mode, digest=None, maximum=1048576):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and (before.st_uid, before.st_gid,
         stat.S_IMODE(before.st_mode), before.st_nlink) == (uid, gid, mode, 1)
         and 0 < before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    need(len(raw) == before.st_size and
         (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    need(digest is None or sha(raw) == digest)
    return raw


def run(argv, timeout=30):
    result = subprocess.run(argv, capture_output=True, timeout=timeout, env=ENV)
    if result.returncode != 0 or len(result.stdout) >= 262144:
        # These closed commands return only source/route/status metadata;
        # no JWT, environment dump, database row or credential is requested.
        print('M05_PR300_NATIVE_FAILURE', Path(argv[0]).name, result.returncode, flush=True)
        print(result.stdout.decode('utf-8', 'replace'), flush=True)
        print(result.stderr.decode('utf-8', 'replace'), file=sys.stderr, flush=True)
        raise RuntimeError('NATIVE_COMMAND_FAILED')
    return result.stdout.decode()


def uid991(code):
    return json.loads(run(['/usr/bin/setpriv', '--reuid', '991', '--regid', '991',
        '--groups', '992', '--no-new-privs', '/usr/bin/python3', '-I', '-B', '-c',
        "import sys;sys.path.insert(0," + repr(str(ROOT)) + ");" + code]))


def routes():
    return uid991("import json;from deployment import analytics_loopback_guard as g;"
        "g._rootless_info();g._verified_slot('blue',g._IMAGE," + repr(BLUE) + ");"
        "g._http_ready('/readyz');g._http_ready('/livez');"
        "p=g._raw_rules();assert len(p)==2 and sum(x['spec']==g._CANARY for x in p)==1 "
        "and sum(x['spec']==g._TARGET for x in p)==1;"
        "print(json.dumps(sorted(p,key=lambda x:x['id'])))")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('SOURCE_METADATA_REDIRECT_HOLD')


def reviewed_merge():
    url = 'https://api.github.com/repos/MichaelTrueX/omnilyzer-platform/commits/main'
    request = urllib.request.Request(url, headers={'User-Agent': 'Omnilyzer-M05-reviewed-source'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        raw = response.read(262145)
    need(len(raw) <= 262144)
    value = json.loads(raw)
    need(value['commit']['tree']['sha'] == TREE and
         [p['sha'] for p in value['parents']] == [BASE, HEAD] and
         value['commit']['verification']['verified'] is True and
         re.fullmatch('[a-f0-9]{40}', value['sha']) and value['sha'] != BASE)
    return value['sha']


def source_manifest():
    value = json.loads(checked(MANIFEST, 1001, 1001, 0o600, MANIFEST_SHA))
    need(value['source_file_count'] == 76 and value['next_commit'] ==
         'd11ce821715b3e1eca2689701065b0e3e2a19e50')
    model = dict(value['next_source_sha256'])
    model['deployment/analytics_active_state_review.py'] = ACTIVE
    need(len(model) == 76 and model[REL] == OLD)
    return model


def verify_source(expected):
    for name in (Path('/opt'), Path('/opt/omnilyzer'), ROOT.parent):
        s = name.lstat()
        need(stat.S_ISDIR(s.st_mode) and (s.st_uid, s.st_gid,
             stat.S_IMODE(s.st_mode)) == (0, 0, 0o755))
    found = set()
    for folder, dirs, files in os.walk(ROOT, followlinks=False):
        for name in [Path(folder), *(Path(folder) / d for d in dirs)]:
            s = name.lstat()
            need(stat.S_ISDIR(s.st_mode) and (s.st_uid, s.st_gid,
                 stat.S_IMODE(s.st_mode)) == (0, 0, 0o755))
        for name in files:
            path = Path(folder) / name
            rel = str(path.relative_to(ROOT))
            need(rel in expected)
            checked(path, 0, 0, 0o644, expected[rel])
            found.add(rel)
    need(found == set(expected))


def configs(main, expected):
    before, after = {}, {}
    for index, (path, gid) in enumerate(CONFIGS):
        parent = path.parent.lstat()
        need(stat.S_ISDIR(parent.st_mode) and (parent.st_uid, parent.st_gid,
             stat.S_IMODE(parent.st_mode)) == (0, gid, 0o750))
        raw = checked(path, 0, gid, 0o640, maximum=4096)
        value = json.loads(raw)
        need(canonical(value) == raw and value['expected_workflow_sha'] == BASE)
        before[str(path)] = raw
        if index:
            need(value['schema_version'] == 3 and value['owner_authorized_first_successor'] is True
                 and value['reviewed_installed_commit'] == BASE and len(value['source_sha256']) == 26
                 and all(expected[k] == v for k, v in value['source_sha256'].items())
                 and value['source_sha256'][REL] == OLD)
            value['reviewed_installed_commit'] = main
            value['source_sha256'][REL] = NEW
        value['expected_workflow_sha'] = main
        after[str(path)] = canonical(value)
    need(before[str(CONFIGS[1][0])] == before[str(CONFIGS[2][0])])
    return before, after


def replay_check():
    c = sqlite3.connect(REPLAY.as_uri() + '?mode=ro', uri=True, isolation_level=None)
    try:
        c.execute('PRAGMA query_only=ON')
        rows = c.execute('SELECT github_run_id,status FROM consumptions WHERE github_run_id IN (?,?) ORDER BY github_run_id',
                         (43813770692, 43827257114)).fetchall()
        need(rows == [(43813770692, 'executing'), (43827257114, 'executing')])
    finally:
        c.close()
    return sha(REPLAY.read_bytes())


def green_before():
    return uid991("import json;from deployment import analytics_loopback_guard as g;"
        "g._verified_slot('green'," + repr(IMAGE) + ',' + repr(GREEN) + ");"
        "from deployment.analytics_route_journal import AnalyticsRouteJournal;"
        "j=AnalyticsRouteJournal();assert j.read() is None;"
        "print(json.dumps({'id':" + repr(GREEN) + ",'image':" + repr(IMAGE) + "}))")


def units():
    for unit in (BROKER, SOCKET, SUPERVISOR):
        need(run(['/usr/bin/systemctl', 'is-active', unit]).strip() == 'active')
    need(run(['/usr/bin/systemctl', 'show', EXECUTOR, '--property=MainPID', '--value']).strip() == '0')
    need(run(['/usr/bin/systemctl', 'show', SUPERVISOR, '--property=ExecStopPost', '--value']).strip() == '')
    need('analytics-v3-supervisor.conf' in run(['/usr/bin/systemctl', 'show', SUPERVISOR, '--property=DropInPaths', '--value']))
    checked(Path('/opt/omnilyzer/deployment/analytics-loopback/analytics_loopback_successor_supervisor.py'),
            0, 0, 0o644, 'e6db998859197bf3454a183ca4c26fc9e80787e5ad4cc82f90b4d37bb4d1e57c')


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, raw, gid, mode):
    fd, temporary = tempfile.mkstemp(prefix='.m05-pr300-', dir=path.parent)
    try:
        os.fchown(fd, 0, gid); os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, path); sync_dir(path.parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def docker(*args):
    return run(['/usr/bin/setpriv', '--reuid', '991', '--regid', '991', '--groups', '992',
        '--no-new-privs', '/usr/bin/docker', '--config', '/nonexistent', '--host',
        'unix:///run/user/991/docker.sock', *args], timeout=45)


def apply(c):
    global PHASE
    RECEIPT.mkdir(mode=0o700)  # Durable exclusive receipt also consumes this operation.
    for i, (path, _) in enumerate(CONFIGS):
        write_new(RECEIPT / ('config%d.before' % i), c['configs'][0][str(path)])
        write_new(RECEIPT / ('config%d.after' % i), c['configs'][1][str(path)])
    write_new(RECEIPT / 'guard.before', checked(ROOT / REL, 0, 0, 0o644, OLD))
    write_new(RECEIPT / 'receipt.json', canonical({
        'old_main': BASE, 'new_main': c['merge'], 'reviewed_head': HEAD,
        'guard_old': OLD, 'guard_new': NEW, 'failed_run': 43827257114,
        'failed_green': GREEN, 'replay_before': c['replay'],
        'routes_before': c['routes'], 'signed_dispatch': False}))
    sync_dir(RECEIPT); sync_dir(RECEIPT.parent)
    PHASE = 'ADMISSION_CLOSED'
    run(['/usr/bin/systemctl', 'stop', SOCKET]); run(['/usr/bin/systemctl', 'stop', BROKER])
    need(run(['/usr/bin/systemctl', 'show', EXECUTOR, '--property=MainPID', '--value']).strip() == '0')
    need(replay_check() == c['replay'] and routes() == c['routes'])
    verify_source(c['sources'])
    for path, gid in CONFIGS:
        need(checked(path, 0, gid, 0o640) == c['configs'][0][str(path)])
    PHASE = 'STOP_UNROUTED_GREEN'
    write_new(RECEIPT / 'green-before.json', canonical(c['green']))
    docker('stop', '--time', '20', GREEN)
    need(routes() == c['routes'])
    need(docker('inspect', '--format', '{{.State.Running}}', GREEN).strip() == 'false')
    PHASE = 'SOURCE_AND_CONFIG'
    atomic(ROOT / REL, c['fix'], 0, 0o644)
    for path, gid in CONFIGS:
        atomic(path, c['configs'][1][str(path)], gid, 0o640)
    expected = dict(c['sources']); expected[REL] = NEW
    verify_source(expected)
    check = uid991("import json;from deployment.analytics_executor_service_config import load_analytics_executor_service_config;"
        "s,i=load_analytics_executor_service_config(require_successor=True);"
        "print(json.dumps(i['expected_workflow_sha']))")
    need(check == c['merge'] and routes() == c['routes'] and replay_check() == c['replay'])
    PHASE = 'RETIRE_FAILED_CONTAINER'
    need(not list(JOURNAL.iterdir()))
    docker('rm', GREEN)  # No volumes/image/cache/database removal.
    uid991("import json;from deployment.analytics_active_state_review import verify_empty_analytics_successor_slot;"
        "verify_empty_analytics_successor_slot();print(json.dumps(True))")
    PHASE = 'SERVICES'
    run(['/usr/bin/systemctl', 'restart', SUPERVISOR])  # V3 stop has no route cleanup.
    run(['/usr/bin/systemctl', 'start', SOCKET]); run(['/usr/bin/systemctl', 'start', BROKER])
    units()
    need(routes() == c['routes'] and replay_check() == c['replay'])
    write_new(RECEIPT / 'source-ready-no-signed-dispatch', b'PR300_SOURCE_READY_NO_SIGNED_DISPATCH\n')
    sync_dir(RECEIPT)
    print('M05_PR300_SOURCE_READY_BLUE_HEALTHY_GREEN_ABSENT_NO_RELEASE')


def main():
    p = Path(__file__); parent = p.parent.lstat(); s = p.lstat()
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0 and socket.gethostname().split('.')[0] == 'omnilyzerdev'
         and len(sys.argv) == 2 and sys.argv[1] in ('--inspect', '--apply-once')
         and p.parent.parent == Path('/run') and p.parent.name.startswith('m05-pr300-source.')
         and stat.S_ISDIR(parent.st_mode) and (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)) == (0, 0, 0o700)
         and stat.S_ISREG(s.st_mode) and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) == (0, 0, 0o400, 1))
    c, failed = {}, []
    def check(name, function, dependencies=()):
        if any(d not in c for d in dependencies):
            print('M05_PR300_' + name + '=BLOCKED'); failed.append(name); return
        try:
            c[name] = function(); print('M05_PR300_' + name + '=PASS')
        except Exception as error:
            frame = traceback.extract_tb(error.__traceback__)[-1]
            print('M05_PR300_' + name + '=HOLD:' + type(error).__name__
                  + ':' + frame.name + ':' + str(frame.lineno)); failed.append(name)
    check('merge', reviewed_merge)
    check('fix', lambda: checked(FIX, 1001, 1001, 0o600, NEW))
    check('sources', lambda: source_manifest())
    check('closed_tree', lambda: verify_source(c['sources']), ('sources',))
    check('configs', lambda: configs(c['merge'], c['sources']), ('merge', 'sources'))
    check('replay', replay_check)
    check('routes', routes, ('closed_tree',))
    check('green', green_before, ('closed_tree',))
    check('units', units)
    check('unused', lambda: need(not os.path.lexists(RECEIPT)))
    need(not failed)
    if sys.argv[1] == '--apply-once':
        apply(c)
    else:
        print('M05_PR300_COMPLETE_READONLY_PREFLIGHT_PASS')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        print('M05_PR300_HARD_HOLD_NO_RETRY phase=' + PHASE + ' type=' + type(error).__name__
              + ' at=' + frame.name + ':' + str(frame.lineno))
        raise SystemExit(1)
