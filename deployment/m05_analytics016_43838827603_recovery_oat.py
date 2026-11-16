"""One owner-authorized PRIVATE DEV rollback/return OAT for a finished release.

Not a deployment interface: no request, pull, start, signature or replay writes.
Uses only the installed checked route primitives and the exact finished signed
run. Preserve the original request binding and before/after recovery evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys

ROOT = Path('/opt/omnilyzer/deployment/analytics-app-candidate')
FIXTURE = Path('/run/m05-analytics016-43838827603-acceptance.py')
REPLAY = Path('/var/lib/omnilyzer/deployment/authority/replay.sqlite3')
RECEIPT = Path('/var/lib/omnilyzer/deployment/.m05-analytics016-43838827603-recovery-oat')
REQUEST = '73071f42dffcce2dc7eaa2cf494335b6cc7e85eb7346c074529065f4fb079004'
BLUE = '227318fc3e8f4a9e2c6b6a6a269f4a2de4052c785ac05014d77a30c93fc4fb47'
GREEN = 'c160029c449cbdf37f35515dd25e5e2235cdeb08f3eebe6525fee17d2d839432'
IMAGE15 = 'oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1'
IMAGE16 = 'oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent',
       'ANALYTICS_REVIEWED_SUPERVISOR_V2': '1'}


def save(name, value):
    b = (json.dumps(value, sort_keys=True) + '\n').encode()
    fd = os.open(RECEIPT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, b)
        os.fsync(fd)
    finally:
        os.close(fd)
    d = os.open(RECEIPT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def replay():
    with sqlite3.connect('file:' + str(REPLAY) + '?mode=ro', uri=True) as c:
        c.execute('PRAGMA query_only=ON')
        assert c.execute('SELECT executor_request_sha256,status FROM consumptions '
                         'WHERE github_run_id=43838827603 AND github_run_attempt=1').fetchall() == [(REQUEST, 'finished')]
    return hashlib.sha256(REPLAY.read_bytes()).hexdigest()


def uid991(action):
    # Fixed source, fixed identities, no request-controlled Python or OCI.
    code = '''import sys,json
sys.path.insert(0, %r)
from deployment.analytics_executor_service_config import load_analytics_executor_service_config
_,identity=load_analytics_executor_service_config(require_successor=True)
assert identity['expected_workflow_sha']=='c6d6b067f932e60d82f8b7a9d75a2629a62606c8'
from deployment import analytics_loopback_guard as g
from deployment.analytics_route_journal import AnalyticsRouteJournal
from deployment.analytics_active_state_review import inspect_committed_analytics_route
j=AnalyticsRouteJournal()
args=dict(previous_slot='blue',previous_image=%r,previous_id=%r,next_slot='green',next_image=%r,next_id=%r,journal=j,request_sha256=%r)
def confirm(slot,image,cid):
    inspect_committed_analytics_route(journal=j,reviewed_image=image,reviewed_slot=slot,reviewed_container_id=cid,reviewed_request_sha256=%r)
''' % (str(ROOT), IMAGE15, BLUE, IMAGE16, GREEN, REQUEST, REQUEST)
    if action == 'rollback':
        code += "confirm('green',args['next_image'],args['next_id']);g._rollback_committed_private_successor(**args);confirm('blue',args['previous_image'],args['previous_id'])\n"
    elif action == 'return':
        code += "confirm('blue',args['previous_image'],args['previous_id']);g._stage_reviewed_private_candidate_probe(**args);g._switch_reviewed_private_route(**args);confirm('green',args['next_image'],args['next_id'])\n"
    elif action == 'inspect':
        code += "confirm('green',args['next_image'],args['next_id'])\n"
    else:
        raise ValueError('unknown OAT operation')
    code += "print(json.dumps(dict(journal=j.read(),routes=g._raw_rules())))\n"
    result = subprocess.run(['/usr/bin/setpriv', '--reuid', '991', '--regid', '991',
        '--groups', '992', '--no-new-privs', '/usr/bin/python3', '-I', '-B', '-c', code],
        env=ENV, capture_output=True, text=True, timeout=50)
    if result.returncode:
        raise RuntimeError('route OAT ' + action + ': ' + result.stderr[-1500:])
    return json.loads(result.stdout)


def database_snapshot(m, database, principal):
    # Only aggregate hashes leave PG; no rows, secrets, migrations or writes.
    tables = ('User', 'Session', 'Workspace', 'WorkspaceMembership', 'Website',
              'WorkspaceAnalyticsEvent', 'WorkspaceAnalyticsDaily', 'WebsiteAnalyticsDaily')
    statements = ['BEGIN READ ONLY;']
    for table in tables:
        statements.append('SELECT ' + m['sql_literal'](table) + ',count(*),'
            "md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')) "
            'FROM public."' + table + '" t;')
    statements.append('ROLLBACK;')
    return m['sql'](database, principal, '\n'.join(statements) + '\n')


def main():
    assert sys.argv[1:] in (['--inspect'], ['--run-once'])
    assert os.geteuid() == 0
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == 'd89d9ed277ea7dcb663b6c02ec93f8be01e9d7a59c1558eb42c9ff431a24c92e'
    assert hashlib.sha256((ROOT / 'deployment/analytics_loopback_guard.py').read_bytes()).hexdigest() == 'b5990fd7ab74163f414db41517b207968d1ca72d2b8ffb90e167d1c8a1637eda'
    m = runpy.run_path(str(FIXTURE))  # Definitions only; never fixture main.
    failures = []
    before = {}
    def check(name, fn):
        try:
            before[name] = fn()
            print('RECOVERY_OAT_READONLY_PASS', name, flush=True)
        except Exception as error:
            failures.append(name)
            print('RECOVERY_OAT_READONLY_FAIL', name, type(error).__name__, str(error)[:250], flush=True)
    check('runtime', m['signed_private_runtime'])
    check('replay', replay)
    check('route', lambda: uid991('inspect'))
    def data():
        database = before['runtime'][1]
        principal = m['postgres_principal'](database)
        return database_snapshot(m, database, principal)
    check('database', data)
    check('no_prior_oat', lambda: not RECEIPT.exists() or (_ for _ in ()).throw(ValueError('consumed OAT')))
    if failures:
        return 2
    if sys.argv[1] == '--inspect':
        return 0
    RECEIPT.mkdir(mode=0o700)  # Exclusive consumption before any route mutation.
    save('before.json', before)
    try:
        restored = uid991('rollback')
        save('restored015.json', restored)
        assert data() == before['database'] and replay() == before['replay']
        print('RECOVERY_OAT_REAL015_ROLLBACK_PASS data_preserved=true', flush=True)
        returned = uid991('return')
        save('returned016.json', returned)
        assert data() == before['database'] and replay() == before['replay']
        assert [x for x in before['route']['routes'] if x['spec']['parentPort'] == 3020] == [x for x in returned['routes'] if x['spec']['parentPort'] == 3020]
        m['signed_private_runtime']()
        save('result.json', {'pass': True, 'replay_unchanged': True, 'database_unchanged': True})
        print('RECOVERY_OAT_RETURN016_PASS data_preserved=true replay_unchanged=true', flush=True)
        return 0
    except Exception as error:
        save('hold.json', {'type': type(error).__name__, 'detail': str(error)[:2000]})
        print('RECOVERY_OAT_HARD_HOLD_NO_AUTORETRY', type(error).__name__, str(error)[:2000], flush=True)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
