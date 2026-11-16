#!/usr/bin/python3 -I
"""Issue281: one reviewed PR299 transition from preserved partial D11.

Reuses original FD staging/exchange, config, replay and service primitives.
Only the reviewed active-state module and installed/workflow authority change.
Old partial receipts, source backups and every replay byte remain preserved.
No signed request, package/OCI action, schema/data operation or public ingress.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
SELF = Path('/usr/local/sbin/omnilyzer-m05-pr299-source-transition')
LIB = Path('/usr/local/lib/m05-pr299-source-transition')
FIX = LIB / 'analytics_active_state_review.py'
FIX_SHA = '25a193c3c8511d060d8d1d4b7528edf2671a507cb7b97acde86e33d391d0fddb'
REL = 'deployment/analytics_active_state_review.py'
OLD_SHA = 'e340274f1a2d44f1a7559785314702e503b862e8b3de10a2288b77cce9f9e6d6'
OLD_MAIN = 'd11ce821715b3e1eca2689701065b0e3e2a19e50'
NEW_MAIN = '49256c8340eb30feb586bbc6538a1c8d7bfd2cf3'
SOURCE = Path('/usr/local/lib/m05-analytics016-d11-delivery/operator.py')
SOURCE_SHA = 'e4ea1e0d6d1657672a4aeeafba4d444b72f89223742a7b7ddf339f67e3b6694a'
RECOVERY = Path('/usr/local/sbin/omnilyzer-m05-d11-partial-recovery')
RECOVERY_SHA = '0d38abdf0f8fe285e715f01edb5c5c459131fd182654fefb33745fe29f19df9b'
BASE = Path('/opt/omnilyzer/deployment')
BACKUP = BASE / '.m05-pr299-prior-d11-partial'
RECEIPT = Path('/var/lib/omnilyzer/deployment/.m05-pr299-source-before')
CONSUMED = Path('/var/lib/omnilyzer/deployment/.m05-pr299-source-consumed')
MARKER = RECEIPT / 'source-pr299-installed-no-signed-dispatch'
MARKER_BYTES = b'SOURCE_PR299_49256C8_INSTALLED_NO_SIGNED_DISPATCH\n'
REPORT = 1
PHASE = 'SETUP'
LABELS = frozenset({
    'SETUP', 'OLD_RECEIPT', 'INSTALL_CONSUMED', 'STAGE_ABSENT',
    'OLD_MARKER_ABSENT', 'CURRENT_SOURCE', 'D11_BACKUP', '766_BACKUP',
    'CONFIG_LIVE', 'REPLAY_EQUAL', 'ROUTE_EMPTY', 'BROKER', 'SOCKET',
    'EXECUTOR', 'BLUE_SERVICE', 'BLUE_HEALTH', 'UID991_FIXED_REVIEW',
    'NEW_RECEIPT', 'CAPACITY', 'CONSUMED', 'STAGED', 'SOURCE_EXCHANGE',
    'CONFIG_EXCHANGE', 'UID991_INSTALLED', 'MARKER', 'SERVICES', 'POSTCHECK',
})


def require(ok):
    if ok is not True:
        raise ValueError('fixed source transition hold')


def emit(label, outcome):
    require(label in LABELS and outcome in ('PASS', 'HOLD', 'BLOCKED'))
    os.write(REPORT, ('M05_PR299_' + label + '=' + outcome + '\n').encode('ascii'))


@contextmanager
def confined():
    sys.stdout.flush()
    sys.stderr.flush()
    saved = os.dup(1), os.dup(2)
    null = os.open('/dev/null', os.O_WRONLY)
    try:
        os.dup2(null, 1)
        os.dup2(null, 2)
        yield
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for fd in (*saved, null):
            os.close(fd)


def pinned(path, mode, digest, gid=0):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and
            (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink) ==
            (0, gid, mode, 1) and 0 < before.st_size <= 65536)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(65537)
        after = os.fstat(fd)
        require(hashlib.sha256(raw).hexdigest() == digest and len(raw) == opened.st_size
                and (opened.st_dev, opened.st_ino, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns))
        return raw
    finally:
        os.close(fd)


def library(path, mode, digest):
    raw = pinned(path, mode, digest)
    ns = {'__name__': 'm05_pr299_frozen_' + path.stem, '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), ns)
    return SimpleNamespace(**ns)


def load():
    require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (0, 0, 0, 0)
            and socket.gethostname() == 'omnilyzerdev'
            and len(sys.argv) == 2 and sys.argv[1] in ('--inspect', '--apply-once')
            and os.environ.get('SUDO_COMMAND') == str(SELF) + ' ' + sys.argv[1]
            and str(Path(__file__)) == sys.argv[0])
    os.umask(0o077)
    named = SELF.lstat()
    require(stat.S_ISREG(named.st_mode) and
            (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode), named.st_nlink) ==
            (0, 0, 0o750, 1))
    if sys.argv[0] != str(SELF):
        require(re.fullmatch(r'/(?:proc/self/fd|dev/fd)/[0-9]+', sys.argv[0]) is not None)
        opened = os.fstat(int(sys.argv[0].rsplit('/', 1)[1]))
        require((opened.st_dev, opened.st_ino, opened.st_size) ==
                (named.st_dev, named.st_ino, named.st_size))
    for folder in (SELF.parent, SOURCE.parent, RECEIPT.parent, BASE):
        s = folder.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0
                and stat.S_IMODE(s.st_mode) & 0o022 == 0)
    s = LIB.lstat()
    require(stat.S_ISDIR(s.st_mode) and
            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, 991, 0o750))
    fixed = pinned(FIX, 0o440, FIX_SHA, gid=991)
    op = library(SOURCE, 0o400, SOURCE_SHA)
    legacy = library(RECOVERY, 0o750, RECOVERY_SHA)
    require(op.NEW_MAIN == OLD_MAIN and op.CANDIDATE == BASE / 'analytics-app-candidate')
    prior = op.original()
    previous, _oat, diagnostic = prior.approved_helpers()
    helper = previous.original()
    oldest, current = op.manifest(prior)
    require(len(current) == 76 and current[REL] == OLD_SHA)
    target = dict(current, **{REL: FIX_SHA})
    context = SimpleNamespace(op=op, legacy=legacy, prior=prior, previous=previous,
        diagnostic=diagnostic, helper=helper, old=current, target=target,
        oldest=oldest, fixed=fixed, completed=os.path.lexists(MARKER))
    return context


def configs(context):
    # Reuse the exact original partial receipt/preimage binding, not its
    # failed order-sensitive active-state composite or any consumed main.
    old = SimpleNamespace(op=context.op, prior=context.prior, helper=context.helper,
                          old=context.oldest, target=context.old)
    context.legacy.record(old)
    context.replay = old.replay
    context.before = old.wanted
    context.partial_receipt_sha = context.op.sha(context.prior._bounded_read_only(
        context.op.RECEIPT / 'receipt.json', 4096))
    issuer = json.loads(context.before[context.prior.CONFIG_PATHS[0][0]],
                        object_pairs_hook=context.op.unique)
    model = json.loads(context.before[context.prior.CONFIG_PATHS[1][0]],
                       object_pairs_hook=context.op.unique)
    require(model['reviewed_installed_commit'] == OLD_MAIN
            and model['expected_workflow_sha'] == OLD_MAIN
            and issuer['expected_workflow_sha'] == OLD_MAIN
            and model['schema_version'] == 3
            and model['owner_authorized_first_successor'] is True
            and len(model['source_sha256']) == 26
            and model['source_sha256'][REL] == OLD_SHA)
    nxt = dict(model)
    nxt['source_sha256'] = dict(model['source_sha256'], **{REL: FIX_SHA})
    nxt['reviewed_installed_commit'] = nxt['expected_workflow_sha'] = NEW_MAIN
    context.wanted = {
        context.prior.CONFIG_PATHS[0][0]: context.op.canonical(
            dict(issuer, expected_workflow_sha=NEW_MAIN)),
        context.prior.CONFIG_PATHS[1][0]: context.op.canonical(nxt),
        context.prior.CONFIG_PATHS[2][0]: context.op.canonical(nxt),
    }
    require(all(0 < len(raw) <= 4096 for raw in context.wanted.values()))


def receipt_model(context):
    return {
        'schema_version': 1, 'previous_commit': OLD_MAIN, 'next_commit': NEW_MAIN,
        'previous_partial_receipt': str(context.op.RECEIPT),
        'previous_partial_receipt_sha256': context.partial_receipt_sha,
        'previous_partial_transaction_superseded': True,
        'source_file_count': 76, 'changed_source': REL,
        'previous_source_sha256': OLD_SHA, 'next_source_sha256': FIX_SHA,
        'previous_source_manifest_sha256': context.op.sha(context.op.canonical(context.old)),
        'next_source_manifest_sha256': context.op.sha(context.op.canonical(context.target)),
        'source_backup': str(BACKUP), 'replay_sha256_before': context.replay,
        'last_signed_attempt': 43686555264, 'new_signed_dispatch': False,
    }


def verify_tree(context, path, expected):
    # This transition owns its new backup path; never widen a frozen helper's
    # global allowlist. Reuse only its exact metadata/hash-pinned FD reader.
    require(path in (context.op.CANDIDATE, context.op.STAGE, context.op.BACKUP, BACKUP)
            and len(expected) == 76)
    found = set()
    for folder, dirs, files in os.walk(path, followlinks=False):
        folder = Path(folder)
        for directory in (folder, *(folder / name for name in dirs)):
            s = directory.lstat()
            require(stat.S_ISDIR(s.st_mode) and
                    (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, 0, 0o755))
        for name in files:
            file = folder / name
            relative = file.relative_to(path).as_posix()
            s = file.lstat()
            require(relative in expected and relative not in found
                    and 0 < s.st_size <= 1024 * 1024)
            context.prior.pinned(file, 0, 0, 0o644, s.st_size, expected[relative])
            found.add(relative)
    require(found == set(expected))


def uid991(context, *, installed):
    expected = NEW_MAIN if installed else OLD_MAIN
    if installed:
        selection = ('from deployment import analytics_active_state_review as active\n')
    else:
        selection = (
            'import importlib.util,hashlib\n'
            f'assert hashlib.sha256(open({str(FIX)!r},"rb").read()).hexdigest()=={FIX_SHA!r}\n'
            f'spec=importlib.util.spec_from_file_location("deployment.m05_pr299_review",{str(FIX)!r})\n'
            'active=importlib.util.module_from_spec(spec);sys.modules[spec.name]=active\n'
            'spec.loader.exec_module(active)\n'
        )
    code = (
        'import sys\n'
        f'sys.path.insert(0,{str(context.op.CANDIDATE)!r})\n'
        'from deployment.analytics_executor_service_config import load_analytics_executor_service_config\n'
        'from deployment.analytics_signed_release_consumer import PINNED_DIGEST,PINNED_IMAGE\n'
        'source,ids=load_analytics_executor_service_config(require_successor=True)\n'
        f'assert source["reviewed_installed_commit"]=={expected!r}\n'
        f'assert ids["expected_workflow_sha"]=={expected!r}\n'
        'assert ids["owner_authorized_first_successor"] is True\n'
        'assert ids["expected_executor_uid"]==991 and ids["expected_executor_gid"]==991\n'
        + selection +
        'a=active.inspect_analytics_active_state();b=active.inspect_analytics_active_state()\n'
        'active.verify_empty_analytics_successor_slot()\n'
        'assert a==b and a.active_slot=="blue" and a.active_digest==PINNED_DIGEST\n'
        'assert a.active_image==PINNED_IMAGE and a.candidate_probe_present is False\n'
        'assert a.read_only is True and a.deployment_authorized is False\n'
        'first=active._unix_get(active._ROOTLESS,"/v1/ports")\n'
        'second=active._unix_get(active._ROOTLESS,"/v1/ports")\n'
        'assert active._port_rules_snapshot(first)==active._port_rules_snapshot(second)\n'
        'print("M05_PR299_UID991_BLUE_PASS")\n'
        'print("M05_PR299_RAW_PORT_ORDER_EQUAL" if first==second else "M05_PR299_RAW_PORT_ORDER_DIFFERS_ONLY")\n'
    )
    result = subprocess.run([
        '/usr/bin/setpriv', '--reuid', '991', '--regid', '991', '--groups', '992', '--no-new-privs',
        '/opt/omnilyzer/deployment/venv/bin/python', '-I', '-B', '-c', code,
    ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=45, cwd=str(context.op.CANDIDATE),
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent',
             'PYTHONDONTWRITEBYTECODE': '1'}, check=False)
    require(result.returncode == 0 and result.stdout in (
        b'M05_PR299_UID991_BLUE_PASS\nM05_PR299_RAW_PORT_ORDER_EQUAL\n',
        b'M05_PR299_UID991_BLUE_PASS\nM05_PR299_RAW_PORT_ORDER_DIFFERS_ONLY\n'))
    if result.stdout.endswith(b'M05_PR299_RAW_PORT_ORDER_DIFFERS_ONLY\n'):
        os.write(REPORT, b'M05_PR299_LIVE_ORDER_ONLY_DIFFERENCE_OBSERVED\n')


def check_receipt(context):
    s = RECEIPT.lstat()
    require(stat.S_ISDIR(s.st_mode) and
            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, 0, 0o700))
    raw = context.op.canonical(receipt_model(context))
    context.prior.pinned(RECEIPT / 'receipt.json', 0, 0, 0o600, len(raw), context.op.sha(raw))
    for i, (path, _gid) in enumerate(context.prior.CONFIG_PATHS, 1):
        raw = context.before[path]
        context.prior.pinned(RECEIPT / f'config_{i:02d}.before', 0, 0, 0o600,
                             len(raw), context.op.sha(raw))
    context.prior.pinned(MARKER, 0, 0, 0o600, len(MARKER_BYTES), context.op.sha(MARKER_BYTES))


def inspect(context):
    passed = set()
    op, prior, helper = context.op, context.prior, context.helper
    post = context.completed
    expected = context.target if post else context.old
    checks = [
        ('OLD_RECEIPT', lambda: configs(context), ()),
        ('INSTALL_CONSUMED', lambda: prior.pinned(context.legacy.INSTALL_CONSUMED, 0, 0, 0o600,
            len(b'D11_DELIVERY_ONE_SOURCE_OPERATION_CONSUMED_NO_RETRY\n'),
            op.sha(b'D11_DELIVERY_ONE_SOURCE_OPERATION_CONSUMED_NO_RETRY\n')), ()),
        ('STAGE_ABSENT', lambda: require(not os.path.lexists(op.STAGE)), ()),
        ('OLD_MARKER_ABSENT', lambda: require(not os.path.lexists(op.MARKER)), ()),
        ('CURRENT_SOURCE', lambda: verify_tree(context, op.CANDIDATE, expected), ()),
        ('766_BACKUP', lambda: verify_tree(context, op.BACKUP, context.oldest), ()),
        ('CONFIG_LIVE', lambda: require(all(helper.read_config(path, gid) ==
            (context.wanted if post else context.before)[path]
            for path, gid in prior.CONFIG_PATHS)), ('OLD_RECEIPT',)),
        ('REPLAY_EQUAL', lambda: require(prior.replay_snapshot(context.diagnostic) == context.replay), ('OLD_RECEIPT',)),
        ('ROUTE_EMPTY', lambda: require(not any(op.ROUTE.iterdir())), ()),
        ('BROKER', lambda: require(helper.service_state(op.BROKER) == ('active' if post else 'inactive')), ()),
        ('SOCKET', lambda: require(helper.service_state(op.SOCKET) == ('active' if post else 'inactive')), ()),
        ('EXECUTOR', lambda: require(helper.service_state(op.EXECUTOR) == 'failed'), ()),
        ('BLUE_SERVICE', lambda: require(helper.service_state(op.BLUE) == 'active'), ()),
        ('BLUE_HEALTH', helper.healthy, ()),
        ('UID991_FIXED_REVIEW', lambda: uid991(context, installed=post), ('CURRENT_SOURCE', 'CONFIG_LIVE')),
    ]
    if post:
        checks.extend([
            ('D11_BACKUP', lambda: verify_tree(context, BACKUP, context.old), ()),
            ('NEW_RECEIPT', lambda: check_receipt(context), ('OLD_RECEIPT',)),
        ])
    else:
        checks.append(('NEW_RECEIPT', lambda: require(not any(os.path.lexists(p) for p in
            (RECEIPT, BACKUP, context.legacy.RECOVERY_CONSUMED))), ()))
    for label, callback, dependencies in checks:
        if not set(dependencies) <= passed:
            emit(label, 'BLOCKED')
            continue
        try:
            callback()
        except Exception:
            emit(label, 'HOLD')
        else:
            passed.add(label)
            emit(label, 'PASS')
    return len(passed) == len(checks)


def consume(context):
    fd = os.open(CONSUMED, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, b'PR299_SOURCE_TRANSITION_CONSUMED_NO_RETRY\n')
        os.fsync(fd)
    finally:
        os.close(fd)
    context.helper.fsync_directory(CONSUMED.parent)


def apply(context):
    global PHASE
    op, prior, helper = context.op, context.prior, context.helper
    require(context.completed is False and not os.path.lexists(CONSUMED))
    PHASE = 'CAPACITY'
    space = os.statvfs(str(BASE))
    require(space.f_bavail * space.f_frsize >= 8 * 1024 * 1024 and space.f_favail >= 300)
    PHASE = 'CONSUMED'
    consume(context)
    require(inspect(context))
    prior.admission_closed(helper, context.diagnostic, context.replay)
    source = []
    for name, digest in sorted(context.old.items()):
        path = op.CANDIDATE / name
        raw = prior.pinned(path, 0, 0, 0o644, path.lstat().st_size, digest)
        source.append((name, context.fixed if name == REL else raw))
    require({name: op.sha(raw) for name, raw in source} == context.target)
    installer, temporary = helper.import_pinned_source_installer()
    try:
        PHASE = 'STAGED'
        holder = []
        try:
            fd = installer._open_checked_root(str(BASE), holder, 0, 0)
            installer._stage_new_generation(fd, tuple(source), uid=0, gid=0, successor_source=True)
        finally:
            installer._original._finish_close(holder)
        verify_tree(context, op.STAGE, context.target)
        emit(PHASE, 'PASS')
        RECEIPT.mkdir(mode=0o700)
        for i, (path, _gid) in enumerate(prior.CONFIG_PATHS, 1):
            helper.write_durable(RECEIPT / f'config_{i:02d}.before', context.before[path], 0, 0, 0o600)
        helper.write_durable(RECEIPT / 'receipt.json', op.canonical(receipt_model(context)), 0, 0, 0o600)
        helper.fsync_directory(RECEIPT)
        helper.fsync_directory(RECEIPT.parent)
        prior.admission_closed(helper, context.diagnostic, context.replay)
        verify_tree(context, op.CANDIDATE, context.old)
        require(all(helper.read_config(path, gid) == context.before[path] for path, gid in prior.CONFIG_PATHS))
        PHASE = 'SOURCE_EXCHANGE'
        helper.exchange_directory(op.CANDIDATE, op.STAGE)
        require(not os.path.lexists(BACKUP))
        os.rename(op.STAGE, BACKUP)
        helper.fsync_directory(BASE)
        verify_tree(context, op.CANDIDATE, context.target)
        verify_tree(context, BACKUP, context.old)
        emit(PHASE, 'PASS')
        PHASE = 'CONFIG_EXCHANGE'
        for path, gid in prior.CONFIG_PATHS:
            prior.admission_closed(helper, context.diagnostic, context.replay)
            require(helper.read_config(path, gid) == context.before[path])
            helper.atomic_config(path, context.wanted[path], gid)
            require(helper.read_config(path, gid) == context.wanted[path])
        emit(PHASE, 'PASS')
        PHASE = 'UID991_INSTALLED'
        uid991(context, installed=True)
        prior.admission_closed(helper, context.diagnostic, context.replay)
        emit(PHASE, 'PASS')
        PHASE = 'MARKER'
        helper.write_durable(MARKER, MARKER_BYTES, 0, 0, 0o600)
        helper.fsync_directory(RECEIPT)
        PHASE = 'SERVICES'
        helper.service_action('start', op.SOCKET)
        helper.service_action('start', op.BROKER)
        context.completed = True
        PHASE = 'POSTCHECK'
        require(inspect(context))
        emit(PHASE, 'PASS')
    finally:
        if str(temporary) in sys.path:
            sys.path.remove(str(temporary))
        shutil.rmtree(temporary)


def main():
    global REPORT
    REPORT = os.dup(1)
    try:
        with confined():
            context = load()
            if sys.argv[1] == '--apply-once':
                apply(context)
            elif not inspect(context):
                return 2
        os.write(REPORT, b'M05_PR299_SOURCE_READY_NOT_ANALYTICS_016_DEPLOYED\n'
                 if context.completed else b'M05_PR299_READONLY_PREWRITE_PASS\n')
        return 0
    except Exception:
        emit(PHASE, 'HOLD')
        os.write(REPORT, b'M05_PR299_HARD_HOLD_NO_AUTORETRY\n')
        return 2
    finally:
        os.close(REPORT)


if __name__ == '__main__':
    raise SystemExit(main())
