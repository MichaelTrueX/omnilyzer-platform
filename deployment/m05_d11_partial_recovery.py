#!/usr/bin/python3 -I
"""Issue281: inspect and finish only the existing partial D11 transaction.

No source exchange, config rewrite, signed request, replay reset or OCI action.
The two exact sudo commands permit read-only inspection and one missing-tail
completion under the unchanged reviewed source operator's strict UID991 gate.
"""
import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True

SELF = Path('/usr/local/sbin/omnilyzer-m05-d11-partial-recovery')
SOURCE = Path('/usr/local/lib/m05-analytics016-d11-delivery/operator.py')
SOURCE_SHA = 'e4ea1e0d6d1657672a4aeeafba4d444b72f89223742a7b7ddf339f67e3b6694a'
INSTALL_CONSUMED = Path('/var/lib/omnilyzer/deployment/.m05-d11-delivery-fd-command-consumed')
RECOVERY_CONSUMED = Path('/var/lib/omnilyzer/deployment/.m05-d11-delivery-recovery-consumed')
MODES = ('--inspect', '--finish-once')


def require(ok):
    if ok is not True:
        raise ValueError('fixed recovery hold')


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


def root_file(path, mode):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and
            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) ==
            (0, 0, mode, 1))
    return s


def load():
    require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (0, 0, 0, 0)
            and socket.gethostname() == 'omnilyzerdev'
            and len(sys.argv) == 2 and sys.argv[1] in MODES
            and os.environ.get('SUDO_COMMAND') == str(SELF) + ' ' + sys.argv[1]
            and str(Path(__file__)) == sys.argv[0])
    os.umask(0o077)
    root_file(SELF, 0o750)
    if sys.argv[0] != str(SELF):
        require(re.fullmatch(r'/(?:proc/self/fd|dev/fd)/[0-9]+', sys.argv[0]) is not None)
        fd = int(sys.argv[0].rsplit('/', 1)[1])
        opened, named = os.fstat(fd), SELF.lstat()
        require((opened.st_dev, opened.st_ino, opened.st_size) ==
                (named.st_dev, named.st_ino, named.st_size))
    for folder in (SELF.parent, SOURCE.parent, INSTALL_CONSUMED.parent):
        s = folder.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0
                and stat.S_IMODE(s.st_mode) & 0o022 == 0)
    before = root_file(SOURCE, 0o400)
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(65537)
        after = os.fstat(fd)
        require(0 < len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == SOURCE_SHA
                and (opened.st_dev, opened.st_ino, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns))
    finally:
        os.close(fd)
    ns = {'__name__': 'm05_verified_d11_recovery_source', '__file__': str(SOURCE)}
    exec(compile(raw, str(SOURCE), 'exec'), ns)
    op = SimpleNamespace(**ns)
    prior = op.original()
    previous, _oat, diagnostic = prior.approved_helpers()
    helper = previous.original()
    old, target = op.manifest(prior)
    return SimpleNamespace(op=op, prior=prior, previous=previous,
                           diagnostic=diagnostic, helper=helper, old=old, target=target)


def record(context):
    op, prior = context.op, context.prior
    s = op.RECEIPT.lstat()
    require(stat.S_ISDIR(s.st_mode) and
            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, 0, 0o700))
    path = op.RECEIPT / 'receipt.json'
    raw = prior._bounded_read_only(path, 4096)
    model = json.loads(raw, object_pairs_hook=op.unique)
    replay = model['replay_sha256_before']
    require(type(replay) is str and re.fullmatch('[0-9a-f]{64}', replay) is not None
            and raw == op.canonical(op.receipt_model(prior, replay)))
    context.replay = replay
    context.configs = {
        path: prior._bounded_read_only(op.RECEIPT / f'config_{i:02d}.before', 4096)
        for i, (path, _gid) in enumerate(prior.CONFIG_PATHS, 1)
    }
    context.wanted = op.updated_configs(prior, context.helper, context.configs,
                                        context.old, context.target)


def marker(context):
    op, prior = context.op, context.prior
    context.completed = os.path.lexists(op.MARKER)
    if context.completed:
        prior.pinned(op.MARKER, 0, 0, 0o600, len(op.MARKER_BYTES), op.sha(op.MARKER_BYTES))


def uid991_diagnostic(op, target=()):
    """Same child statements, AST-equal line breaks; capture no raw output.

    This diagnostic is NEVER the completion gate. --finish-once calls the
    original unchanged exact subprocess separately before any missing-tail write.
    """
    original = subprocess.run
    observations = []

    def observe(args, **kwargs):
        require(args[:2] == ['/usr/bin/setpriv', '--reuid'] and
                args[-2] == '-c' and type(args[-1]) is str
                and kwargs['stderr'] == subprocess.DEVNULL)
        code = args[-1]
        lines = code.replace(';', ';\n')
        require(ast.dump(ast.parse(code)) == ast.dump(ast.parse(lines)))
        files = {str(op.CANDIDATE / name): i for i, name in enumerate(sorted(target))}
        # Exception events expose only a bounded code-file index and line,
        # including errors hidden by the loader's generic outer exception.
        # Never inspect exception values, locals, globals or runtime data.
        prelude = (
            'import sys,atexit,os\n'
            f'_m05_files={files!r}\n'
            '_m05_events=[]\n'
            'def _m05_trace(frame,event,arg):\n'
            ' if event=="exception" and frame.f_code.co_filename in _m05_files:\n'
            '  pair=(_m05_files[frame.f_code.co_filename],frame.f_lineno)\n'
            '  if pair not in _m05_events: _m05_events.append(pair)\n'
            '  del _m05_events[:-32]\n'
            ' return _m05_trace\n'
            'def _m05_flush():\n'
            ' for file,line in _m05_events:\n'
            '  os.write(2,("M05_CHILD_TRACE %d %d\\n"%(file,line)).encode("ascii"))\n'
            'atexit.register(_m05_flush)\n'
            'sys.settrace(_m05_trace)\n'
            f'exec(compile({lines!r},"<string>","exec"))\n'
        )
        kwargs['stderr'] = subprocess.PIPE
        try:
            result = original([*args[:-1], prelude], **kwargs)
        except subprocess.TimeoutExpired:
            observations.append('TIMEOUT')
            raise
        observations.append('EXIT_ZERO' if result.returncode == 0 else 'EXIT_NONZERO')
        observations.append('STDOUT_EXACT' if result.stdout ==
                            b'M05_016_DELIVERY_UID991_SOURCE_BLUE_PASS\n' else 'STDOUT_DIFFERS')
        # Print only a numeric statement position in the first-party -c code.
        # stderr may contain protected bytes and is never printed or persisted.
        positions = re.findall(rb'File "<string>", line ([0-9]+)', result.stderr)
        if positions:
            observations.append('CHILD_STATEMENT_' + str(int(positions[-1])))
        if result.returncode != 0:
            for file, line in re.findall(rb'^M05_CHILD_TRACE ([0-9]+) ([0-9]+)$',
                                         result.stderr, re.MULTILINE):
                if int(file) < len(files) and 0 < int(line) <= 100000:
                    observations.append('TRACE_FILE_' + str(int(file)) + '_LINE_' + str(int(line)))
        return result

    try:
        subprocess.run = observe
        op.uid991_source_preflight()
    finally:
        subprocess.run = original
        op._m05_diagnostic_observations = observations


def inspect(context, *, diagnose):
    op, prior, helper = context.op, context.prior, context.helper
    passed = set()
    checks = (
        ('RECEIPT_PREIMAGES', lambda: record(context), ()),
        ('INSTALL_CONSUMED', lambda: prior.pinned(
            INSTALL_CONSUMED, 0, 0, 0o600,
            len(b'D11_DELIVERY_ONE_SOURCE_OPERATION_CONSUMED_NO_RETRY\n'),
            op.sha(b'D11_DELIVERY_ONE_SOURCE_OPERATION_CONSUMED_NO_RETRY\n')), ()),
        ('STAGE_ABSENT', lambda: require(not os.path.lexists(op.STAGE)), ()),
        ('CURRENT_SOURCE', lambda: op.verify_tree(op.CANDIDATE, context.target), ()),
        ('BACKUP_SOURCE', lambda: op.verify_tree(op.BACKUP, context.old), ()),
        ('CONFIG_LIVE', lambda: require(all(helper.read_config(path, gid) == context.wanted[path]
            for path, gid in prior.CONFIG_PATHS)), ('RECEIPT_PREIMAGES',)),
        ('MARKER', lambda: marker(context), ()),
        ('REPLAY_EQUAL', lambda: require(prior.replay_snapshot(context.diagnostic) == context.replay),
            ('RECEIPT_PREIMAGES',)),
        ('ROUTE_EMPTY', lambda: require(not any(op.ROUTE.iterdir())), ()),
        ('BROKER', lambda: require(helper.service_state(op.BROKER) ==
            ('active' if context.completed else 'inactive')), ('MARKER',)),
        ('SOCKET', lambda: require(helper.service_state(op.SOCKET) ==
            ('active' if context.completed else 'inactive')), ('MARKER',)),
        ('EXECUTOR', lambda: require(helper.service_state(op.EXECUTOR) == 'failed'), ()),
        ('BLUE_SERVICE', lambda: require(helper.service_state(op.BLUE) == 'active'), ()),
        ('BLUE_HEALTH', helper.healthy, ()),
        ('ACTIVE_STABLE', context.diagnostic['active_state_stable'], ()),
        ('UID991_DIAGNOSTIC' if diagnose else 'UID991_EXACT',
            lambda: uid991_diagnostic(op, context.target) if diagnose else op.uid991_source_preflight(), ()),
    )
    for name, callback, dependencies in checks:
        if not set(dependencies) <= passed:
            print('M05_D11_RECOVERY_' + name + '=BLOCKED', flush=True)
            continue
        try:
            with confined():
                callback()
        except Exception:
            print('M05_D11_RECOVERY_' + name + '=HOLD', flush=True)
        else:
            passed.add(name)
            print('M05_D11_RECOVERY_' + name + '=PASS', flush=True)
        if name == 'UID991_DIAGNOSTIC':
            for value in getattr(op, '_m05_diagnostic_observations', []):
                print('M05_D11_RECOVERY_UID991=' + value, flush=True)
    return len(passed) == len(checks)


def consume():
    fd = os.open(RECOVERY_CONSUMED, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, b'D11_MISSING_TAIL_RECOVERY_CONSUMED_NO_RETRY\n')
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(RECOVERY_CONSUMED.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def finish(context):
    """Only the original marker/start/postcheck tail; no source/config exchange."""
    op, prior, helper = context.op, context.prior, context.helper
    require(context.completed is False)
    space = os.statvfs(str(op.BASE))
    require(space.f_bavail * space.f_frsize >= 8 * 1024 * 1024 and space.f_favail >= 300)
    prior.admission_closed(helper, context.diagnostic, context.replay)
    helper.write_durable(op.MARKER, op.MARKER_BYTES, 0, 0, 0o600)
    helper.fsync_directory(op.RECEIPT)
    helper.service_action('start', op.SOCKET)
    helper.service_action('start', op.BROKER)
    op.postcheck(prior, context.previous, context.diagnostic, helper,
                 context.old, context.target, context.configs, context.wanted, context.replay)


def main():
    try:
        with confined():
            context = load()
        finishing = sys.argv[1] == '--finish-once'
        if finishing:
            consume()
        if not inspect(context, diagnose=not finishing):
            print('M05_D11_RECOVERY_MATRIX_HOLD_NO_RETRY', flush=True)
            return 2
        if finishing:
            with confined():
                finish(context)
            print('M05_D11_RECOVERY_SOURCE_COMPLETE_NOT_016_DEPLOYED', flush=True)
        else:
            print('M05_D11_RECOVERY_READONLY_ALL_PASS', flush=True)
        return 0
    except Exception:
        print('M05_D11_RECOVERY_HOLD_NO_AUTORETRY', flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
