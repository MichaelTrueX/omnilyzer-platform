"""One bounded, redacted registry read for failed Task014 run43813770692.

Reads only Zot timeout fields and the Analytics transfer log window.
No network, credentials, service operation, configuration write or release.
Run only from an owner-verified root0400 snapshot on truexmainserver.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

LIMIT = 16 * 1024 * 1024
START = dt.datetime(2026, 11, 16, 5, 59, 30, tzinfo=dt.timezone.utc)
END = dt.datetime(2026, 11, 16, 6, 9, tzinfo=dt.timezone.utc)
PATH = re.compile(r'/v2/omnilyzer/analytics/(blobs|manifests)/sha256:([a-f0-9]{64})(?![a-f0-9])')
ERRORS = ('upstream prematurely closed connection', 'upstream timed out',
          'connection reset by peer', 'broken pipe', 'client prematurely closed connection',
          'client timed out', 'no live upstreams', 'connect() failed')


def read(path, limit, tail=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError()
        if info.st_size > limit:
            if not tail:
                raise ValueError()
            os.lseek(fd, info.st_size - limit, os.SEEK_SET)
        chunks, remaining = [], limit
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)


def emit(value):
    print(json.dumps(value, sort_keys=True))


def main():
    source = Path(__file__)
    parent, info = source.parent.lstat(), source.lstat()
    if (len(sys.argv) != 1 or os.getuid() != 0 or os.geteuid() != 0
            or socket.gethostname().split('.')[0] != 'truexmainserver'
            or source.parent.parent != Path('/run')
            or not source.parent.name.startswith('m05-run438-readonly.')
            or not stat.S_ISDIR(parent.st_mode)
            or (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)) != (0, 0, 0o700)
            or not stat.S_ISREG(info.st_mode)
            or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) != (0, 0, 0o400, 1)):
        print('M05_RUN438_READONLY_WRONG_CALLER')
        return 2
    try:
        raw = read('/etc/zot/config.json', 32768)
        http = json.loads(raw)['http']
        timeouts = {}
        for field in ('readTimeout', 'writeTimeout'):
            value = http.get(field)
            timeouts[field] = value if (value is None or
                type(value) is str and re.fullmatch(r'[0-9.]{1,12}(?:ms|s|m|h)', value) or
                type(value) in (int, float) and 0 <= value <= 86400) else 'INVALID'
        emit({'check': 'zot_config', 'sha256': hashlib.sha256(raw).hexdigest(), 'timeouts': timeouts})
    except Exception:
        emit({'check': 'zot_config', 'result': 'UNAVAILABLE'})
    for name in ('access.log', 'error.log'):
        rows = 0
        try:
            raw = read('/var/log/nginx/' + name, LIMIT, tail=True)
            for line in raw.decode('utf-8', 'replace').splitlines():
                path = PATH.search(line)
                if path is None:
                    continue
                if name == 'access.log':
                    stamp = re.search(r'\[([0-9]{2}/Nov/2026:[0-9:]{8} [+-][0-9]{4})\]', line)
                    moment = dt.datetime.strptime(stamp[1], '%d/%b/%Y:%H:%M:%S %z') if stamp else None
                else:
                    stamp = re.match(r'2026/11/16 [0-9:]{8}', line)
                    moment = dt.datetime.strptime(stamp[0], '%Y/%m/%d %H:%M:%S').astimezone() if stamp else None
                if moment is None or not START <= moment <= END:
                    continue
                result = {'check': name, 'time': moment.isoformat(), 'kind': path[1], 'digest': path[2]}
                if name == 'access.log':
                    status = re.search(r'HTTP/[0-9.]+" ([0-9]{3}) ([0-9]+)', line)
                    if status:
                        result.update(status=int(status[1]), body_bytes=int(status[2]))
                else:
                    result['errors'] = [error for error in ERRORS if error in line.lower()]
                emit(result)
                rows += 1
                if rows == 256:
                    break
            emit({'check': name, 'rows': rows, 'bounded_tail_bytes': LIMIT})
        except Exception:
            emit({'check': name, 'result': 'UNAVAILABLE'})
    print('M05_RUN438_REGISTRY_READONLY_COMPLETE_NO_CHANGES')
    return 0


if __name__ == '__main__':
    sys.exit(main())
