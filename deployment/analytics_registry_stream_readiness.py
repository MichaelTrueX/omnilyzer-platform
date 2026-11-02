"""File: deployment/analytics_registry_stream_readiness.py

Purpose: Read-only fixed Task014 registry deadline/blob/log qualification.
Related: analytics_registry_stream_transition.py and issue27.

No network request, credential output, file write or service operation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result


def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError('invalid_file')
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        if len(raw) > maximum:
            raise ValueError('file_limit')
        return raw
    finally:
        os.close(fd)


def run():
    assert os.getuid() == os.geteuid() == 0
    assert socket.gethostname().split('.')[0] == 'truexmainserver'
    model = None
    try:
        raw = read('/etc/zot/config.json', 32768)
        model = json.loads(raw, object_pairs_hook=unique)
        fields = {}
        for name in ('readTimeout', 'writeTimeout'):
            value = model['http'].get(name)
            fields[name] = value if value is None or (type(value) in (int, float) and 0 <= value <= 86400) or (type(value) is str and re.fullmatch(r'[0-9.]+(?:ms|s|m|h)', value)) else 'INVALID'
        print(json.dumps({'check': 'registry_configuration',
            'sha256': hashlib.sha256(raw).hexdigest(),
            'expected_sha256_match': hashlib.sha256(raw).hexdigest() == '880dca7bb8aede9a833e31e938abc7b6f2ee1dd96911be927de6ce5502318d1a',
            'configured_http_timeouts': fields,
            'unset_timeout_default_in_verified_v2_1_20_seconds': 60}))
    except Exception as error:
        print(json.dumps({'check': 'registry_configuration', 'error_type': type(error).__name__}))
    try:
        assert model is not None and model['storage']['rootDirectory'] == '/srv/omnilyzer-registry/zot'
        directory = Path('/srv/omnilyzer-registry/zot/omnilyzer/analytics/blobs/sha256')
        digest = '6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1'
        raw = read(directory / digest, 1024 * 1024)
        assert hashlib.sha256(raw).hexdigest() == digest
        manifest = json.loads(raw, object_pairs_hook=unique)
        rows = [manifest['config'], *manifest['layers']]
        assert len(rows) <= 128 and sum(row['size'] for row in rows) <= 2 * 1024**3
        for row in rows:
            result = {'check': 'published_blob', 'digest': row['digest'], 'declared_bytes': row['size']}
            try:
                assert re.fullmatch(r'sha256:[a-f0-9]{64}', row['digest']) and type(row['size']) is int and 0 <= row['size'] <= 1024**3
                fd = os.open(directory / row['digest'][7:], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                try:
                    info = os.fstat(fd)
                    assert stat.S_ISREG(info.st_mode) and info.st_size <= 1024**3
                    result['stored_bytes'] = info.st_size
                    hasher = hashlib.sha256()
                    count = 0
                    while count <= 1024**3:
                        chunk = os.read(fd, min(1024 * 1024, 1024**3 + 1 - count))
                        if not chunk:
                            break
                        count += len(chunk)
                        hasher.update(chunk)
                    result['size_and_digest_match'] = count == info.st_size == row['size'] and hasher.hexdigest() == row['digest'][7:]
                finally:
                    os.close(fd)
            except Exception as error:
                result['error_type'] = type(error).__name__
            print(json.dumps(result))
    except Exception as error:
        print(json.dumps({'check': 'published_manifest_and_blobs', 'error_type': type(error).__name__}))
    for name in ('error.log', 'access.log'):
        try:
            raw = read('/var/log/nginx/' + name, 8 * 1024**2).decode('utf-8', 'replace')
            for line in raw.splitlines():
                if not re.search(r'(?:2026/10/31 10:0[3-6]:|31/Oct/2026:10:0[3-6]:)', line):
                    continue
                path = re.search(r'/v2/omnilyzer/analytics/(?:blobs|manifests)/sha256:[a-f0-9]{64}', line)
                if path is None:
                    continue
                result = {'check': 'nginx_transfer', 'log': name, 'path': path.group()}
                if name == 'error.log':
                    result['known_errors'] = [text for text in ('upstream prematurely closed connection', 'upstream timed out', 'connection reset by peer', 'broken pipe') if text in line.lower()]
                else:
                    matched = re.search(r'HTTP/[0-9.]+" ([0-9]{3}) ([0-9]+)', line)
                    if matched:
                        result['http_status'], result['body_bytes'] = map(int, matched.groups())
                print(json.dumps(result))
        except Exception as error:
            print(json.dumps({'check': 'nginx_log', 'log': name, 'error_type': type(error).__name__}))
    print('REGISTRY_STREAM_READ_ONLY_COMPLETE_NO_CHANGES')


if __name__ == '__main__':
    run()
