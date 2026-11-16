"""Wrap the unchanged accepted OCI blobs for native Docker cache loading.

Operational data packaging only: no build, signature, tag, Docker operation,
deployment, registry mutation, source/config exchange or replay operation.
The later original signed Task014 pull must authenticate and bind RepoDigest.
Related: Issue281; Docker29.8.1 daemon/internal/image/tarexport/load.go.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import sys
import tarfile

MANIFEST = 'a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1'
CONFIG = '8ddf7273804b8c9a5a964fb85b573de25f66915dd5ef33465522742f5a5df76e'
SOURCE = Path('/srv/omnilyzer-registry/zot/omnilyzer/analytics/blobs/sha256')
OUTPUT = Path('/var/tmp/m05-analytics016-cache-20261116')


def opened(digest, size):
    assert re.fullmatch('[a-f0-9]{64}', digest) and 0 < size <= 512 * 1024**2
    fd = os.open(SOURCE / digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    f = os.fdopen(fd, 'rb')
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_size != size:
        f.close()
        raise ValueError('OCI_BLOB_METADATA_HOLD')
    return f


def member(tar, name, size, source):
    info = tarfile.TarInfo(name)
    info.size, info.mode = size, 0o444
    tar.addfile(info, source)


class VerifiedReader:
    def __init__(self, source):
        self.source, self.hash = source, hashlib.sha256()

    def read(self, count):
        data = self.source.read(count)
        self.hash.update(data)
        return data


def main():
    assert (len(sys.argv) == 1 and os.getuid() == os.geteuid() == 0
            and socket.gethostname().split('.')[0] == 'truexmainserver')
    assert shutil.disk_usage('/var/tmp').free >= 2 * 1024**3
    # These fixed small blobs bind every subsequent descriptor to Task013.
    with opened(MANIFEST, 2578) as f:
        raw = f.read()
    assert hashlib.sha256(raw).hexdigest() == MANIFEST
    manifest = json.loads(raw)
    assert manifest['schemaVersion'] == 2 and len(manifest['layers']) == 12
    assert manifest['config']['digest'] == 'sha256:' + CONFIG
    descriptors = [manifest['config'], *manifest['layers']]
    assert sum(x['size'] for x in descriptors) < 512 * 1024**2
    with opened(CONFIG, manifest['config']['size']) as f:
        config_raw = f.read()
    assert hashlib.sha256(config_raw).hexdigest() == CONFIG
    config = json.loads(config_raw)
    assert config['os'] == 'linux' and config['architecture'] == 'amd64'
    assert len(config['rootfs']['diff_ids']) == 12
    load_manifest = json.dumps([{
        'Config': 'blobs/sha256/' + CONFIG, 'RepoTags': [],
        'Layers': ['blobs/sha256/' + x['digest'][7:] for x in manifest['layers']],
    }], sort_keys=True, separators=(',', ':')).encode()
    OUTPUT.mkdir(mode=0o700)  # Existing output is a HOLD, never overwritten.
    path = OUTPUT / 'analytics016-cache.tar'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        with tarfile.open(fileobj=out, mode='w|') as tar:
            member(tar, 'manifest.json', len(load_manifest), io.BytesIO(load_manifest))
            for item in descriptors:
                assert re.fullmatch('sha256:[a-f0-9]{64}', item['digest'])
                digest = item['digest'][7:]
                with opened(digest, item['size']) as source:
                    reader = VerifiedReader(source)
                    member(tar, 'blobs/sha256/' + digest, item['size'], reader)
                    assert reader.hash.hexdigest() == digest
        out.flush()
        os.fsync(out.fileno())
    with path.open('rb') as source:
        archive_hash = hashlib.file_digest(source, 'sha256').hexdigest()
    receipt = {'oci_manifest': 'sha256:' + MANIFEST, 'config': 'sha256:' + CONFIG,
               'archive_sha256': archive_hash, 'archive_bytes': path.stat().st_size,
               'repo_tags': [], 'deployment_authorized': False,
               'registry_authentication_still_required': True}
    fd = os.open(OUTPUT / 'verified.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(receipt, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
