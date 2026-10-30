#!/usr/bin/env bash
# File: deployment/analytics_dev_resume_once.sh
# Purpose: Owner-authorized, one-shot local SSH recovery of the preflighted
#          Analytics 0.15.0 DEV PostgreSQL installation after pg-admin traversal
#          was corrected. Reuse the protected original admin secret and empty
#          volume; never rerun the original installer or delete data.
# Related: omnilyzer-platform@e624816 deployment/analytics_dev_bootstrap.py,
#          reviewed SQL files in /opt/omnilyzer/deployment/.analytics-db-review.
# Security: No password bytes sent to ChatGPT. Only owner-initiated local sudo.
#          Fail closed, no automatic retries, cleanup, chmod, restart, or prod.
set -euo pipefail
printf '%s\n' 'Analytics DEV 0.15.0 — owner-operated one-time recovery' \
  'Requires authorized SSH/sudo. No retries or data deletion.' \
  'If any phase fails, do NOT run this script again.'
ssh -tt trust@100.108.144.83 'sudo /usr/bin/python3 -I -B -' <<'PY'
"""File: stdin via deployment/analytics_dev_resume_once.sh.
Purpose: Exact-source guarded one-shot recovery, reusing the existing
         reviewed Task014 bootstrap functions, root-owned SQL, protected data.
Sections: immutable source, partial-state preflight, PG creation, SQL+secrets.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time

SOURCE = Path('/opt/omnilyzer/deployment/.analytics-db-review/analytics_dev_bootstrap.py')
SHA = '55b0376ce2d0efce2f2ce8ff8c0dfe499841c79bf84dd4ea45893af85c9730ee'
phase = 'source_preflight'

def fail(message):
    """Stop without credentials in output or any destructive recovery."""
    print('RECOVERY_STOPPED phase=' + phase + ' cause=' + message + ' DO_NOT_RERUN', flush=True)
    raise SystemExit(1)

try:
    if os.geteuid() != 0 or socket.gethostname().split('.')[0] != 'omnilyzerdev':
        fail('HOST_OR_ROOT_DENIED')
    if not SOURCE.is_file() or SOURCE.is_symlink():
        fail('REVIEWED_SOURCE_MISSING')
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SHA:
        fail('SOURCE_SHA_MISMATCH')
    spec = importlib.util.spec_from_file_location('analytics_dev_bootstrap', SOURCE)
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    if b.HOST != 'omnilyzerdev' or b.CONTAINER != 'omnilyzer-analytics-pg16-dev':
        fail('BOOTSTRAP_CONTRACT_MISMATCH')
    print('PASS_IMMUTABLE_REVIEWED_SOURCE', flush=True)

    phase = 'partial_state_preflight'
    # Original preflight rejects the existing admin secret; inspect its other
    # immutable conditions without bypassing rootless or safety boundaries.
    b._metadata(b.DB_DIR, owner=0, group=0, mode=0o700, directory=True)
    for name, digest in b.STAGES:
        p = b.DB_DIR / name
        b._metadata(p, owner=0, group=0, mode=0o400, directory=False)
        if b._sha256(p) != digest:
            fail('SQL_SOURCE_MISMATCH')
    for d in (b.PRIVATE_DIR.parent, b.PRIVATE_DIR, b.SECRET_DIR, b.ADMIN_DIR):
        b._metadata(d, owner=0, group=b.ROOTLESS_GID, mode=0o710, directory=True)
    b._metadata(b.ADMIN_SECRET, owner=b.ROOTLESS_UID, group=b.ROOTLESS_GID,
                mode=0o400, directory=False)
    if any(b.SECRET_DIR.iterdir()):
        fail('PRODUCT_SECRETS_ALREADY_PRESENT')
    # Only the exact previously checked DEV volume is eligible. No cleanup.
    volume = json.loads(b.run((*b.DOCKER, 'volume', 'inspect', b.VOLUME)))[0]
    if (volume.get('Driver') != 'local' or volume.get('Name') != b.VOLUME or
        (volume.get('Labels') or {}) != {
            'ai.omnilyzer.environment':'dev',
            'ai.omnilyzer.product':'analytics',
            'ai.omnilyzer.purpose':'postgres-persistence'}):
        fail('VOLUME_IDENTITY_DENIED')
    mount = Path(volume.get('Mountpoint',''))
    expected = Path('/var/lib/omnilyzer/deployment/rootless-docker-data/volumes/omnilyzer-analytics-pg16-dev/_data')
    if mount != expected or mount.is_symlink() or not mount.is_dir():
        fail('VOLUME_PATH_DENIED')
    if next(mount.iterdir(), None) is not None:
        fail('VOLUME_HAS_DATA')
    net = json.loads(b.run((*b.DOCKER, 'network','inspect',b.NETWORK)))[0]
    if (net.get('Name') != b.NETWORK or net.get('Internal') is not True or
        net.get('Driver') != 'bridge' or net.get('Containers') not in ({},None)):
        fail('PRIVATE_NETWORK_DENIED')
    image = json.loads(b.run((*b.DOCKER,'image','inspect',b.IMAGE)))[0]
    if image.get('Os') != 'linux' or image.get('Architecture') != 'amd64':
        fail('IMMUTABLE_PG_IMAGE_DENIED')
    present = subprocess.run([*b.DOCKER,'container','inspect',b.CONTAINER],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=8)
    if present.returncode == 0:
        fail('PG_CONTAINER_ALREADY_EXISTS')
    if b.run(('/usr/bin/systemctl','is-active','omnilyzer-deployment-broker.service')).strip() != b'active':
        fail('TASK014_BROKER_DENIED')
    # Permission check ONLY; never read or copy the original admin credential.
    permission = subprocess.run(['/usr/bin/runuser','-u','omnilyzer-executor','--',
                      '/usr/bin/test','-r',str(b.ADMIN_SECRET)],
                      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8)
    if permission.returncode:
        fail('PG_ADMIN_SECRET_NOT_READABLE_BY_EXECUTOR')
    print('PASS_PRESERVED_EMPTY_VOLUME_AND_ADMIN_SECRET', flush=True)

    phase = 'postgres_start'
    # Match original reviewed create_database Docker argv exactly, excluding
    # its irreversible creation of a new admin secret. Do not call --install.
    b.run((*b.DOCKER,'run','--detach','--name',b.CONTAINER,
         '--network',b.NETWORK,'--network-alias',b.CONTAINER,
         '--restart','unless-stopped','--pids-limit','192',
         '--memory','1024m','--security-opt','no-new-privileges:true',
         '--mount',f'type=volume,src={b.VOLUME},dst=/var/lib/postgresql/data',
         '--mount',f'type=bind,src={b.ADMIN_SECRET},dst=/run/secrets/pg-admin,readonly',
         '--env',f'POSTGRES_USER={b.DB_OWNER}', '--env',f'POSTGRES_DB={b.DB_NAME}',
         '--env','POSTGRES_PASSWORD_FILE=/run/secrets/pg-admin',
         '--env','POSTGRES_HOST_AUTH_METHOD=scram-sha-256', b.IMAGE),
         timeout=45,secret_step=True)
    for _ in range(30):
        try:
            b.run((*b.DOCKER,'exec',b.CONTAINER,'pg_isready','-q',
                  '-U',b.DB_OWNER,'-d',b.DB_NAME),timeout=5)
            break
        except b.BootstrapDenied:
            time.sleep(1)
    else:
        fail('PG_NOT_READY_PRESERVE_STATE')
    print('PASS_POSTGRESQL_READY', flush=True)

    phase = 'reviewed_sql_stages'
    b.install_reviewed_schema()
    print('PASS_REVIEWED_SCHEMA_RLS_METADATA', flush=True)

    phase = 'runtime_credentials'
    import secrets
    b.install_runtime_credentials(*(secrets.token_urlsafe(48) for _ in range(4)))
    print('BOOTSTRAP_COMPLETE_NOT_TASK014_DEPLOYED', flush=True)
except SystemExit:
    raise
except Exception:
    fail('FIXED_STEP_FAILED_PRESERVE_PARTIAL_STATE')
PY
