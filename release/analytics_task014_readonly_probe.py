"""Read the fixed Analytics release and verify signatures in the existing CI probe.

Related: private_zot_auth_probe.py, analytics_signed_release_consumer.py and
platform-promote.yml. This diagnostic has no broker, replay, host provisioning,
container, database, publication or deployment operation. It is not host acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Mapping

from deployment import release_consumer as consumer
from deployment.analytics_signed_release_consumer import (
    PINNED_DIGEST, PINNED_IMAGE, PINNED_VERSION, _analytics_archive, _signed_fields,
)
from deployment.policy import EXPECTED_CERTIFICATE_IDENTITY, EXPECTED_CERTIFICATE_ISSUER
from . import private_zot_auth_probe as original


def _private_file(path: Path, raw: bytes) -> None:
    """Write only under this process's private temporary directory."""
    with path.open('xb') as output:
        path.chmod(0o600)
        output.write(raw)


def _observed_factory(records: list[dict[str, object]], registry: str):
    """Keep only fixed HTTP envelope diagnostics, never credentials or bodies."""
    class Connection:
        def __init__(self, host, port, timeout, context):
            self.connection = consumer._connection(host, port, timeout, context)
        def request(self, *args, **kwargs):
            return self.connection.request(*args, **kwargs)
        def getresponse(self):
            response = self.connection.getresponse()
            headers = response.getheaders()
            names = [name.lower() for name, _ in headers]
            media = response.getheader('Content-Type')
            known = ('application/json', 'application/json; charset=utf-8',
                     consumer.OCI_MEDIA_TYPE, consumer.ARCHIVE_MEDIA_TYPE)
            records.append({
                'registry': registry, 'status': response.status,
                'content_type': media if media in known else 'other',
                'header_count': len(headers), 'duplicate_headers': len(names) != len(set(names)),
                'has_content_length': 'content-length' in names,
                'has_transfer_encoding': 'transfer-encoding' in names,
                'has_content_encoding': 'content-encoding' in names,
            })
            return response
        def close(self):
            self.connection.close()
    return Connection


class CheckFailed(Exception):
    """Internal fixed diagnostic code, never external exception text."""


def _run_cosign(argv: list[str], environment: dict[str, str]) -> tuple[int, bytes]:
    """Reuse the original verifier's bounded pipe/deadline and pinned-PID cleanup."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, env=environment, cwd=environment['HOME'],
                             start_new_session=True, close_fds=True)
    output = bytearray()
    deadline = time.monotonic() + 90
    try:
        os.set_blocking(child.stderr.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CheckFailed('COMMAND_TIMEOUT')
                for key, _event in selector.select(remaining):
                    block = os.read(key.fileobj.fileno(), min(4096, 65537 - len(output)))
                    output.extend(block)
                    if len(output) > 65536:
                        raise CheckFailed('COMMAND_OUTPUT_LIMIT')
                    if not block:
                        selector.unregister(key.fileobj)
        # WNOWAIT preserves the child PID until its process group is cleaned.
        while True:
            state = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if state is not None:
                code = state.si_status if state.si_code == os.CLD_EXITED else -state.si_status
                return code, bytes(output)
            if time.monotonic() >= deadline:
                raise CheckFailed('COMMAND_TIMEOUT')
            time.sleep(0.01)
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=2)
        finally:
            child.stderr.close()


def _cosign(executable: str, args: list[str], environment: dict[str, str]) -> None:
    """Emit only fixed categories from bounded in-memory stderr; never raw text."""
    code, stderr = _run_cosign([executable, *args], environment)
    if code == 0:
        return
    lowered = stderr.lower()
    categories = (
        ('REGISTRY_ACCESS_DENIED', (b'unauthorized', b'forbidden', b'authentication required', b'denied')),
        ('SIGNATURE_NOT_FOUND_OR_MATCHING', (b'no signatures found', b'no matching signatures')),
        ('SIGNATURE_IDENTITY_MISMATCH', (b'certificate identity', b'certificate subject', b'oidc issuer')),
        ('TRUST_MATERIAL_UNAVAILABLE', (b'tuf', b'trusted root', b'trust material')),
        ('COMMAND_NETWORK_TIMEOUT', (b'deadline exceeded', b'timed out', b'timeout')),
    )
    for label, markers in categories:
        if any(marker in lowered for marker in markers):
            raise CheckFailed(label)
    raise CheckFailed('SIGNATURE_COMMAND_FAILED')


def run(environment: Mapping[str, str], zot_token: str) -> int:
    """Continue independent component checks and report every redacted mismatch."""
    original._workflow_context_preflight(environment)
    original._claims_preflight(zot_token, environment, int(time.time()))
    checks: list[dict[str, str]] = []
    http_records: list[dict[str, object]] = []

    def check(name, operation):
        try:
            value = operation()
            checks.append({'name': name, 'status': 'PASS'})
            return value
        except Exception as error:
            entry = {'name': name, 'status': 'HOLD'}
            if type(error) is CheckFailed:
                entry['code'] = str(error)
            checks.append(entry)
            return None

    def blocked(name):
        checks.append({'name': name, 'status': 'BLOCKED'})

    zot = check('zot_authenticated_manifest', lambda: consumer._get(
        'zot', PINNED_DIGEST, zot_token, _observed_factory(http_records, 'zot'),
        product='analytics',
    ))
    optional_fields = []
    if zot is not None:
        def manifest():
            body, headers = zot
            observed = consumer.parse_bounded_json(body, maximum_bytes=consumer.MAX_MANIFEST_BYTES,
                                                   maximum_root_members=8)
            if type(observed) is dict:
                optional_fields.extend(key for key in ('annotations', 'subject', 'artifactType') if key in observed)
            if (headers.get('docker-content-digest') != PINNED_DIGEST
                    or 'sha256:' + hashlib.sha256(body).hexdigest() != PINNED_DIGEST):
                raise ValueError('digest mismatch')
            value = consumer._json(body, frozenset({'schemaVersion', 'mediaType', 'config', 'layers'}), schema=None)
            if value['schemaVersion'] != 2 or value['mediaType'] != consumer.OCI_MEDIA_TYPE:
                raise ValueError('manifest schema mismatch')
        check('zot_exact_digest_and_manifest_schema', manifest)
    else:
        blocked('zot_exact_digest_and_manifest_schema')

    def forgejo_credential():
        token = original._oidc_token(environment, audience=original.FORGEJO_AUDIENCE)
        original._claims_preflight(token, environment, int(time.time()), audience=original.FORGEJO_AUDIENCE)
        return token
    forgejo_token = check('forgejo_oidc_context', forgejo_credential)
    archive = None
    if forgejo_token is not None:
        answer = check('forgejo_authenticated_package', lambda: consumer._get(
            'forgejo', PINNED_VERSION, forgejo_token,
            _observed_factory(http_records, 'forgejo'), product='analytics',
        ))
        if answer is not None:
            archive = check('closed_analytics_archive', lambda: _analytics_archive(answer[0]))
        else:
            blocked('closed_analytics_archive')
    else:
        blocked('forgejo_authenticated_package'); blocked('closed_analytics_archive')
    if archive is not None:
        evidence, scanner_hashes = archive
        check('release_fields_and_scanner_bindings', lambda: _signed_fields(evidence, scanner_hashes))
    else:
        blocked('release_fields_and_scanner_bindings')

    def cosign_available():
        executable = shutil.which('cosign')
        if executable is None:
            raise ValueError('Cosign unavailable')
        return executable
    executable = check('pinned_ci_cosign_available', cosign_available)
    with tempfile.TemporaryDirectory(prefix='task014-analytics-readonly-') as location:
        directory = Path(location); directory.chmod(0o700)
        docker = directory / '.docker'; docker.mkdir(mode=0o700)
        encoded = base64.b64encode(('oidc:' + zot_token).encode('ascii')).decode('ascii')
        _private_file(docker / 'config.json', (json.dumps({'auths': {consumer.ZOT_HOST: {'auth': encoded}}}) + '\n').encode('ascii'))
        process_environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                               'HOME': str(directory), 'DOCKER_CONFIG': str(docker)}
        identity = ['--certificate-identity', EXPECTED_CERTIFICATE_IDENTITY,
                    '--certificate-oidc-issuer', EXPECTED_CERTIFICATE_ISSUER]
        for name in ('release-manifest', 'release-provenance'):
            phase = name.replace('-', '_') + '_signature'
            if archive is None or executable is None:
                blocked(phase)
                continue
            for suffix in ('.json', '.sigstore.json'):
                _private_file(directory / (name + suffix), evidence[name + suffix])
            check(phase, lambda n=name: _cosign(executable, [
                'verify-blob', '--bundle', str(directory / (n + '.sigstore.json')),
                *identity, str(directory / (n + '.json')),
            ], process_environment))
        if executable is not None:
            check('oci_signature', lambda: _cosign(executable, [
                'verify', *identity, PINNED_IMAGE,
            ], process_environment))
        else:
            blocked('oci_signature')
    passed = all(item['status'] == 'PASS' for item in checks)
    print(json.dumps({'operation': 'analytics_task014_read_only_preflight',
                      'release_version': PINNED_VERSION, 'checks': checks, 'http': http_records,
                      'oci_optional_fields_present': optional_fields,
                      'deployment_authorized': False, 'host_state_changed': False}, sort_keys=True))
    print('TASK014_ANALYTICS_READONLY_MATRIX_' + ('PASS' if passed else 'HOLD'))
    return 0 if passed else 2
