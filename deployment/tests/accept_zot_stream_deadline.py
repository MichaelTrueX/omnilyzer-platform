"""File: deployment/tests/accept_zot_stream_deadline.py

Purpose: Reproduce the live Zot response deadline on private loopback fixtures.
Related: analytics_registry_stream_transition.py and Task014 issue27.
Never run on DEV/production; requires truexdevelopment and the exact binary.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
import socket
import subprocess
import tempfile
import threading
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def run_case(write_timeout, *, short_token=False):
    with tempfile.TemporaryDirectory(prefix='task014-zot-stream-') as temporary:
        root = Path(temporary)
        data = root / 'data'
        repository = data / 'probe' / 'stream'
        blobs = repository / 'blobs' / 'sha256'
        blobs.mkdir(parents=True)
        payload = b'\0' * (32 * 1024 * 1024)
        layer_sha = hashlib.sha256(payload).hexdigest()
        (blobs / layer_sha).write_bytes(payload)
        config = b'{}'
        config_sha = hashlib.sha256(config).hexdigest()
        (blobs / config_sha).write_bytes(config)
        manifest = canonical({'schemaVersion': 2,
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                       'digest': 'sha256:' + config_sha, 'size': len(config)},
            'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                        'digest': 'sha256:' + layer_sha, 'size': len(payload)}]})
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        (blobs / manifest_sha).write_bytes(manifest)
        (repository / 'oci-layout').write_bytes(canonical({'imageLayoutVersion': '1.0.0'}))
        (repository / 'index.json').write_bytes(canonical({'schemaVersion': 2,
            'manifests': [{'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                          'digest': 'sha256:' + manifest_sha, 'size': len(manifest),
                          'annotations': {'org.opencontainers.image.ref.name': 'probe'}}]}))
        with socket.socket() as selection:
            selection.bind(('127.0.0.1', 0))
            port = selection.getsockname()[1]
        http_settings = {'address': '127.0.0.1', 'port': str(port)}
        if write_timeout is not None:
            http_settings['writeTimeout'] = write_timeout
        identity_server=identity_thread=private_key=None
        issuer=None
        if short_token:
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            public=private_key.public_key().public_numbers()
            def encoded(raw):return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
            jwk={'kty':'RSA','kid':'fixture','use':'sig','alg':'RS256',
                 'n':encoded(public.n.to_bytes((public.n.bit_length()+7)//8,'big')),
                 'e':encoded(public.e.to_bytes((public.e.bit_length()+7)//8,'big'))}
            class Identity(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    if self.path=='/.well-known/openid-configuration':
                        value={'issuer':issuer,'jwks_uri':issuer+'/jwks',
                               'authorization_endpoint':issuer+'/authorize','token_endpoint':issuer+'/token',
                               'response_types_supported':['id_token'],'subject_types_supported':['public'],
                               'id_token_signing_alg_values_supported':['RS256']}
                    elif self.path=='/jwks':value={'keys':[jwk]}
                    else:self.send_error(404);return
                    raw=canonical(value);self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            identity_server=ThreadingHTTPServer(('127.0.0.1',0),Identity)
            issuer='http://127.0.0.1:'+str(identity_server.server_port)
            identity_thread=threading.Thread(target=identity_server.serve_forever,daemon=True);identity_thread.start()
            http_settings['auth']={'bearer':{'realm':'http://127.0.0.1:'+str(port)+'/zot/auth/token','service':'fixture',
                'oidc':[{'issuer':issuer,'audiences':['fixture'],
                         'claimMapping':{'username':'claims.sub','groups':''}}]}}
            http_settings['accessControl']={'repositories':{'**':{'defaultPolicy':[],'anonymousPolicy':[]},
                'probe/stream':{'policies':[{'users':['fixture-user'],'actions':['read']}]}}}
        settings = root / 'config.json'
        settings.write_bytes(canonical({'distSpecVersion': '1.1.1',
            'storage': {'rootDirectory': str(data), 'dedupe': False, 'gc': False},
            'http': http_settings, 'log': {'level': 'error'}}))
        log = (root / 'server.log').open('wb')
        process = subprocess.Popen(['/usr/local/bin/zot', 'serve', str(settings)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(root)}, cwd=root)
        connection = None
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError('isolated_zot_exit:' + str(process.returncode))
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('isolated_zot_not_ready')
                    time.sleep(.1)
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            connection.connect()
            connection.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            started = time.monotonic()
            headers={}
            if short_token:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                issued=int(time.time())
                signing=(encoded(canonical({'alg':'RS256','kid':'fixture','typ':'JWT'}))+'.'+
                         encoded(canonical({'iss':issuer,'aud':'fixture','sub':'fixture-user','iat':issued,'exp':issued+6}))).encode()
                token=signing.decode()+'.'+encoded(private_key.sign(signing,padding.PKCS1v15(),hashes.SHA256()))
                headers={'Authorization':'Bearer '+token}
            connection.request('GET', '/v2/probe/stream/blobs/sha256:' + layer_sha,headers=headers)
            response = connection.getresponse()
            if response.status != 200 or int(response.getheader('Content-Length')) != len(payload):
                raise RuntimeError('fixture_blob_not_served:' + str(response.status))
            # Stall beyond either the default60s response deadline or the
            # fixture token's6s expiry. Each wait is at most five seconds.
            until = started + (9 if short_token else 65)
            while time.monotonic() < until:
                time.sleep(min(5, until - time.monotonic()))
            if connection.sock is not None:
                connection.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            hasher = hashlib.sha256()
            count = 0
            error = None
            try:
                while count <= len(payload):
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    hasher.update(chunk)
            except (OSError, http.client.HTTPException) as caught:
                error = type(caught).__name__
            result = {'write_timeout': write_timeout, 'declared_bytes': len(payload),
                      'received_bytes': count, 'complete_and_hash_verified':
                      count == len(payload) and hasher.hexdigest() == layer_sha,
                      'seconds': round(time.monotonic() - started, 3), 'read_error': error}
            if short_token:
                fresh=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                try:
                    fresh.request('GET','/v2/probe/stream/blobs/sha256:'+layer_sha,headers=headers)
                    refused=fresh.getresponse();result['expired_new_request_status']=refused.status;refused.read(65536);refused.close()
                finally:fresh.close()
                assert time.time()>issued+6
                assert result['complete_and_hash_verified'] and result['expired_new_request_status']==401,result
            print(json.dumps(result, sort_keys=True), flush=True)
            return result
        finally:
            if connection is not None:
                connection.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.close()
            if identity_server is not None:
                identity_server.shutdown();identity_server.server_close();identity_thread.join(timeout=3)


if __name__ == '__main__':
    assert os.getuid() != 0 and socket.gethostname().split('.')[0] == 'truexdevelopment'
    binary = Path('/usr/local/bin/zot')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert digest == 'a32e42d042d1f17b5b1317e55cc1a415a744c873dcd05c25c56b665478258bcb'
    print('ISOLATED_BINARY_SHA256', digest, flush=True)
    import sys
    if sys.argv[1:]==['--expiry-only']:
        run_case('90s',short_token=True)
        print('ACTUAL_ZOT_ADMITTED_STREAM_AND_EXPIRED_NEW_REQUEST_PASS',flush=True)
    else:
        assert not sys.argv[1:]
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(run_case, (None, '90s')))
        assert not results[0]['complete_and_hash_verified']
        assert results[1]['complete_and_hash_verified']
        print('ACTUAL_ZOT_DEFAULT_CUTOFF_AND_EXPLICIT_BOUNDED_RESPONSE_PASS', flush=True)
