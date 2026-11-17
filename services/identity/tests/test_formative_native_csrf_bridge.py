"""Real Django CSRF middleware + HTTP interoperability with Native's challenge.

Native retains its own cookie-bound csrfToken from /api/auth/csrf. This HTTP
fixture exercises that existing protocol, not its cryptography or learner DB.
OIDC identity/Native admission are synthetic; no production data is accessed.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from unittest import mock

from django.test import SimpleTestCase, override_settings
import test_formative_csrf as fixture
from identity_bff import formative


class Native(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body=json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','private, no-store')
        self.end_headers();self.wfile.write(body)

    def do_GET(self):
        self.server.hits.append(('GET',self.path,self.headers.get('Cookie')))
        if self.headers.get('X-Forwarded-Proto') != 'https':
            return self.respond(403,{'code':'SUM_NATIVE_HTTPS_PROXY_REQUIRED'})
        if self.path!='/api/auth/csrf' or self.headers.get('Cookie')!='__Host-sumlaude_session='+fixture.COOKIE:
            return self.respond(403,{'code':'SUM_BFF_UNTRUSTED_SESSION'})
        self.respond(self.server.csrf_status,self.server.csrf_payload)

    def do_POST(self):
        self.server.hits.append(('POST',self.path,self.headers.get('Cookie')))
        self.rfile.read(int(self.headers.get('Content-Length','0')))
        if self.headers.get('X-Forwarded-Proto') != 'https':
            return self.respond(403,{'code':'SUM_NATIVE_HTTPS_PROXY_REQUIRED'})
        if (self.headers.get('X-CSRF-Token')!='f'*64 or
                self.headers.get('Cookie')!='__Host-sumlaude_session='+fixture.COOKIE or
                self.headers.get('Origin')!='https://app.sumlaude.com' or self.server.reject_post):
            return self.respond(403,{'code':'SUM_BFF_CSRF_DENIED'})
        self.respond(200,{'saved':True})

    def log_message(self,*args):pass


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default':{'BACKEND':'django.core.cache.backends.locmem.LocMemCache'}},
    REQUIRE_GTM_ADULT_CHOICE=False,
    CANONICAL_AUTH_ENABLED=True,
    ALLOWED_HOSTS=['app.sumlaude.com','sumlaude.com'],
)
class NativeCsrfBridgeTests(SimpleTestCase):
    _login=fixture.FormativeSessionCsrfTests._login
    _csrf=fixture.FormativeSessionCsrfTests._csrf
    _post=fixture.FormativeSessionCsrfTests._post

    def setUp(self):
        fixture.FormativeSessionCsrfTests.setUp(self)
        self.bridge.stop()  # Exercise REAL first-party HTTP forwarding.
        self.client.defaults['HTTP_HOST']='sumlaude.com'
        self.native=ThreadingHTTPServer(('127.0.0.1',0),Native)
        self.native.hits=[];self.native.csrf_status=200
        self.native.csrf_payload={'csrfToken':'f'*64};self.native.reject_post=False
        threading.Thread(target=self.native.serve_forever,daemon=True).start()
        self.port=mock.patch.object(formative,'_NATIVE_PORT',self.native.server_port)
        self.port.start();self.addCleanup(self.port.stop)
        self.addCleanup(self.native.server_close);self.addCleanup(self.native.shutdown)
        self._login()

    def post(self, token=None, **kwargs):
        return self._post(token or self._csrf(),origin='https://sumlaude.com',**kwargs)

    def test_both_distinct_csrf_controls_pass_before_native_save(self):
        csrf=self._csrf();self.assertNotEqual(csrf,'f'*64)
        response=self.post(csrf)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json(),{'saved':True})
        self.assertEqual([(m,p) for m,p,_ in self.native.hits],[('GET','/api/auth/csrf'),('POST',fixture.ROUTE)])
        self.assertTrue(all(cookie=='__Host-sumlaude_session='+fixture.COOKIE for _,_,cookie in self.native.hits))

    def test_wrong_django_csrf_never_contacts_native_even_with_spoofed_native_header(self):
        response=self.post('A'*64,extra={'HTTP_X_CSRF_TOKEN':'f'*64})
        self.assertEqual(response.status_code,403);self.assertEqual(self.native.hits,[])

    def test_cookie_pair_mismatch_never_fetches_native_challenge(self):
        self.client.cookies['__Host-sumlaude_session']='c'*64
        self.assertEqual(self.post().status_code,401);self.assertEqual(self.native.hits,[])

    def test_native_challenge_denial_or_bad_shape_never_posts(self):
        for status,payload in [(403,{'code':'SUM_BFF_REVOKED'}),(200,{'csrfToken':'not-a-native-token'}),(302,{})]:
            self.native.hits=[];self.native.csrf_status=status;self.native.csrf_payload=payload
            response=self.post()
            self.assertIn(response.status_code,(403,503))
            self.assertFalse(any(m=='POST' for m,_,_ in self.native.hits))

    def test_native_post_authorization_denial_is_preserved(self):
        self.native.reject_post=True
        self.assertEqual(self.post().status_code,403)
