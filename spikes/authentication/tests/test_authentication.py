import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import TestCase

from django.conf import settings
from django.contrib.sessions.models import Session
from django.test import Client

from authspike.oidc import (
    authorization_url,
    discovery,
    pkce_material,
    validate_id_token,
)
from tests.browser_harness import complete_keycloak_login


NATIVE_CLIENT = "omnilyzer-native-spike"
NATIVE_REDIRECT = "com.omnilyzer.authspike:/oauth2redirect/keycloak"


def _runtime_values():
    return dict(
        line.split("=", 1)
        for line in Path("/tmp/omnilyzer-auth-spike-runtime.env").read_text().splitlines()
        if "=" in line
    )


def _post_form(url, values):
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(values).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def _callback_query(url):
    parsed = urllib.parse.urlparse(url)
    return parsed, {key: values[0] for key, values in urllib.parse.parse_qs(parsed.query).items()}


class AuthenticationArchitectureTests(TestCase):
    """One ordered protocol journey minimizes real-provider repetition."""

    databases = {"default"}

    def test_real_keycloak_browser_native_and_bearer_boundaries(self):
        Session.objects.all().delete()
        runtime = _runtime_values()
        metadata = discovery()
        self.assertEqual(metadata["issuer"], settings.OIDC_ISSUER)
        for field in (
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "end_session_endpoint",
        ):
            self.assertTrue(metadata[field])
        self.assertIn("S256", metadata["code_challenge_methods_supported"])

        realm_path = settings.BASE_DIR / "keycloak/omnilyzer-auth-spike-realm.json"
        realm_text = realm_path.read_text()
        realm = json.loads(realm_text)
        clients = {client["clientId"]: client for client in realm["clients"]}
        self.assertEqual(set(clients), {
            "omnilyzer-bff-spike",
            "omnilyzer-native-spike",
            "omnilyzer-api-spike",
        })
        bff_config = clients["omnilyzer-bff-spike"]
        native_config = clients[NATIVE_CLIENT]
        self.assertFalse(bff_config["publicClient"])
        self.assertEqual(bff_config["redirectUris"], [settings.OIDC_REDIRECT_URI])
        self.assertTrue(native_config["publicClient"])
        self.assertNotIn("secret", native_config)
        self.assertEqual(native_config["redirectUris"], [NATIVE_REDIRECT])
        for config in (bff_config, native_config):
            self.assertTrue(config["standardFlowEnabled"])
            self.assertFalse(config["implicitFlowEnabled"])
            self.assertFalse(config["directAccessGrantsEnabled"])
            self.assertFalse(config["serviceAccountsEnabled"])
            self.assertEqual(config["attributes"]["pkce.code.challenge.method"], "S256")
            self.assertNotIn("*", "".join(config["redirectUris"]))
        self.assertIn("${OMNILYZER_BFF_SECRET}", realm_text)
        self.assertIn("${OMNILYZER_TEST_PASSWORD}", realm_text)
        self.assertNotIn("workspace", realm_text.lower())
        self.assertNotIn("roles", realm)

        browser = Client(enforce_csrf_checks=True)
        login_response = browser.get("/auth/login", secure=True)
        self.assertEqual(login_response.status_code, 302)
        authorization = login_response["Location"]
        authorization_query = urllib.parse.parse_qs(
            urllib.parse.urlparse(authorization).query
        )
        self.assertEqual(authorization_query["response_type"], ["code"])
        self.assertEqual(authorization_query["client_id"], [settings.OIDC_BFF_CLIENT_ID])
        self.assertEqual(authorization_query["redirect_uri"], [settings.OIDC_REDIRECT_URI])
        self.assertEqual(authorization_query["code_challenge_method"], ["S256"])
        for field in ("state", "nonce", "code_challenge"):
            self.assertTrue(authorization_query[field][0])
        for forbidden in ("access_token", "refresh_token", "client_secret"):
            self.assertNotIn(forbidden, authorization_query)
        pre_login_key = browser.cookies[settings.SESSION_COOKIE_NAME].value

        callback_url = complete_keycloak_login(
            authorization,
            "auth-spike-user",
            runtime["OMNILYZER_TEST_PASSWORD"],
            settings.OIDC_REDIRECT_URI,
        )
        parsed_callback, callback_query = _callback_query(callback_url)
        self.assertEqual(callback_query["state"], authorization_query["state"][0])
        self.assertNotIn("#", callback_url)
        self.assertNotIn("access_token", callback_url)
        self.assertNotIn("refresh_token", callback_url)

        tampered_query = dict(callback_query)
        tampered_query["state"] = "tampered-state"
        tampered_response = browser.get(
            f"{parsed_callback.path}?{urllib.parse.urlencode(tampered_query)}",
            secure=True,
        )
        self.assertEqual(tampered_response.status_code, 400)
        self.assertEqual(tampered_response.json(), {"error": "authentication failed"})

        callback_response = browser.get(
            f"{parsed_callback.path}?{parsed_callback.query}", secure=True
        )
        self.assertEqual(callback_response.status_code, 302)
        self.assertEqual(callback_response["Location"], "/auth/session")
        post_login_key = browser.cookies[settings.SESSION_COOKIE_NAME].value
        self.assertNotEqual(pre_login_key, post_login_key)
        self.assertRegex(post_login_key, r"^[a-z0-9]{32}$")
        cookie = callback_response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["path"], "/")
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["domain"], "")

        old_browser = Client()
        old_browser.cookies[settings.SESSION_COOKIE_NAME] = pre_login_key
        self.assertEqual(old_browser.get("/api/browser-private").status_code, 401)
        self.assertFalse(Session.objects.filter(session_key=pre_login_key).exists())

        replay_response = browser.get(
            f"{parsed_callback.path}?{parsed_callback.query}", secure=True
        )
        self.assertEqual(replay_response.status_code, 400)

        session_response = browser.get("/auth/session", secure=True)
        self.assertEqual(session_response.status_code, 200)
        public_session = session_response.json()
        self.assertTrue(public_session["authenticated"])
        self.assertTrue(public_session["subject"])
        self.assertEqual(public_session["username"], "auth-spike-user")
        for forbidden in ("access_token", "refresh_token", "id_token", "client_secret"):
            self.assertNotIn(forbidden, public_session)
            self.assertNotIn(forbidden, callback_response["Location"])

        stored_session = Session.objects.get(session_key=post_login_key).get_decoded()
        self.assertIn("oauth_tokens", stored_session)
        self.assertIn("access_token", stored_session["oauth_tokens"])
        self.assertIn("refresh_token", stored_session["oauth_tokens"])
        for token in stored_session["oauth_tokens"].values():
            if isinstance(token, str) and len(token) > 40:
                self.assertNotIn(token, session_response.content.decode())
                self.assertNotEqual(token, post_login_key)

        fresh_browser = Client(enforce_csrf_checks=True)
        fresh_browser.cookies[settings.SESSION_COOKIE_NAME] = post_login_key
        protected = fresh_browser.get("/api/browser-private", secure=True)
        self.assertEqual(protected.status_code, 200)
        self.assertEqual(protected.json()["auth"], "session")

        without_csrf = fresh_browser.post("/api/browser-private-write", secure=True)
        self.assertEqual(without_csrf.status_code, 403)
        csrf_response = fresh_browser.get("/auth/csrf", secure=True)
        csrf = csrf_response.json()["csrf_token"]
        csrf_cookie = csrf_response.cookies[settings.CSRF_COOKIE_NAME]
        self.assertTrue(csrf_cookie["secure"])
        self.assertEqual(csrf_cookie["path"], "/")
        self.assertEqual(csrf_cookie["samesite"], "Lax")
        self.assertEqual(csrf_cookie["domain"], "")
        with_csrf = fresh_browser.post(
            "/api/browser-private-write",
            secure=True,
            HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://testserver",
        )
        self.assertEqual(with_csrf.status_code, 200)
        hostile_origin = fresh_browser.post(
            "/api/browser-private-write",
            secure=True,
            HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://hostile.example",
        )
        self.assertEqual(hostile_origin.status_code, 403)

        before_refresh = Session.objects.get(session_key=post_login_key).get_decoded()[
            "oauth_tokens"
        ]
        refresh_response = fresh_browser.post(
            "/auth/refresh",
            secure=True,
            HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://testserver",
        )
        self.assertEqual(refresh_response.status_code, 200)
        self.assertEqual(
            refresh_response.json(), {"authenticated": True, "refreshed": True}
        )
        after_refresh = Session.objects.get(session_key=post_login_key).get_decoded()[
            "oauth_tokens"
        ]
        self.assertNotEqual(before_refresh["access_token"], after_refresh["access_token"])
        for token in after_refresh.values():
            if isinstance(token, str) and len(token) > 40:
                self.assertNotIn(token, refresh_response.content.decode())
        self.assertTrue(fresh_browser.get("/auth/session", secure=True).json()["authenticated"])

        native_state = os.urandom(24).hex()
        native_nonce = os.urandom(24).hex()
        native_verifier, native_challenge = pkce_material()
        native_authorization = authorization_url(
            client_id=NATIVE_CLIENT,
            redirect_uri=NATIVE_REDIRECT,
            state=native_state,
            nonce=native_nonce,
            challenge=native_challenge,
        )
        native_callback = complete_keycloak_login(
            native_authorization,
            "auth-spike-user",
            runtime["OMNILYZER_TEST_PASSWORD"],
            NATIVE_REDIRECT,
        )
        _, native_query = _callback_query(native_callback)
        self.assertEqual(native_query["state"], native_state)
        native_exchange = {
            "grant_type": "authorization_code",
            "client_id": NATIVE_CLIENT,
            "code": native_query["code"],
            "redirect_uri": NATIVE_REDIRECT,
            "code_verifier": native_verifier,
        }
        self.assertNotIn("client_secret", native_exchange)
        status, native_tokens = _post_form(metadata["token_endpoint"], native_exchange)
        self.assertEqual(status, 200)
        self.assertIn("access_token", native_tokens)
        validate_id_token(
            native_tokens["id_token"],
            nonce=native_nonce,
            access_token=native_tokens["access_token"],
            client_id=NATIVE_CLIENT,
        )

        bad_state = os.urandom(24).hex()
        bad_nonce = os.urandom(24).hex()
        bad_verifier, bad_challenge = pkce_material()
        bad_authorization = authorization_url(
            client_id=NATIVE_CLIENT,
            redirect_uri=NATIVE_REDIRECT,
            state=bad_state,
            nonce=bad_nonce,
            challenge=bad_challenge,
        )
        bad_callback = complete_keycloak_login(
            bad_authorization,
            "auth-spike-user",
            runtime["OMNILYZER_TEST_PASSWORD"],
            NATIVE_REDIRECT,
        )
        _, bad_query = _callback_query(bad_callback)
        bad_exchange = {
            "grant_type": "authorization_code",
            "client_id": NATIVE_CLIENT,
            "code": bad_query["code"],
            "redirect_uri": NATIVE_REDIRECT,
            "code_verifier": f"wrong-{bad_verifier}",
        }
        bad_status, bad_tokens = _post_form(metadata["token_endpoint"], bad_exchange)
        self.assertEqual(bad_status, 400)
        self.assertIsNone(bad_tokens)

        unregistered = authorization_url(
            client_id=NATIVE_CLIENT,
            redirect_uri="com.omnilyzer.authspike:/unregistered",
            state=os.urandom(24).hex(),
            nonce=os.urandom(24).hex(),
            challenge=pkce_material()[1],
        )
        with self.assertRaises(urllib.error.HTTPError) as invalid_redirect:
            urllib.request.urlopen(unregistered, timeout=10)
        self.assertEqual(invalid_redirect.exception.code, 400)

        mobile = Client()
        valid_bearer = mobile.get(
            "/api/mobile-private",
            HTTP_AUTHORIZATION=f"Bearer {native_tokens['access_token']}",
        )
        self.assertEqual(valid_bearer.status_code, 200)
        self.assertEqual(valid_bearer.json()["auth"], "bearer")
        self.assertEqual(mobile.get("/api/mobile-private").status_code, 401)
        self.assertEqual(
            mobile.get(
                "/api/mobile-private", HTTP_AUTHORIZATION="Bearer malformed"
            ).status_code,
            401,
        )
        access_parts = native_tokens["access_token"].split(".")
        signature = access_parts[2]
        replacement = "A" if signature[len(signature) // 2] != "A" else "B"
        access_parts[2] = (
            signature[: len(signature) // 2]
            + replacement
            + signature[len(signature) // 2 + 1 :]
        )
        tampered_token = ".".join(access_parts)
        self.assertEqual(
            mobile.get(
                "/api/mobile-private",
                HTTP_AUTHORIZATION=f"Bearer {tampered_token}",
            ).status_code,
            401,
        )
        self.assertEqual(
            mobile.get(
                "/api/mobile-private",
                HTTP_AUTHORIZATION=f"Bearer {native_tokens['id_token']}",
            ).status_code,
            401,
        )

        logout_response = fresh_browser.post(
            "/auth/logout",
            secure=True,
            HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://testserver",
        )
        self.assertEqual(logout_response.status_code, 200)
        self.assertFalse(logout_response.json()["authenticated"])
        self.assertFalse(Session.objects.filter(session_key=post_login_key).exists())
        logged_out = Client()
        logged_out.cookies[settings.SESSION_COOKIE_NAME] = post_login_key
        self.assertEqual(logged_out.get("/api/browser-private").status_code, 401)
        self.assertEqual(logout_response.cookies[settings.SESSION_COOKIE_NAME]["max-age"], 0)
