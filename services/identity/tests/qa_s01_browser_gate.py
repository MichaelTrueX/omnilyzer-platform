"""QA-only Chromium S01 identity gate backed by real Django/PostgreSQL session.

Browser /auth/session goes to an actual independent Django Client backed by
the verified Keycloak identity session; private Native APIs are held at 503.
This is NOT a full private lesson acceptance or a synthetic authenticated stub.
"""
from http.cookies import SimpleCookie
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
from urllib.parse import urlparse
from django.test import Client
from playwright.sync_api import sync_playwright

ORIGIN = "https://app.sumlaude.com"


def verify(browser_client, *, authenticated=True, old_cookies=None):
    root = Path(os.environ["S01_QA_PRIVATE_BUILD_ROOT"]).resolve()
    index = root / "index.html"
    assert root.is_dir() and index.is_file()
    assert root.name == "dist-private-bff-candidate"
    assert browser_client.get("/auth/session", secure=True).json()["authenticated"] is authenticated
    errors, requests = [], []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            context = browser.new_context(viewport={"width": 390, "height": 844})
            cookie_values = old_cookies
            if cookie_values is None:
                cookie_values = []
                for key in ("__Host-omnilyzer_identity", "__Host-sumlaude_session"):
                    item = browser_client.cookies[key]
                    cookie_values.append({"name":key,"value":item.value,"url":ORIGIN,
                                          "secure":True,"httpOnly":True,"sameSite":"Lax"})
            context.add_cookies(cookie_values)

            def respond(route):
                req = route.request
                url = urlparse(req.url)
                if url.scheme != "https" or url.netloc != "app.sumlaude.com":
                    return route.abort()
                p = url.path
                requests.append(p)
                if p == "/auth/session":
                    # Read the genuine, PostgreSQL-backed Django session from
                    # the very cookies supplied by Chromium, not a bool stub.
                    def read_django_state():
                        cookies = SimpleCookie()
                        cookies.load(req.headers.get("cookie",""))
                        client = Client(enforce_csrf_checks=True, HTTP_HOST="testserver")
                        for key, value in cookies.items():
                            client.cookies[key] = value.value
                        return client.get("/auth/session",secure=True)
                    # Django ORM cannot be used on Playwright's asyncio loop.
                    with ThreadPoolExecutor(max_workers=1) as worker:
                        state = worker.submit(read_django_state).result(timeout=10)
                    return route.fulfill(status=state.status_code,
                                         content_type="application/json",
                                         headers={"cache-control":"no-store"},
                                         body=state.content)
                if p.startswith("/api/"):
                    # Native product is deliberately held. Never return lesson
                    # content on this source-only identity gate smoke test.
                    return route.fulfill(status=503,content_type="application/json",
                                         body='{"error":"private test API held"}')
                if p in ("/", "/start", "/index.html"):
                    return route.fulfill(status=200,content_type="text/html",
                                         body=index.read_bytes())
                if p.startswith("/assets/") and ".." not in p:
                    asset=(root / p.lstrip("/")).resolve()
                    if not asset.is_relative_to(root) or not asset.is_file():
                        return route.fulfill(status=404,body="not found")
                    mimetype = "text/css" if p.endswith(".css") else "application/javascript"
                    return route.fulfill(status=200,content_type=mimetype,
                                         body=asset.read_bytes())
                return route.fulfill(status=404,body="not found")

            context.route("**/*",respond)
            page = context.new_page()
            page.on("pageerror",lambda error:errors.append(str(error)))
            page.goto(ORIGIN+"/")
            if authenticated:
                page.get_by_role("navigation",name="Account session").wait_for(timeout=20000)
                page.get_by_role("heading",name="Learning unavailable").wait_for(timeout=20000)
                assert any(x.startswith("/api/") for x in requests)
                print("REAL_KEYCLOAK_PG_DJANGO_SESSION_TO_S01_CHROMIUM_AUTH_GATE_PASS")
            else:
                page.get_by_role("heading",name="Sign in to study").wait_for(timeout=20000)
                assert not any(x.startswith("/api/") for x in requests)
                print("REAL_KEYCLOAK_LOGOUT_TO_S01_CHROMIUM_PRIVATE_HOLD_PASS")
            assert "/auth/session" in requests and not errors, errors
            return cookie_values
        finally:
            browser.close()
