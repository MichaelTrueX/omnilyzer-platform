import html
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


class _LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form" and values.get("method", "").lower() == "post":
            self.action = html.unescape(values.get("action", ""))
        if tag == "input" and values.get("name"):
            self.inputs[values["name"]] = values.get("value", "")


class _StopAtCallback(urllib.request.HTTPRedirectHandler):
    def __init__(self, callback_prefix):
        self.callback_prefix = callback_prefix
        self.location = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(self.callback_prefix):
            self.location = newurl
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(self, req, fp, code, msg, headers):
        newurl = headers.get("Location", "")
        if newurl.startswith(self.callback_prefix):
            self.location = newurl
            return fp
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def complete_keycloak_login(authorization_url, username, password, callback_prefix):
    redirect = _StopAtCallback(callback_prefix)
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar), redirect
    )
    with opener.open(authorization_url, timeout=10) as response:
        page = response.read().decode()
    parser = _LoginForm()
    parser.feed(page)
    if not parser.action:
        raise AssertionError("Keycloak login form was not found")
    parser.inputs.update({"username": username, "password": password})
    request = urllib.request.Request(
        parser.action,
        data=urllib.parse.urlencode(parser.inputs).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            # urllib does not apply browsers' loopback secure-context exception.
            # The cookies were issued by this exact local Keycloak transaction.
            "Cookie": "; ".join(
                f"{cookie.name}={cookie.value}" for cookie in cookie_jar
            ),
        },
    )
    try:
        opener.open(request, timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code not in (301, 302, 303, 307, 308) or redirect.location is None:
            raise
    if redirect.location is None:
        raise AssertionError("Keycloak did not redirect to the registered callback")
    return redirect.location
