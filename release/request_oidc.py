#!/usr/bin/env python3
"""Request a GitHub OIDC JWT without placing either token in a command line."""

from __future__ import annotations

import argparse
import json
import os
import stat
import urllib.parse
import urllib.request
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise RuntimeError("OIDC endpoint redirected unexpectedly")


def request(audience: str, output: Path) -> None:
    base = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not base.startswith("https://") or not request_token:
        raise RuntimeError("GitHub OIDC request environment is unavailable")
    parsed = urllib.parse.urlsplit(base)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("audience", audience))
    url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                  urllib.parse.urlencode(query), ""))
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {request_token}"})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        value = json.load(response).get("value")
    if not isinstance(value, str) or value.count(".") != 2 or "\n" in value:
        raise RuntimeError("GitHub OIDC response did not contain a JWT")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(value)
    print(f"::add-mask::{value}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audience", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request(args.audience, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
