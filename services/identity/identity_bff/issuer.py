"""Restricted server-to-S03 database issuance, no auto-provisioning of learners."""
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

import psycopg
from django.conf import settings

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")


class AdmissionError(Exception):
    pass


def _function(value):
    if not _IDENTIFIER.fullmatch(value) or ".qa_" in value:
        raise AdmissionError("only reviewed production issuer functions allowed")
    return value


def issue(principal):
    if (principal.get("issuer") != settings.OIDC_ISSUER or
        not isinstance(principal.get("sub"), str) or
        not 8 <= len(principal["sub"]) <= 255):
        raise AdmissionError("principal not verified")
    cookie = secrets.token_hex(32)
    digest = hashlib.sha256(cookie.encode("ascii")).digest()
    expires = datetime.now(timezone.utc) + timedelta(seconds=settings.PRODUCT_SESSION_SECONDS)
    fn = _function(settings.SUMLAUDE_ISSUE_FUNCTION)
    try:
        with psycopg.connect(settings.SUMLAUDE_ISSUER_DSN, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute(f"SELECT {fn}(%s,%s,%s,%s)",
                    (principal["issuer"], principal["sub"], digest, expires))
                result = cur.fetchone()
                if not result or not isinstance(result[0], int) or result[0] <= 0:
                    raise AdmissionError("learner admission denied")
    except (psycopg.Error, OSError) as exc:
        raise AdmissionError("restricted session issuance unavailable") from exc
    return cookie, digest.hex()


def revoke(digest_hex):
    if not isinstance(digest_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_hex):
        raise AdmissionError("invalid session digest")
    fn = _function(settings.SUMLAUDE_REVOKE_FUNCTION)
    try:
        with psycopg.connect(settings.SUMLAUDE_ISSUER_DSN, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute(f"SELECT {fn}(%s)", (bytes.fromhex(digest_hex),))
                result = cur.fetchone()
                if not result or not isinstance(result[0], bool):
                    raise AdmissionError("revocation response invalid")
                return result[0]
    except (psycopg.Error, OSError) as exc:
        raise AdmissionError("restricted session revocation unavailable") from exc
