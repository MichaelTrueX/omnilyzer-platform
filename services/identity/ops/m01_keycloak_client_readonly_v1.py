#!/usr/bin/env python3
"""File: services/identity/ops/m01_keycloak_client_readonly_v1.py

Purpose: Classify the real persisted, existing sumlaude-bff Keycloak client
    after the one-shot public callback operator ended in a post-write HOLD.
    This NEVER calls Keycloak update or changes roles, flags, clients or users.
    Report only fixed-name pass/fail fields, status codes and receipt presence.
Related: services/identity/ops/keycloak_add_public_callback_once.py,
    services/identity/tests/test_m01_keycloak_client_readonly_v1.py,
    deployment/enable_prod_m01_keycloak_readonly_v1.py and PR #298.
Precondition: Root-owned 0500 installed copy at the fixed OPERATOR path.
No client JSON, secret, password, ID, bearer token or unknown field is logged.
"""
from __future__ import annotations

import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile

# Section: Fixed trust boundaries from the already M04-approved M01 operator.
HOST = "truexmainserver"
OPERATOR = Path("/usr/local/sbin/m01-keycloak-client-readonly-v1")
REVIEWED_OPERATOR = Path("/usr/local/sbin/m01-keycloak-public-callback-once")
REVIEWED_SHA = "6a43414a89a38514a3553bb92374d9f520e278d4bf8b4a3bc2a61e7015ff2d2d"
EXPECTED_CLIENT = "sumlaude-bff"
EXPECTED_APP = "https://app.sumlaude.com/auth/callback"
EXPECTED_PUBLIC = "https://sumlaude.com/auth/callback"
EXPECTED_ORIGIN = "https://app.sumlaude.com"


def reject(reason: str) -> None:
    """Stop with only a bounded, non-secret reason."""
    raise RuntimeError("M01_KC_READONLY_HOLD_" + reason)


def sha256(path: Path) -> str:
    """Hash only fixed local executable bytes for source provenance."""
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def source_checked(path: Path, *, expected: str) -> None:
    """Require exactly one protected root-owned, executable Python source."""
    m = path.lstat()
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1
            or stat.S_IMODE(m.st_mode) != 0o500
            or sha256(path) != expected):
        reject("REVIEWED_OPERATOR_DRIFT")


def root_entrypoint() -> None:
    """Refuse an untrusted source checkout or another host/identity."""
    if (os.getuid() != 0 or os.geteuid() != 0
            or socket.gethostname().split(".")[0] != HOST):
        reject("EXPECTED_PRODUCTION_ROOT")
    if Path(__file__).absolute() != OPERATOR:
        reject("REVIEWED_ROOT_INSTALLED_PATH_ONLY")
    m = OPERATOR.lstat()
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1
            or stat.S_IMODE(m.st_mode) != 0o500):
        reject("READONLY_OPERATOR_OWNERSHIP")
    source_checked(REVIEWED_OPERATOR, expected=REVIEWED_SHA)


def load_reviewed_operator():
    """Import only the validated root-owned existing Keycloak read functions."""
    loader = SourceFileLoader("_m01_kc_reviewed_once", str(REVIEWED_OPERATOR))
    spec = spec_from_loader("_m01_kc_reviewed_once", loader)
    if spec is None:
        reject("REVIEWED_SOURCE_IMPORT")
    module = module_from_spec(spec)
    # The audit must not create persistent root-owned __pycache__ files while
    # loading the already reviewed operator. Only /run temporary admin
    # session data is permitted for this read-only inspection.
    prior = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = prior
    return module


def safe_receipts(receipt_dir: Path) -> dict[str, str]:
    """Expose only presence of one-shot markers, never their contents."""
    names = ("attempt.json", "success.json")
    if not receipt_dir.exists() and not receipt_dir.is_symlink():
        return {name: "ABSENT" for name in names}
    m = receipt_dir.lstat()
    if (not stat.S_ISDIR(m.st_mode) or m.st_uid != 0
            or stat.S_IMODE(m.st_mode) != 0o700):
        reject("RECEIPTS_UNSAFE")
    out = {}
    for name in names:
        f = receipt_dir / name
        if not f.exists() and not f.is_symlink():
            out[name] = "ABSENT"
            continue
        st = f.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            reject("RECEIPT_TYPE_UNSAFE")
        out[name] = "PRESENT"
    return out


def classify(client: dict) -> dict[str, str]:
    """Report fixed contract keys as PASS/FAIL only, never actual values."""
    if not isinstance(client, dict):
        reject("CLIENT_READBACK_NOT_OBJECT")
    attributes = client.get("attributes")
    if not isinstance(attributes, dict):
        attributes = {}
    client_id = client.get("id")
    cases = {
        "CLIENT_ID": client.get("clientId") == EXPECTED_CLIENT,
        "CLIENT_UUID_FORMAT": (isinstance(client_id, str) and
                               re.fullmatch(r"[a-zA-Z0-9-]{16,80}", client_id) is not None),
        "PROTOCOL": client.get("protocol") == "openid-connect",
        "CONFIDENTIAL": client.get("publicClient") is False,
        "ENABLED": client.get("enabled") is True,
        "STANDARD_FLOW": client.get("standardFlowEnabled") is True,
        "IMPLICIT_FLOW_DISABLED": client.get("implicitFlowEnabled") is False,
        "PASSWORD_GRANTS_DISABLED": client.get("directAccessGrantsEnabled") is False,
        "SERVICE_ACCOUNTS_DISABLED": client.get("serviceAccountsEnabled") is False,
        "PKCE_S256": attributes.get("pkce.code.challenge.method") == "S256",
        "PRIVATE_WEB_ORIGIN_ONLY": client.get("webOrigins") == [EXPECTED_ORIGIN],
        "TWO_EXACT_REDIRECTS": client.get("redirectUris") ==
            [EXPECTED_APP, EXPECTED_PUBLIC],
    }
    return {name: ("PASS" if matches else "FAIL")
            for name, matches in cases.items()}


def client_readonly(kc) -> dict:
    """Fetch exactly one admin-client document without printing its bytes."""
    admin = kc.root_admin_env()
    with tempfile.TemporaryDirectory(prefix="m01-kc-readonly-",
                                     dir="/run") as private_dir:
        directory = Path(private_dir)
        directory.chmod(0o700)
        config = directory / "kcadm.config"
        env = dict(os.environ)
        env["HOME"] = private_dir
        env["KC_CLI_PASSWORD"] = admin["KC_BOOTSTRAP_ADMIN_PASSWORD"]
        kc.command([
            str(kc.KCADM), "config", "credentials", "--config", str(config),
            "--server", kc.SERVER, "--realm", "master",
            "--user", admin["KC_BOOTSTRAP_ADMIN_USERNAME"],
        ], env=env)
        # Existing reviewed helper issues only GET clients?q=clientId, no PUT.
        return kc.admin_client(config, env)


def main() -> int:
    """Single exact read-only action, no caller-supplied parameters."""
    if sys.argv[1:] != ["inspect"]:
        reject("ONLY_EXACT_INSPECT_ARGUMENT")
    root_entrypoint()
    kc = load_reviewed_operator()
    before = safe_receipts(kc.RECEIPTS)
    app, public = kc.public_preflight()
    current = classify(client_readonly(kc))
    after = safe_receipts(kc.RECEIPTS)
    if before != after:
        reject("RECEIPTS_CHANGED_DURING_READONLY_GET")
    print("M01_KC_READONLY_ATTEMPT_RECEIPT=" + after["attempt.json"])
    print("M01_KC_READONLY_SUCCESS_RECEIPT=" + after["success.json"])
    print("M01_KC_READONLY_APP_CALLBACK_STATUS=" + str(app))
    print("M01_KC_READONLY_PUBLIC_CALLBACK_STATUS=" + str(public))
    for name, status in sorted(current.items()):
        print("M01_KC_FIELD_" + name + "=" + status)
    print("M01_KC_HISTORICAL_NON_REDIRECT_PREIMAGE=NOT_CAPTURED")
    print("M01_KC_READONLY_SUMMARY=" +
          ("CURRENT_KNOWN_FIELDS_MATCH_BUT_HISTORY_UNPROVEN"
           if all(state == "PASS" for state in current.values())
           else "CURRENT_CLIENT_CONTRACT_MISMATCH_HOLD"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, TypeError) as error:
        print(str(error) if str(error).startswith("M01_KC_READONLY_HOLD_")
              else "M01_KC_READONLY_HOLD_REDACTED_FAILURE", file=sys.stderr)
        raise SystemExit(2)
