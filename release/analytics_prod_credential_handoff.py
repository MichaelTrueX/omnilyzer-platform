#!/usr/bin/env python3
"""File: release/analytics_prod_credential_handoff.py

Purpose: Encrypt one fresh GitHub Actions OIDC Zot-read credential to the
         already-approved private Analytics PROD X25519 age recipient.
Related: release/private_zot_auth_probe.py,
         .github/workflows/platform-promote.yml,
         deployment/analytics_prod_authenticated_pull.py.

Sections: exact owner/workflow/context admission; original GitHub OIDC request
          and decoded-claims preflight; bounded standard age encryption;
          0600 encrypted artifact custody and no-token diagnostics.

This tool does NOT deploy, download an image, modify Task014 journal/replay,
create credentials on PROD, expose a token in argv/env/logs, or bypass Zot auth.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys

from .private_zot_auth_probe import (
    AUDIENCE, ProbeUnavailableError, _claims_preflight,
    _oidc_token, _workflow_context_preflight,
)

AGE = "/usr/bin/age"
RECIPIENT = "age18h3hqjk25d2t5sxh6x6z0wy6znvgs0x6mcnj78vawjtn3w0n4q8qdjhls7"
OWNER = "MichaelTrueX"
ERROR = "ANALYTICS_PROD_REGISTRY_CREDENTIAL_HANDOFF_HOLD"
MAX_ENCRYPTED = 16_384


def mint_encrypt(environment: dict[str, str], output: Path) -> None:
    """Mint one exact-audience JWT and encrypt it without ever printing it."""
    if (environment.get("GITHUB_ACTOR") != OWNER
            or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or environment.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or environment.get("GITHUB_REF") != "refs/heads/main"):
        raise ProbeUnavailableError(ERROR)
    _workflow_context_preflight(environment)
    work = Path(environment.get("RUNNER_TEMP", ""))
    if not work.is_absolute() or work.is_symlink() or output.parent != work:
        raise ProbeUnavailableError(ERROR)
    if output.name != "m05-analytics-prod-registry-token.age" or output.exists():
        raise ProbeUnavailableError(ERROR)
    jwt = _oidc_token(environment, audience=AUDIENCE)
    from time import time
    _claims_preflight(jwt, environment, int(time()), audience=AUDIENCE)
    # Existing signed GitHub OIDC JWT is the entire process STDIN, not argv.
    # age provides authenticated encryption to the single PROD recipient.
    try:
        result = subprocess.run(
            (AGE, "--encrypt", "--recipient", RECIPIENT, "--output", str(output)),
            input=jwt.encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=12, check=False,
        )
        if result.returncode != 0 or result.stdout:
            raise ProbeUnavailableError(ERROR)
        info = os.lstat(output)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or not 1 <= info.st_size <= MAX_ENCRYPTED):
            raise ProbeUnavailableError(ERROR)
        os.chmod(output, 0o600)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise ProbeUnavailableError(ERROR) from None


def main() -> int:
    """Closed invocation with a single exact artifact name under RUNNER_TEMP."""
    try:
        temp = Path(os.environ["RUNNER_TEMP"])
        output = temp / "m05-analytics-prod-registry-token.age"
        mint_encrypt(dict(os.environ), output)
        print("ANALYTICS_PROD_OIDC_ENCRYPTED_HANDOFF_PASS token=redacted")
        return 0
    except (KeyError, ProbeUnavailableError):
        print(ERROR, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
