"""Authorization policy for cryptographically verified GitHub OIDC claims.

This module does not parse JWTs, verify signatures, or fetch JWKS.  Its input
must come from a cryptographic verifier supplied by a later live-broker PR.  It
only applies the closed Task 014 DEV authorization and temporal policy to the
already-verified claim values.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import threading
from typing import Any, Callable, Mapping, Protocol

from .policy import DeploymentPolicyError, validate_source_sha


DEV_ISSUER = "https://token.actions.githubusercontent.com"
DEV_AUDIENCE = "https://deploy-dev.omnilyzer.ai/task014-dev"
DEV_REPOSITORY = "MichaelTrueX/omnilyzer-platform"
DEV_REPOSITORY_ID = 1350104356
DEV_REPOSITORY_OWNER_ID = 130741173
DEV_WORKFLOW_REF = (
    "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-promote.yml"
    "@refs/heads/main"
)
DEV_REF = "refs/heads/main"
DEV_ENVIRONMENT = "task014-dev"
DEV_EVENT_NAME = "workflow_dispatch"
DEV_RUNNER_ENVIRONMENT = "github-hosted"

MAX_TOKEN_LIFETIME_SECONDS = 300
MAX_RECEIVED_AGE_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 30
MAX_DECIMAL_IDENTIFIER = 2**63 - 1
MAX_JTI_LENGTH = 128

REQUIRED_AUTHORIZATION_CLAIMS = frozenset({
    "iss", "aud", "repository", "repository_id", "repository_owner_id",
    "workflow_ref", "workflow_sha", "ref", "environment", "event_name",
    "runner_environment", "run_id", "run_attempt", "actor_id", "iat",
    "nbf", "exp", "jti",
})
_DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
_JTI_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")


class OIDCAuthorizationError(DeploymentPolicyError):
    """Already-verified OIDC claims do not authorize Task 014 DEV."""


class ReplayError(DeploymentPolicyError):
    """A replay identifier was already consumed or replay state failed closed."""


class ReplayUnavailableError(ReplayError):
    """Replay persistence is unavailable, corrupt, or beyond its safe bound."""


@dataclass(frozen=True)
class AuthorizedGitHubIdentity:
    issuer: str
    audience: str
    repository: str
    repository_id: int
    repository_owner_id: int
    workflow_ref: str
    workflow_sha: str
    ref: str
    environment: str
    event_name: str
    runner_environment: str
    run_id: int
    run_attempt: int
    actor_id: int
    issued_at: int
    not_before: int
    expires_at: int
    jti: str


@dataclass(frozen=True)
class GitHubOIDCAuthorizationPolicy:
    """Closed immutable workload-identity allowlist for one environment."""

    issuer: str
    audience: str
    repository: str
    repository_id: int
    repository_owner_id: int
    workflow_ref: str
    ref: str
    environment: str
    event_name: str
    runner_environment: str
    maximum_token_lifetime_seconds: int
    maximum_received_age_seconds: int
    maximum_clock_skew_seconds: int


DEV_AUTHORIZATION_POLICY = GitHubOIDCAuthorizationPolicy(
    DEV_ISSUER, DEV_AUDIENCE, DEV_REPOSITORY, DEV_REPOSITORY_ID,
    DEV_REPOSITORY_OWNER_ID, DEV_WORKFLOW_REF, DEV_REF, DEV_ENVIRONMENT,
    DEV_EVENT_NAME, DEV_RUNNER_ENVIRONMENT, MAX_TOKEN_LIFETIME_SECONDS,
    MAX_RECEIVED_AGE_SECONDS, MAX_CLOCK_SKEW_SECONDS,
)


def _exact_string(claims: Mapping[str, Any], name: str, expected: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or value != expected:
        raise OIDCAuthorizationError(f"OIDC claim {name} is not authorized")
    return value


def _decimal_identifier(claims: Mapping[str, Any], name: str) -> int:
    """Validate GitHub custom ID claims, which GitHub serializes as strings."""

    value = claims.get(name)
    if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
        raise OIDCAuthorizationError(f"OIDC claim {name} must be a positive decimal string")
    number = int(value)
    if number > MAX_DECIMAL_IDENTIFIER:
        raise OIDCAuthorizationError(f"OIDC claim {name} exceeds its bound")
    return number


def _timestamp(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OIDCAuthorizationError(f"OIDC claim {name} must be a non-negative integer")
    return value


def validate_jti(value: Any) -> str:
    """Return one bounded non-path JTI or fail closed."""

    if (not isinstance(value, str) or len(value) > MAX_JTI_LENGTH
            or _JTI_RE.fullmatch(value) is None or ".." in value):
        raise OIDCAuthorizationError("OIDC claim jti is not a bounded safe identifier")
    return value


def authorize_verified_github_oidc(
    claims: Mapping[str, Any], *, received_at: int,
) -> AuthorizedGitHubIdentity:
    """Authorize cryptographically verified claims at a caller-supplied time.

    Extra token claims are ignored: they neither grant nor widen authority.
    Every claim used for authorization is explicitly named and fail-closed.
    """

    if not isinstance(claims, Mapping):
        raise OIDCAuthorizationError("verified OIDC claims must be a mapping")
    if isinstance(received_at, bool) or not isinstance(received_at, int) or received_at < 0:
        raise OIDCAuthorizationError("received_at must be a non-negative integer")
    missing = REQUIRED_AUTHORIZATION_CLAIMS - set(claims)
    if missing:
        raise OIDCAuthorizationError(f"verified OIDC claims are missing: {sorted(missing)}")

    issuer = _exact_string(claims, "iss", DEV_ISSUER)
    audience = _exact_string(claims, "aud", DEV_AUDIENCE)
    repository = _exact_string(claims, "repository", DEV_REPOSITORY)
    repository_id = _decimal_identifier(claims, "repository_id")
    owner_id = _decimal_identifier(claims, "repository_owner_id")
    if repository_id != DEV_REPOSITORY_ID or owner_id != DEV_REPOSITORY_OWNER_ID:
        raise OIDCAuthorizationError("GitHub repository numeric identity is not authorized")
    workflow_ref = _exact_string(claims, "workflow_ref", DEV_WORKFLOW_REF)
    workflow_sha_value = claims.get("workflow_sha")
    try:
        workflow_sha = validate_source_sha(workflow_sha_value)
    except DeploymentPolicyError as exc:
        raise OIDCAuthorizationError("OIDC workflow_sha is not an exact revision") from exc
    ref = _exact_string(claims, "ref", DEV_REF)
    environment = _exact_string(claims, "environment", DEV_ENVIRONMENT)
    event_name = _exact_string(claims, "event_name", DEV_EVENT_NAME)
    runner = _exact_string(
        claims, "runner_environment", DEV_RUNNER_ENVIRONMENT,
    )
    run_id = _decimal_identifier(claims, "run_id")
    run_attempt = _decimal_identifier(claims, "run_attempt")
    actor_id = _decimal_identifier(claims, "actor_id")
    issued_at = _timestamp(claims, "iat")
    not_before = _timestamp(claims, "nbf")
    expires_at = _timestamp(claims, "exp")

    if expires_at <= issued_at or not_before > expires_at:
        raise OIDCAuthorizationError("OIDC timestamps have impossible ordering")
    if expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS:
        raise OIDCAuthorizationError("OIDC token lifetime exceeds five minutes")
    if issued_at > received_at + MAX_CLOCK_SKEW_SECONDS:
        raise OIDCAuthorizationError("OIDC token was issued too far in the future")
    if not_before > received_at + MAX_CLOCK_SKEW_SECONDS:
        raise OIDCAuthorizationError("OIDC token is not yet valid")
    if received_at > expires_at + MAX_CLOCK_SKEW_SECONDS:
        raise OIDCAuthorizationError("OIDC token has expired")
    if received_at - issued_at > MAX_RECEIVED_AGE_SECONDS:
        raise OIDCAuthorizationError("OIDC token was not received within sixty seconds")

    return AuthorizedGitHubIdentity(
        issuer, audience, repository, repository_id, owner_id, workflow_ref,
        workflow_sha, ref, environment, event_name, runner, run_id, run_attempt,
        actor_id, issued_at, not_before, expires_at, validate_jti(claims.get("jti")),
    )


class ReplayGuard(Protocol):
    """Durably and atomically consume a JTI once through expiry plus skew.

    Production implementations must use bounded durable local state and fail
    closed when that state is unavailable or corrupt.  In-memory state is not a
    production replay boundary.
    """

    def consume(
        self, jti: str, *, expires_at: int, request_hash: str,
        run_id: int, run_attempt: int,
    ) -> None:
        ...


class InMemoryReplayGuard:
    """Deterministic contract-test implementation; never a production guard."""

    def __init__(self, current_time: Callable[[], int], *, maximum_entries: int = 1024):
        if isinstance(maximum_entries, bool) or maximum_entries <= 0:
            raise ValueError("maximum_entries must be positive")
        self._current_time = current_time
        self._maximum_entries = maximum_entries
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(
        self, jti: str, *, expires_at: int, request_hash: str,
        run_id: int, run_attempt: int,
    ) -> None:
        # Validate all contract inputs even though only JTI/expiry are retained.
        value = validate_jti(jti)
        if (isinstance(expires_at, bool) or not isinstance(expires_at, int)
                or expires_at < 0):
            raise ReplayUnavailableError("replay expiry is invalid")
        if (not isinstance(request_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", request_hash) is None):
            raise ReplayUnavailableError("replay request hash is invalid")
        for name, number in (("run_id", run_id), ("run_attempt", run_attempt)):
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise ReplayUnavailableError(f"replay {name} is invalid")
        with self._lock:
            try:
                now = self._current_time()
            except Exception as exc:
                raise ReplayUnavailableError("replay clock is unavailable") from exc
            if isinstance(now, bool) or not isinstance(now, int) or now < 0:
                raise ReplayUnavailableError("replay clock is unavailable")
            self._entries = {
                key: retention for key, retention in self._entries.items()
                if retention >= now
            }
            if value in self._entries:
                raise ReplayError("OIDC jti was already consumed")
            if len(self._entries) >= self._maximum_entries:
                raise ReplayUnavailableError("replay state reached its safe bound")
            self._entries[value] = expires_at + MAX_CLOCK_SKEW_SECONDS
