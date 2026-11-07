"""File: deployment/analytics_executor_composition.py

Purpose: Compose the existing original Task014 kernel-checked executor boundary
         with the exact signed Analytics 0.15.0 first-install operation.
         Single product, single private Unix socket, original durable replay.

Related: deployment/analytics_unix_boundary.py (Analytics-only original
         SO_PEERCRED + SCM_RIGHTS listener, handler and socket),
         deployment/analytics_executor.py (exact schema-v2 and original
         replay begin/finish), deployment/analytics_first_install.py (private
         blue health and stop-only rollback), deployment/analytics_private_registry.py
         (original rootless Docker/Zot image manifest and pull),
         deployment/executor_composition.py (unchanged canary graph),
         deployment/replay_sqlite.py (one original shared protected JTI store),
         deployment/tests/test_analytics_executor_composition.py.

Sections: root-reviewed source binding; inert product-only dependency graph;
          original socket listener's explicit one-connection delegation.

SECURITY: This composition does not grant source authorization. The caller MUST
first independently attest the root-owned Task014 installed source manifest,
four source/profile hashes, original installation identity, and an inherited
Analytics systemd socket. Neither a Python mapping nor a request-shaped public
dataclass is a signed deployment grant. This file is not in the installed
original Task014 source set; it does not install/enable/bind/listen/start any
systemd service, Docker, database, secrets or product.
"""
from __future__ import annotations

from .analytics_executor import AnalyticsPrivilegedExecutor
from .analytics_first_install import AnalyticsFirstInstallOperation
from .analytics_private_registry import AnalyticsPrivateZotPullAdapter
from .analytics_unix_boundary import (
    AnalyticsUnixExecutorConnectionHandler,
    AnalyticsUnixExecutorListener,
    _root_reviewed_source,
)
from .docker_runtime import SubprocessCommandRunner
from .replay_sqlite import PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard
from .identity import validate_expected_workflow_sha

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsExecutorComposition:
    """Inert, fixed original Task014-primitive Analytics receiver graph."""

    __slots__ = ("_serve_once", "_reviewed_source")

    def __init__(
        self, *, listener: object,
        reviewed_installed_source: dict[str, str],
        expected_replay_directory_uid: int,
        expected_replay_directory_gid: int,
        expected_broker_uid: int, expected_broker_gid: int,
        expected_executor_uid: int, expected_executor_gid: int,
        expected_socket_owner_uid: int, expected_socket_group_gid: int,
        expected_workflow_sha: str | None = None,
        owner_authorized_first_successor: bool = False,
    ) -> None:
        """Wire the original same replay DB and a strictly separate product.

        The reviewed source mapping and numeric identities MUST originate from
        the existing root-controlled Task014 installation integrity/config
        boundary, never from an incoming GitHub/HTTP promotion request.
        """
        try:
            source = _root_reviewed_source(reviewed_installed_source)
            # V1 remains the original first-install graph. Root V2 is signed
            # review-only DENY. Separately owner-installed root V3 alone
            # selects the original signed UID991 replay/cutover transaction.
            if type(owner_authorized_first_successor) is not bool:
                raise ValueError("invalid owner authorization")
            workflow = None
            if expected_workflow_sha is not None:
                workflow = validate_expected_workflow_sha(
                    expected_workflow_sha,
                )
                if workflow == "0" * 40:
                    raise ValueError("no root-reviewed workflow")
            replay = SQLiteReplayGuard(
                PRODUCTION_REPLAY_DATABASE,
                expected_directory_uid=expected_replay_directory_uid,
                expected_directory_gid=expected_replay_directory_gid,
                expected_broker_uid=expected_broker_uid,
                expected_executor_uid=expected_executor_uid,
            )
            # Actual real command runner is the original bounded implementation,
            # not a caller-supplied arbitrary command or a new Docker API.
            runner = SubprocessCommandRunner()
            registry = AnalyticsPrivateZotPullAdapter(
                runner, reviewed_installed_source=dict(source),
            )
            operation = AnalyticsFirstInstallOperation(
                runner=runner, private_registry=registry,
                reviewed_installed_source=dict(source),
            )
            executor = AnalyticsPrivilegedExecutor(
                replay_guard=replay, private_registry_preflight=registry,
                operation=operation, reviewed_installed_source=dict(source),
            )
            # Construction is inert. Only a separately installed,
            # root-owned generation-3 config may pass the positive Boolean.
            # Existing V1/V2 service configs cannot select this path.
            candidate = None
            journal = None
            if owner_authorized_first_successor:
                if workflow is None:
                    raise ValueError("missing signed successor workflow")
                from .analytics_first_install import (
                    AnalyticsSuccessorCandidateOperation,
                )
                from .analytics_route_journal import (
                    AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY,
                )
                candidate = AnalyticsSuccessorCandidateOperation(
                    runner=runner, private_registry=registry,
                    reviewed_installed_source=dict(source),
                )
                journal = AnalyticsRouteJournal(
                    ROUTE_JOURNAL_DIRECTORY,
                    expected_uid=expected_executor_uid,
                    expected_gid=expected_executor_gid,
                )
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=expected_broker_uid,
                expected_broker_gid=expected_broker_gid,
                reviewed_installed_source=dict(source),
                full_signed_successor_review_only=(workflow is not None and not owner_authorized_first_successor),
                owner_authorized_first_successor=owner_authorized_first_successor,
                candidate_operation=candidate, route_journal=journal,
                expected_workflow_sha=workflow,
            )
            secured = AnalyticsUnixExecutorListener(
                listener=listener, handler=handler,
                expected_socket_owner_uid=expected_socket_owner_uid,
                expected_socket_group_gid=expected_socket_group_gid,
            )
            object.__setattr__(self, "_serve_once", secured.serve_once)
            object.__setattr__(self, "_reviewed_source", source)
        except _CONTROL:
            raise
        except Exception:
            raise TypeError("Analytics Task014 receiver configuration denied") from None

    def __setattr__(self, name: str, value: object) -> None:
        """Prevent post-construction changes to the privileged receiver."""
        raise AttributeError("Analytics Task014 receiver is immutable")

    def __delattr__(self, name: str) -> None:
        """Prevent post-construction deletion of the privileged receiver."""
        raise AttributeError("Analytics Task014 receiver is immutable")

    def serve_once(self) -> None:
        """Delegate one explicit request to the original secure listener."""
        result = object.__getattribute__(self, "_serve_once")()
        if result is not None:
            raise TypeError("Analytics listener returned unexpected response")
        return None


__all__ = ("AnalyticsExecutorComposition",)
