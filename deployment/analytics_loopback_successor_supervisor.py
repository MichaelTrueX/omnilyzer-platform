#!/usr/bin/env python3
"""File: deployment/analytics_loopback_successor_supervisor.py

Purpose: Privately supervise the existing Analytics 3141 RootlessKit forwarding
         while the original signed Task014 UID991 executor performs one bounded
         3142 candidate and journalled blue-to-green transaction.
Related: deployment/analytics_loopback_guard.py (existing verified RootlessKit
         API, container identity, and route primitives),
         deployment/analytics_route_journal.py (existing fsync journal),
         deployment/analytics_executor_service_config.py (root V3 admission),
         deployment/analytics_dev_activation_inputs.py (uninstalled service
         drop-in and immutable Git source),
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         deployment/tests/test_analytics_loopback_guard.py.

Sections: root-owned V3 source import, exact live route invariants, initial
          signed blue restoration, unprivileged UID991 monitor and entrypoint.

SECURITY: Product-specific extension of the existing supervisor, not a new
listener or release authority. New process is not active by import or Git
merge. Owner-root must independently install its exact reviewed Git bytes,
the existing root-controlled V3 executor config, the UID991 0700 journal,
and a reversible systemd override. Its only normal mutation is restoring
the ORIGINAL signed blue mapping after the old service's stop-time cleanup.
Once established, only the independently OIDC+Cosign+owner-signed+replayed
UID991 executor may prepare or switch routes. The supervisor itself never
accepts HTTP, a release image or a user-selected address and never starts
a container, writes a database or silently removes a candidate route.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import stat
import sys
import time

_UID = 991
_ROOT = Path("/opt/omnilyzer/deployment/analytics-app-candidate")
_SUCCESSOR_SCOPE = "ANALYTICS_REVIEWED_SUPERVISOR_V2"
_PERIOD = 2.0
_ERROR = "TASK014_ANALYTICS_SUCCESSOR_SUPERVISOR_HOLD"


class SuccessorSupervisorUnavailable(Exception):
    """Fail closed without revealing route, credential, or customer details."""


class _Stop(Exception):
    """One ordinary systemd shutdown, with no route mutation."""


def _stop(_signal: int, _frame: object) -> None:
    """Allow PID1 to stop the monitoring process without deleting 3141."""
    raise _Stop()


def _root_approved_sources():
    """Import only immutable installed V3 modules after root-owned path checks.

    Python -I excludes the working directory and user PYTHONPATH. This
    explicit, fixed root-owned candidate is the only module search addition.
    The original installed executor loader verifies all 26 source SHA hashes
    before the first route operation.
    """
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (
        _UID, _UID, _UID, _UID
    ) or os.environ.get(_SUCCESSOR_SCOPE) != "1":
        raise ValueError("unreviewed supervisor principal")
    for directory in (
        Path("/opt"), Path("/opt/omnilyzer"),
        Path("/opt/omnilyzer/deployment"), _ROOT,
        _ROOT / "deployment",
    ):
        meta = directory.lstat()
        if (
            not stat.S_ISDIR(meta.st_mode)
            or meta.st_uid != 0 or meta.st_gid != 0
            or stat.S_IMODE(meta.st_mode) != 0o755
        ):
            raise ValueError("unreviewed installed code directory")
    if str(_ROOT) in sys.path or len(sys.path) > 12:
        raise ValueError("unexpected Python module search authority")
    sys.path.insert(0, str(_ROOT))
    from deployment.analytics_executor_service_config import (
        load_analytics_executor_service_config,
    )
    from deployment.analytics_route_journal import (
        AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY,
    )
    from deployment import analytics_loopback_guard as guard

    source, identities = load_analytics_executor_service_config()
    if (
        type(source) is not dict
        or type(identities) is not dict
        or identities.get("owner_authorized_first_successor") is not True
        or type(identities.get("expected_workflow_sha")) is not str
        or len(identities["expected_workflow_sha"]) != 40
        or guard._UID != _UID
    ):
        raise ValueError("installed V3 authority denied")
    journal = AnalyticsRouteJournal(
        ROUTE_JOURNAL_DIRECTORY, expected_uid=_UID, expected_gid=_UID,
    )
    # A missing, changed or foreign journal is not an empty authorized store.
    journal.read()
    return guard, journal


def _route_spec(guard, port: int, ip: str) -> dict[str, object]:
    """Construct only exact loopback port forwarding with child port 3000."""
    if port not in (3141, 3142) or type(ip) is not str:
        raise ValueError("unapproved private port")
    return {
        "proto": "tcp4", "parentIP": "127.0.0.1",
        "parentPort": port, "childIP": ip, "childPort": 3000,
    }


def _snapshot(guard, journal, original_id: str, *, startup: bool = False) -> str:
    """Validate Canary and all allowed DURABLE journal transition phases.

    A RootlessKit operation may temporarily leave no 3141 port between the
    signed executor's DELETE and POST. Only the exact previous journal phase
    permits that transient. The supervisor never adopts a new release merely
    because a container is healthy, or makes a port change to reconcile it.
    """
    if type(startup) is not bool:
        raise ValueError("wrong supervisor caller")
    guard._rootless_info()
    guard._container_state(original_id)
    rules = guard._raw_rules()
    if len(rules) not in (1, 2, 3):
        raise ValueError("unexpected RootlessKit rule count")
    if sum(r["spec"] == guard._CANARY for r in rules) != 1:
        raise ValueError("Canary routing changed")
    if any(r["spec"].get("parentIP") != "127.0.0.1"
           or r["spec"].get("proto") != "tcp4" for r in rules):
        raise ValueError("non-private route detected")
    record = journal.read()
    known = [guard._CANARY, guard._TARGET]
    actual = [r["spec"] for r in rules]
    def equals(*expected):
        """Check exact route multiset, not just port numbers."""
        return len(actual) == len(expected) and all(
            actual.count(spec) == expected.count(spec)
            for spec in expected
        )
    if record is None:
        if equals(*known):
            guard._http_ready("/readyz")
            guard._http_ready("/livez")
            return "blue"
        if startup and equals(guard._CANARY):
            return "restore_original_blue"
        raise ValueError("unexpected route without durable journal")
    if (
        record.get("previous_slot") != "blue"
        or record.get("previous_image") != guard._IMAGE
        or record.get("previous_container_id") != original_id
        or record.get("previous_ip") != guard._TARGET["childIP"]
        or record.get("next_slot") != "green"
        or record.get("next_image") == guard._IMAGE
    ):
        raise ValueError("journal not anchored to original signed writer")
    next_ip = guard._verified_slot(
        "green", record["next_image"], record["next_container_id"],
    )
    if next_ip != record["next_ip"]:
        raise ValueError("journal candidate image/endpoint drifted")
    candidate = _route_spec(guard, 3142, next_ip)
    current = _route_spec(guard, 3141, next_ip)
    phase = record["phase"]
    # These are the exact possible intermediate RootlessKit inventories in
    # the existing candidate+switch+durable rollback code. No other service
    # can introduce a new public route, arbitrary port or unknown container.
    allowed = {
        "prepared": (
            (guard._CANARY, guard._TARGET),
            (guard._CANARY, guard._TARGET, candidate),
        ),
        "candidate_ready": (
            (guard._CANARY, guard._TARGET, candidate),
            (guard._CANARY, candidate),
            (guard._CANARY, current, candidate),
            (guard._CANARY, current),
        ),
        "switched": ((guard._CANARY, current),),
        "rollback_pending": (
            (guard._CANARY, current),
            (guard._CANARY,),
            (guard._CANARY, guard._TARGET),
        ),
        "restored": ((guard._CANARY, guard._TARGET),),
    }
    if phase not in allowed or not any(equals(*set_) for set_ in allowed[phase]):
        raise ValueError("unreviewed route or crash phase")
    if phase in ("switched", "restored"):
        guard._http_ready("/readyz")
        guard._http_ready("/livez")
    return phase


def _serve(guard, journal) -> None:
    """Maintain exactly one root-reviewed successor-capable UID991 supervisor.

    Initial startup may re-add only the original signed blue route after
    stopping the OLD unit, which calls its original ExecStopPost cleanup.
    This is the one independently approved maintenance interruption; all
    later green candidate and committed switch mutations belong strictly
    to the signed executor. On abnormal exit do not cleanup either port.
    """
    original_id = guard._identity()
    state = _snapshot(guard, journal, original_id, startup=True)
    if state == "restore_original_blue":
        # No journal, verified running immutable blue and exactly Canary.
        # An ambiguous POST acknowledgment remains a hard HOLD, not deletion.
        received = guard._api(
            guard._ROOTLESS, "POST", "/v1/ports", dict(guard._TARGET),
            status=201,
        )
        if (
            type(received) is not dict
            or type(received.get("id")) is not int
            or received.get("spec") != guard._TARGET
        ):
            raise ValueError("original blue restoration uncertain")
        if _snapshot(guard, journal, original_id) != "blue":
            raise ValueError("original blue restoration not confirmed")
    while True:
        time.sleep(_PERIOD)
        _snapshot(guard, journal, original_id)


def main() -> int:
    """Permit only explicit owner-installed service mode, no public commands."""
    if len(sys.argv) != 2 or sys.argv[1] != "--serve":
        return 2
    original = {}
    try:
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        guard, journal = _root_approved_sources()
        _serve(guard, journal)
    except _Stop:
        return 0
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        sys.stderr.write(_ERROR + "\n")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
