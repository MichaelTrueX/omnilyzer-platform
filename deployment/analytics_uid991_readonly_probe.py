"""File: deployment/analytics_uid991_readonly_probe.py

Purpose: Identify which existing Task014 UID991 read-only acceptance predicate
         fails, without exposing Docker API responses, secrets, or error text.
Related: deployment/analytics_active_state_review.py,
         deployment/analytics_executor_service_config.py,
         deployment/analytics_signed_release_consumer.py,
         deployment/tests/test_analytics_uid991_readonly_probe.py.

Authority: Diagnostic SOURCE ONLY. This module grants no privilege, release,
           source-install, replay, route, or rollback authority. A separate,
           independently approved root-owned launcher must provide UID991.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import sys

# Section 1: Exact pre-existing identity and installed-source boundary.
_UID = 991
_GID = 991
_REPLAY_GID = 992
_HOST = "omnilyzerdev"
_SOURCE = Path("/opt/omnilyzer/deployment/analytics-app-candidate")
_EXPECTED_COMMIT = "766e4763f04b0d2dc57b3981374ddc29c6893183"
_MARKERS = (
    "IMPORT", "SOURCE", "ACTIVE", "EMPTY", "IDENTITY",
    "BLUE_PORT_SHAPE", "BLUE_REPODIGEST_SHAPE", "GREEN_EXISTS",
)


def _fixed_results() -> dict[str, str]:
    """Initialize a complete set of fail-closed, fixed-vocabulary results."""
    return {key: "HOLD" for key in _MARKERS}


def _authorized_process() -> bool:
    """Accept only the original UID991/GID991/replay-group runtime on DEV."""
    return (
        os.getuid() == os.geteuid() == _UID
        and os.getgid() == os.getegid() == _GID
        and set(os.getgroups()) == {_REPLAY_GID}
        and socket.gethostname() == _HOST
        and sys.argv == [__file__]
    )


def _trusted_source_root() -> bool:
    """Reject a symlink or writable ancestor of the fixed installed tree."""
    try:
        for candidate in (_SOURCE, *_SOURCE.parents):
            info = os.lstat(candidate)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                return False
        return True
    except OSError:
        return False


def _diagnose() -> dict[str, str]:
    """Execute each original UID991 read-only predicate independently.

    The entire call is expected to run under FD-level stdout/stderr suppression
    by main(), so even imported source and subprocess output remain private.
    """
    result = _fixed_results()
    if not _trusted_source_root():
        return result
    sys.path.insert(0, str(_SOURCE))
    try:
        from deployment.analytics_executor_service_config import (
            load_analytics_executor_service_config,
        )
        from deployment.analytics_active_state_review import (
            inspect_analytics_active_state,
            verify_empty_analytics_successor_slot,
            _unix_get, _DOCKER, _PREFIX,
        )
        from deployment.analytics_signed_release_consumer import (
            PINNED_DIGEST, PINNED_IMAGE,
        )
        result["IMPORT"] = "PASS"
    except Exception:
        return result
    finally:
        # Import-time path is never needed by subsequent imports because the
        # approved deployment package is already loaded into sys.modules.
        sys.path.remove(str(_SOURCE))

    source = ids = active = None
    try:
        source, ids = load_analytics_executor_service_config(
            require_successor=True,
        )
        result["SOURCE"] = "PASS"
    except Exception:
        pass
    try:
        active = inspect_analytics_active_state()
        result["ACTIVE"] = "PASS"
    except Exception:
        pass
    try:
        verify_empty_analytics_successor_slot()
        result["EMPTY"] = "PASS"
    except Exception:
        pass
    if source is not None and ids is not None and active is not None:
        if (
            source.get("reviewed_installed_commit") == _EXPECTED_COMMIT
            and ids.get("expected_workflow_sha") == _EXPECTED_COMMIT
            and ids.get("owner_authorized_first_successor") is True
            and ids.get("expected_executor_uid") == _UID
            and ids.get("expected_executor_gid") == _GID
            and active.active_slot == "blue"
            and active.active_digest == PINNED_DIGEST
            and active.active_image == PINNED_IMAGE
            and active.candidate_probe_present is False
        ):
            result["IDENTITY"] = "PASS"

    # Section 2: Fixed-shape classification of existing read-only Docker GETs.
    # No image IDs, digests, configuration values, network addresses or
    # exception strings are emitted, even if the Docker response is malformed.
    try:
        blue = _unix_get(_DOCKER, "/containers/" + _PREFIX + "blue-1/json")
        if type(blue) is dict:
            net = blue.get("NetworkSettings")
            ports = net.get("Ports") if type(net) is dict else None
            if type(ports) is dict and set(ports) == {"3000/tcp"}:
                if ports["3000/tcp"] is None:
                    result["BLUE_PORT_SHAPE"] = "NULL"
                elif ports["3000/tcp"] == []:
                    result["BLUE_PORT_SHAPE"] = "EMPTY_LIST"
                else:
                    result["BLUE_PORT_SHAPE"] = "OTHER"
            else:
                result["BLUE_PORT_SHAPE"] = "OTHER"
            image_id = blue.get("Image")
            if (type(image_id) is str and image_id.startswith("sha256:")
                    and len(image_id) == 71
                    and all(c in "0123456789abcdef" for c in image_id[7:])):
                image = _unix_get(_DOCKER, "/images/" + image_id + "/json")
                digests = image.get("RepoDigests") if type(image) is dict else None
                if type(digests) is list:
                    result["BLUE_REPODIGEST_SHAPE"] = (
                        "ONE" if len(digests) == 1 else
                        "MULTIPLE" if len(digests) > 1 else "EMPTY"
                    )
    except Exception:
        pass
    try:
        green = _unix_get(_DOCKER, "/containers/" + _PREFIX + "green-1/json")
        result["GREEN_EXISTS"] = "NO" if green is None else "YES"
    except Exception:
        pass
    return result


def main() -> int:
    """Run only as UID991 and print fixed markers after OS-level FD isolation."""
    if not _authorized_process():
        print("M05_UID991_PROCESS_HOLD")
        return 2
    saved_stdout = os.dup(1)
    null_fd = os.open(os.devnull, os.O_WRONLY | os.O_CLOEXEC)
    result = _fixed_results()
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(null_fd, 1)
        os.dup2(null_fd, 2)
        try:
            result = _diagnose()
        except Exception:
            pass
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os.dup2(saved_stdout, 1)
        os.close(saved_stdout)
        os.close(null_fd)
    for key in _MARKERS:
        print(f"M05_UID991_{key}={result[key]}")
    return 0 if all(result[key] == "PASS" for key in _MARKERS[:5]) else 2


# Section 3: Direct invocation entry point. No network listener or mutations.
if __name__ == "__main__":
    raise SystemExit(main())
