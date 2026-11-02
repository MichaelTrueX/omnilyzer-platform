"""File: deployment/analytics_broker_service_entrypoint.py

Purpose: Approved-only service entrypoint for one original Task014 DEV
         broker on the SAME 127.0.0.1:3031 /task014/dev/promote endpoint.
Related: deployment/analytics_broker_service.py,
         deployment/broker_service_entrypoint.py (original unchanged),
         deployment/systemd/dev/analytics-broker-enabled.conf,
         deployment/tests/test_analytics_broker_service.py.

Sections: original graceful lifecycle signals, exact one-process entrypoint
          and fail-closed exit status; this does not install or start systemd.

SECURITY: This module is NOT in the installed source set. Activation requires
a separately approved, root-owned systemd drop-in and verified source files.
No additional internet-facing route, port or Docker credential is created.
"""
from __future__ import annotations

import signal
import sys

from .analytics_broker_service import (
    AnalyticsBrokerSourceError, run_approved_analytics_broker_service,
)
from .broker_loopback_listener import BrokerStopController


def main() -> int:
    """Run only the root-admitted, original-loopback broker until stopped."""
    controller = BrokerStopController()
    previous: list[tuple[int, object]] = []
    exit_code = 1
    control: BaseException | None = None

    def request_stop(_signum: int, _frame: object) -> None:
        """Use original broker lifecycle: finish current request then exit."""
        controller.request_stop()

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous.append((signum, signal.signal(signum, request_stop)))
        if run_approved_analytics_broker_service(stop_controller=controller) is None:
            exit_code = 0
    except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
        control = error
    except Exception:
        exit_code = 1
    finally:
        for signum, old_handler in reversed(previous):
            try:
                signal.signal(signum, old_handler)
            except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
                control = error
            except Exception:
                exit_code = 1
    if control is not None:
        raise control
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    raise SystemExit(main())
