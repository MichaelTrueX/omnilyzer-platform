"""Inert C32T broker process entrypoint; only explicit -m execution serves.

No command-line security authority exists. SIGTERM/SIGINT request a graceful
stop; the active request completes through its normal credential cleanup path.
"""

from __future__ import annotations

import signal as _signal
import sys as _sys

from .broker_loopback_listener import BrokerStopController
from .broker_service_bootstrap import run_dev_broker_service as _run_service


__all__ = ("main",)
_SUCCESS = 0
_FAILURE = 1
_USAGE = 2


def main() -> int:
    """Install only lifecycle signals and run the closed broker composition."""

    controller = BrokerStopController()
    previous: list[tuple[int, object]] = []

    def request_stop(_signum: int, _frame: object) -> None:
        controller.request_stop()

    result = _FAILURE
    control: BaseException | None = None
    try:
        for signum in (_signal.SIGTERM, _signal.SIGINT):
            previous.append((signum, _signal.signal(signum, request_stop)))
        if _run_service(stop_controller=controller) is None:
            result = _SUCCESS
    except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
        control = error
    except Exception:
        result = _FAILURE
    finally:
        for signum, handler in reversed(previous):
            try:
                _signal.signal(signum, handler)
            except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
                control = error
            except Exception:
                result = _FAILURE
    if control is not None:
        raise control
    return result


if __name__ == "__main__":
    if len(_sys.argv) != 1:
        raise SystemExit(_USAGE)
    raise SystemExit(main())
