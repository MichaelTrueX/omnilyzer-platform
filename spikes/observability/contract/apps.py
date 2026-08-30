"""Django startup hook for the isolated observability fixture."""

from __future__ import annotations

import atexit
import logging

from django.apps import AppConfig

from .runtime import initialize_safely
from .structured_logging import JsonFormatter


class ContractConfig(AppConfig):
    """Configure one JSON stdout handler and a failure-isolated runtime."""

    name = "contract"

    def ready(self) -> None:
        runtime = initialize_safely()
        # Product integration must own the processor lifecycle. The provider's
        # shutdown is bounded by the configured exporter timeout and is isolated
        # from application responses by the asynchronous processor.
        atexit.register(runtime.shutdown)
        logger = logging.getLogger("omnilyzer.observability")
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                JsonFormatter(
                    service=runtime.config.service,
                    product=runtime.config.product,
                    environment=runtime.config.environment,
                )
            )
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
