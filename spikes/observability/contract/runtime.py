"""Process-local ownership of the isolated observability runtime."""

from __future__ import annotations

import logging
import os
from threading import RLock
from typing import Mapping

from .config import ObservabilityConfig
from .metadata import BuildMetadata, load_build_metadata
from .structured_logging import event
from .telemetry import TelemetryRuntime, build_runtime


_LOGGER = logging.getLogger("omnilyzer.observability")
_LOCK = RLock()


def _synthetic_metadata(config: ObservabilityConfig) -> BuildMetadata:
    return BuildMetadata(
        service=config.service,
        product=config.product,
        environment=config.environment,
        app_version="0.0.0",
        platform_version="0.0.0",
        git_commit="0" * 40,
        deployment_timestamp="1970-01-01T00:00:00Z",
        oci_digest="sha256:" + "0" * 64,
    )


_DISABLED_CONFIG = ObservabilityConfig.from_mapping({})
_RUNTIME = build_runtime(_DISABLED_CONFIG, _synthetic_metadata(_DISABLED_CONFIG))


def get_runtime() -> TelemetryRuntime:
    """Return the current immutable runtime reference."""

    with _LOCK:
        return _RUNTIME


def set_runtime(runtime: TelemetryRuntime) -> TelemetryRuntime:
    """Swap runtimes for startup or deterministic tests and return the prior runtime."""

    global _RUNTIME
    with _LOCK:
        previous = _RUNTIME
        _RUNTIME = runtime
        return previous


def initialize_safely(values: Mapping[str, str] | None = None) -> TelemetryRuntime:
    """Initialize from validated configuration; malformed telemetry disables itself."""

    source = dict(os.environ if values is None else values)
    try:
        config = ObservabilityConfig.from_mapping(source)
    except (KeyError, ValueError):
        event(
            _LOGGER,
            "telemetry.configuration_invalid",
            level=logging.ERROR,
            fields={"action": "disabled"},
        )
        config = _DISABLED_CONFIG

    metadata_values = {
        "APPLICATION_DISTRIBUTION": source.get(
            "APPLICATION_DISTRIBUTION", "omnilyzer-observability-spike"
        ),
        "PLATFORM_DISTRIBUTION": source.get(
            "PLATFORM_DISTRIBUTION", "opentelemetry-sdk"
        ),
        "GIT_COMMIT": source.get("GIT_COMMIT", "0" * 40),
        "OCI_DIGEST": source.get("OCI_DIGEST", "sha256:" + "0" * 64),
        "DEPLOYMENT_TIMESTAMP": source.get(
            "DEPLOYMENT_TIMESTAMP", "1970-01-01T00:00:00Z"
        ),
        "OBSERVABILITY_SERVICE": config.service,
        "OBSERVABILITY_PRODUCT": config.product,
        "OBSERVABILITY_ENVIRONMENT": config.environment,
    }
    try:
        metadata = load_build_metadata(metadata_values)
    except (KeyError, ValueError, LookupError):
        event(
            _LOGGER,
            "deployment.metadata_invalid",
            level=logging.ERROR,
            fields={"action": "synthetic_fallback"},
        )
        metadata = _synthetic_metadata(config)
    runtime = build_runtime(config, metadata)
    set_runtime(runtime)
    return runtime
