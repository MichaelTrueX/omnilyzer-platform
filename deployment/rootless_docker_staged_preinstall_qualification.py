"""deployment/rootless_docker_staged_preinstall_qualification.py - C32ZV.

Purpose:
- qualify the exact C32ZS package bundle together with the still-clean C32ZQ
  host boundary immediately before any privileged package installation;
- allow only the reviewed final staging directory while keeping the interrupted
  C32ZU incoming path and every other pre-install mutation surface absent.

Linked files:
- deployment/rootless_docker_preinstall_qualification.py
- deployment/rootless_docker_package_bundle_qualification.py
- deployment/rootless_docker_installation_authority.py
"""

from __future__ import annotations

from dataclasses import dataclass
import os

from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from .rootless_docker_package_bundle_qualification import (
    RootlessDockerPackageBundleEvidence,
    qualify_rootless_docker_package_bundle,
)
from .rootless_docker_preinstall_qualification import (
    RootlessDockerPreinstallEvidence,
    _qualify_host_once,
    _root_identity,
)


__all__ = (
    "RootlessDockerStagedPreinstallQualificationError",
    "RootlessDockerStagedPreinstallEvidence",
    "qualify_rootless_docker_staged_preinstall",
)

_ERROR = "rootless Docker staged preinstall qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_INCOMING_PATH = INSTALLATION_AUTHORITY.staging_directory + ".incoming"


class RootlessDockerStagedPreinstallQualificationError(Exception):
    """One fixed external failure for the staged pre-install boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerStagedPreinstallEvidence:
    """Immutable combined host and exact-package-bundle observation."""

    host: RootlessDockerPreinstallEvidence
    bundle: RootlessDockerPackageBundleEvidence

    def __post_init__(self) -> None:
        """Reject forged, subclassed, or authority-divergent evidence."""

        if (
            type(self.host) is not RootlessDockerPreinstallEvidence
            or type(self.bundle) is not RootlessDockerPackageBundleEvidence
            or self.bundle.staging_directory
            != INSTALLATION_AUTHORITY.staging_directory
        ):
            raise ValueError(_ERROR)
        RootlessDockerPreinstallEvidence.__post_init__(self.host)
        RootlessDockerPackageBundleEvidence.__post_init__(self.bundle)


def _require_incoming_absent() -> None:
    """Require no interrupted C32ZU incoming directory or substitute object."""

    try:
        os.lstat(_INCOMING_PATH)
    except FileNotFoundError:
        return
    raise OSError


def _qualify_once() -> RootlessDockerStagedPreinstallEvidence:
    """Bind one exact bundle observation to an unchanged clean host state."""

    identity = _root_identity()
    _require_incoming_absent()
    host_before = _qualify_host_once()
    if _root_identity() != identity:
        raise OSError
    _require_incoming_absent()

    bundle = qualify_rootless_docker_package_bundle()
    if _root_identity() != identity:
        raise OSError
    _require_incoming_absent()

    host_after = _qualify_host_once()
    if host_after != host_before or _root_identity() != identity:
        raise OSError
    _require_incoming_absent()

    return RootlessDockerStagedPreinstallEvidence(
        host=host_after,
        bundle=bundle,
    )


def qualify_rootless_docker_staged_preinstall() -> RootlessDockerStagedPreinstallEvidence:
    """Require two identical root-only staged pre-install observations."""

    try:
        first = _qualify_once()
        second = _qualify_once()
        if second != first:
            raise OSError
        return first
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerStagedPreinstallQualificationError(_ERROR) from None
