"""File: release/task014_config_cutover.py

Purpose: An offline, separately authorized DEV broker/executor configuration
generation plan and fail-closed rollback. This is NOT an installed runtime
module, CLI, workflow action, or an authorization to operate on a live host.
Links: deployment/broker_service_config.py,
deployment/executor_service_config.py,
release/task014_source_cutover.py,
release/tests/test_task014_config_cutover.py and Task014 PR #209.

Section 1: reviewed immutable configuration inputs and strict schema projection.
Section 2: private root-only host preflight and protected side-by-side staging.
Section 3: service-quiesced, individually atomic replacements with rollback.
The two existing JSON files live in DIFFERENT directories: their replacement
cannot be a single filesystem transaction. Failed second replacement must
restore the first while services remain quiesced; failures requiring manual
recovery are explicitly reported and never dismissed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from deployment.broker_service_config import (
    BROKER_SERVICE_CONFIG_DIRECTORY_MODE,
    BROKER_SERVICE_CONFIG_FILE_MODE,
    PRODUCTION_BROKER_SERVICE_CONFIG_PATH,
    parse_canonical_broker_service_configuration,
)
from deployment.executor_service_config import (
    EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE,
    EXECUTOR_SERVICE_CONFIG_FILE_MODE,
    PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
    parse_canonical_executor_service_configuration,
)
from . import task014_source_cutover as source_cutover

BROKER_FILE = Path(PRODUCTION_BROKER_SERVICE_CONFIG_PATH)
EXECUTOR_FILE = Path(PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH)
_MAX_CONFIG = 4096
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_STAGING_PREFIX = ".task014-config-"


class ConfigurationCutoverHold(Exception):
    """Fail-closed redacted configuration generation or rollback error."""


@dataclass(frozen=True, slots=True)
class ConfigurationPlan:
    """Current canonical source, strictly limited target and explicit digests."""

    source_commit: str
    workflow_sha: str
    broker_gid: int
    executor_gid: int
    broker_previous: bytes = field(repr=False)
    broker_target: bytes = field(repr=False)
    executor_previous: bytes = field(repr=False)
    executor_target: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Prove every object is exact, bounded and independently parseable."""
        if (
            type(self.source_commit) is not str or _SHA40.fullmatch(self.source_commit) is None
            or type(self.workflow_sha) is not str or _SHA40.fullmatch(self.workflow_sha) is None
            or type(self.broker_gid) is not int or type(self.executor_gid) is not int
        ):
            raise ConfigurationCutoverHold("unreviewed configuration generation")
        for raw in (
            self.broker_previous, self.broker_target,
            self.executor_previous, self.executor_target,
        ):
            if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_CONFIG:
                raise ConfigurationCutoverHold("unreviewed configuration generation")
        try:
            previous_broker = parse_canonical_broker_service_configuration(
                self.broker_previous
            )
            target_broker = parse_canonical_broker_service_configuration(
                self.broker_target
            )
            previous_executor = parse_canonical_executor_service_configuration(
                self.executor_previous
            )
            target_executor = parse_canonical_executor_service_configuration(
                self.executor_target
            )
            if (
                target_broker != replace(
                    previous_broker, reviewed_commit=self.source_commit,
                    expected_workflow_sha=self.workflow_sha,
                )
                or target_executor != replace(
                    previous_executor, reviewed_commit=self.source_commit,
                )
                or self.broker_gid != previous_broker.broker_gid
                or self.executor_gid != previous_executor.executor_gid
                or previous_broker.installation_contract()
                    != previous_executor.installation_contract()
                or previous_broker.runtime_configuration_sha256
                    != previous_executor.runtime_configuration_sha256
                or previous_broker.ingress_file_sha256
                    != previous_executor.ingress_file_sha256
                or self.broker_previous == self.broker_target
                or self.executor_previous == self.executor_target
            ):
                raise ValueError
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ConfigurationCutoverHold("unreviewed configuration generation") from None

    def identity(self) -> tuple[str, str, str, str]:
        """Return nonsecret old/target config digests for operator review."""
        return tuple(
            hashlib.sha256(raw).hexdigest()
            for raw in (
                self.broker_previous, self.executor_previous,
                self.broker_target, self.executor_target,
            )
        )


def reviewed_config_plan(
    *, broker_previous: bytes, executor_previous: bytes,
    approved_broker_sha256: str, approved_executor_sha256: str,
    source_plan: source_cutover.SourceGenerationPlan,
    reviewed_workflow_sha: str,
) -> ConfigurationPlan:
    """Only accept independently SHA-pinned actual old canonical config bytes.

    The caller must obtain existing config bytes through an independently
    authorized root preflight. Never infer secrets/configuration from a
    Git checkout, user writable environment, or hard-coded example values.
    """
    try:
        if (
            type(source_plan) is not source_cutover.SourceGenerationPlan
            or type(approved_broker_sha256) is not str
            or type(approved_executor_sha256) is not str
            or _SHA64.fullmatch(approved_broker_sha256) is None
            or _SHA64.fullmatch(approved_executor_sha256) is None
            or type(reviewed_workflow_sha) is not str
            or _SHA40.fullmatch(reviewed_workflow_sha) is None
            or hashlib.sha256(broker_previous).hexdigest() != approved_broker_sha256
            or hashlib.sha256(executor_previous).hexdigest() != approved_executor_sha256
        ):
            raise ValueError
        broker = parse_canonical_broker_service_configuration(broker_previous)
        executor = parse_canonical_executor_service_configuration(executor_previous)
        new_broker = replace(
            broker, reviewed_commit=source_plan.reviewed_commit,
            expected_workflow_sha=reviewed_workflow_sha,
        )
        new_executor = replace(
            executor, reviewed_commit=source_plan.reviewed_commit,
        )
        return ConfigurationPlan(
            source_commit=source_plan.reviewed_commit,
            workflow_sha=reviewed_workflow_sha,
            broker_previous=broker_previous,
            broker_target=new_broker.canonical_bytes(),
            executor_previous=executor_previous,
            executor_target=new_executor.canonical_bytes(),
            broker_gid=broker.broker_gid,
            executor_gid=executor.executor_gid,
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise ConfigurationCutoverHold("configuration preflight unavailable") from None


# Section 2: owned filesystem objects, closed filenames and no symlinks.
def _is_root_owned(info: os.stat_result, gid: int) -> bool:
    """Verify root:configured-group for protected configuration boundaries."""
    return info.st_uid == 0 and info.st_gid == gid


def _validate_file(path: Path, expected: bytes, gid: int, mode: int) -> None:
    """Check a protected root:group file, exact bytes, mode and no hard links."""
    source_cutover._require_root()
    parent = path.parent
    owner = parent.lstat()
    if (
        not stat.S_ISDIR(owner.st_mode)
        or stat.S_ISLNK(owner.st_mode)
        or not _is_root_owned(owner, gid)
        or stat.S_IMODE(owner.st_mode) != (
            BROKER_SERVICE_CONFIG_DIRECTORY_MODE
            if parent == BROKER_FILE.parent else EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE
        )
    ):
        raise ConfigurationCutoverHold("configuration directory unavailable")
    if path.parent not in (BROKER_FILE.parent, EXECUTOR_FILE.parent):
        raise ConfigurationCutoverHold("unapproved configuration directory")
    data = path.lstat()
    if (
        not stat.S_ISREG(data.st_mode) or stat.S_ISLNK(data.st_mode)
        or not _is_root_owned(data, gid)
        or data.st_nlink != 1
        or stat.S_IMODE(data.st_mode) != mode
        or data.st_size > _MAX_CONFIG
    ):
        raise ConfigurationCutoverHold("configuration file unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        state = os.fstat(fd)
        evidence = (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
            "st_size", "st_nlink",
        )
        if any(getattr(state, key) != getattr(data, key) for key in evidence):
            raise ConfigurationCutoverHold("configuration file changed")
        payload = os.read(fd, _MAX_CONFIG + 1)
        after = os.fstat(fd)
        if (payload != expected
                or after.st_size != len(expected)
                or any(getattr(after, key) != getattr(state, key) for key in evidence)):
            raise ConfigurationCutoverHold("configuration bytes mismatch")
    finally:
        os.close(fd)


def readonly_config_preflight(plan: ConfigurationPlan) -> None:
    """Validate both current configs without changing a byte."""
    _validate_file(BROKER_FILE, plan.broker_previous,
                   plan.broker_gid, BROKER_SERVICE_CONFIG_FILE_MODE)
    _validate_file(EXECUTOR_FILE, plan.executor_previous,
                   plan.executor_gid, EXECUTOR_SERVICE_CONFIG_FILE_MODE)


@dataclass(frozen=True, slots=True)
class ConfigurationStaging:
    """Four privately staged configurations; two are retained old backups."""

    broker_candidate: Path
    executor_candidate: Path
    broker_backup: Path
    executor_backup: Path


def _write_stage(path: Path, value: bytes, gid: int, mode: int) -> Path:
    """Write/fsync an O_EXCL stage in the SAME directory as its destination."""
    fd, filename = tempfile.mkstemp(prefix=_STAGING_PREFIX, dir=str(path.parent))
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    directory = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return Path(filename)


def stage_configurations(plan: ConfigurationPlan) -> ConfigurationStaging:
    """Prepare target and complete protected rollback copies; do not activate."""
    source_cutover._require_root()
    readonly_config_preflight(plan)
    try:
        result = ConfigurationStaging(
            broker_candidate=_write_stage(
                BROKER_FILE, plan.broker_target, plan.broker_gid,
                BROKER_SERVICE_CONFIG_FILE_MODE,
            ),
            executor_candidate=_write_stage(
                EXECUTOR_FILE, plan.executor_target, plan.executor_gid,
                EXECUTOR_SERVICE_CONFIG_FILE_MODE,
            ),
            broker_backup=_write_stage(
                BROKER_FILE, plan.broker_previous, plan.broker_gid, 0o600,
            ),
            executor_backup=_write_stage(
                EXECUTOR_FILE, plan.executor_previous, plan.executor_gid, 0o600,
            ),
        )
        _validate_file(result.broker_candidate, plan.broker_target,
                       plan.broker_gid, BROKER_SERVICE_CONFIG_FILE_MODE)
        _validate_file(result.executor_candidate, plan.executor_target,
                       plan.executor_gid, EXECUTOR_SERVICE_CONFIG_FILE_MODE)
        _validate_file(result.broker_backup, plan.broker_previous,
                       plan.broker_gid, 0o600)
        _validate_file(result.executor_backup, plan.executor_previous,
                       plan.executor_gid, 0o600)
        return result
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        # No automatic deletion of partially staged protected files.
        # Root-only review is required before any cleanup.
        raise ConfigurationCutoverHold("configuration staging unavailable") from None


def _checked_stage(path: Path, parent: Path) -> None:
    """Reject user-supplied stage escapes or protected live filenames."""
    if (
        not isinstance(path, Path) or path.parent != parent
        or not path.name.startswith(_STAGING_PREFIX)
        or path == BROKER_FILE or path == EXECUTOR_FILE
    ):
        raise ConfigurationCutoverHold("unapproved configuration stage")


# Section 3: two individually atomic switches, with rollback on failure.
def _replace(path_from: Path, path_to: Path) -> None:
    """Replace a single file on the same filesystem and fsync its directory."""
    if path_from.parent != path_to.parent:
        raise ConfigurationCutoverHold("cross-directory replacement prohibited")
    os.replace(path_from, path_to)
    directory = os.open(
        path_to.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _restore_one(path: Path, previous: bytes, gid: int, mode: int) -> None:
    """Restore one original config from independent, still-pinned plan bytes."""
    stage = _write_stage(path, previous, gid, mode)
    _replace(stage, path)
    _validate_file(path, previous, gid, mode)


def activate_configurations(
    plan: ConfigurationPlan, staged: ConfigurationStaging,
) -> None:
    """Activate both configs only while control-plane services are stopped.

    This is *not* a multi-file atomic exchange. An error triggers best-effort
    byte-exact restoration of both old configs; if restoring either fails,
    report manual recovery required without starting any service.
    """
    source_cutover._require_root()
    source_cutover._require_quiesced()
    readonly_config_preflight(plan)
    targets = (
        (BROKER_FILE, staged.broker_candidate, plan.broker_previous,
         plan.broker_target, plan.broker_gid, BROKER_SERVICE_CONFIG_FILE_MODE),
        (EXECUTOR_FILE, staged.executor_candidate, plan.executor_previous,
         plan.executor_target, plan.executor_gid, EXECUTOR_SERVICE_CONFIG_FILE_MODE),
    )
    for dest, stage, _, new, gid, mode in targets:
        _checked_stage(stage, dest.parent)
        _validate_file(stage, new, gid, mode)
    _checked_stage(staged.broker_backup, BROKER_FILE.parent)
    _checked_stage(staged.executor_backup, EXECUTOR_FILE.parent)
    _validate_file(staged.broker_backup, plan.broker_previous, plan.broker_gid, 0o600)
    _validate_file(staged.executor_backup, plan.executor_previous, plan.executor_gid, 0o600)
    attempted = False
    try:
        for dest, stage, _, _, _, _ in targets:
            attempted = True
            _replace(stage, dest)
        for dest, _, _, new, gid, mode in targets:
            _validate_file(dest, new, gid, mode)
    except Exception:
        if attempted:
            try:
                for dest, _, previous, _, gid, mode in targets:
                    _restore_one(dest, previous, gid, mode)
            except Exception:
                raise ConfigurationCutoverHold(
                    "configuration state requires manual recovery"
                ) from None
        raise ConfigurationCutoverHold("configuration activation rolled back") from None


def rollback_configurations(
    plan: ConfigurationPlan, staged: ConfigurationStaging,
) -> None:
    """Restore the exact reviewed old configs; retain private backup files."""
    source_cutover._require_root()
    source_cutover._require_quiesced()
    _validate_file(BROKER_FILE, plan.broker_target,
                   plan.broker_gid, BROKER_SERVICE_CONFIG_FILE_MODE)
    _validate_file(EXECUTOR_FILE, plan.executor_target,
                   plan.executor_gid, EXECUTOR_SERVICE_CONFIG_FILE_MODE)
    _checked_stage(staged.broker_backup, BROKER_FILE.parent)
    _checked_stage(staged.executor_backup, EXECUTOR_FILE.parent)
    _validate_file(staged.broker_backup, plan.broker_previous, plan.broker_gid, 0o600)
    _validate_file(staged.executor_backup, plan.executor_previous, plan.executor_gid, 0o600)
    try:
        _restore_one(BROKER_FILE, plan.broker_previous, plan.broker_gid,
                     BROKER_SERVICE_CONFIG_FILE_MODE)
        _restore_one(EXECUTOR_FILE, plan.executor_previous, plan.executor_gid,
                     EXECUTOR_SERVICE_CONFIG_FILE_MODE)
    except Exception:
        raise ConfigurationCutoverHold(
            "configuration state requires manual recovery"
        ) from None


# Section 4: exact interrupted-transaction recovery, never automatic startup.
def recover_interrupted_configurations(
    plan: ConfigurationPlan, staged: ConfigurationStaging,
) -> None:
    """Return a recognized old/new pair to the exact original configs.

    A process may terminate after replacing broker config but before replacing
    executor config. The two files are in different directories, therefore
    restoring a mixed state cannot rely on the both-new normal rollback path.
    Reject unknown bytes, mode, owner or backup drift before writing anything.
    """
    source_cutover._require_root()
    source_cutover._require_quiesced()
    _checked_stage(staged.broker_backup, BROKER_FILE.parent)
    _checked_stage(staged.executor_backup, EXECUTOR_FILE.parent)
    _validate_file(staged.broker_backup, plan.broker_previous,
                   plan.broker_gid, 0o600)
    _validate_file(staged.executor_backup, plan.executor_previous,
                   plan.executor_gid, 0o600)
    entries = (
        (BROKER_FILE, plan.broker_previous, plan.broker_target,
         plan.broker_gid, BROKER_SERVICE_CONFIG_FILE_MODE),
        (EXECUTOR_FILE, plan.executor_previous, plan.executor_target,
         plan.executor_gid, EXECUTOR_SERVICE_CONFIG_FILE_MODE),
    )
    states: list[bool] = []
    for path, old, new, group, mode in entries:
        try:
            _validate_file(path, old, group, mode)
            states.append(False)
        except ConfigurationCutoverHold:
            try:
                _validate_file(path, new, group, mode)
                states.append(True)
            except ConfigurationCutoverHold:
                raise ConfigurationCutoverHold(
                    "configuration state requires manual recovery"
                ) from None
    try:
        for changed, (path, old, _, group, mode) in zip(
            states, entries, strict=True,
        ):
            if changed:
                _restore_one(path, old, group, mode)
        for path, old, _, group, mode in entries:
            _validate_file(path, old, group, mode)
    except Exception:
        raise ConfigurationCutoverHold(
            "configuration state requires manual recovery"
        ) from None
