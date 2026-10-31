"""File: deployment/analytics_service_recovery.py

Purpose: Existing Task014 Analytics service lifecycle and stopped recovery.
Related: docs/operations/m05-14-task014-analytics-runtime-20261029.md;
         deployment/tests/accept_task014_analytics_recovery.py;
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service.

No import-time action, credentials, Docker mutation or deployment authority.
The owner entrypoint must independently verify the frozen installed generation.
Native CI uses only uniquely named disposable units on its isolated runner.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import selectors
import signal
import subprocess
import time
from typing import Callable


@dataclass(frozen=True)
class CommandResult:
    """A bounded service-manager result, including its actual diagnostics."""
    operation: str
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class ServiceFailure(Exception):
    """Safe public identity plus a retained bounded native command result."""
    def __init__(self, operation: str, result: CommandResult | None = None):
        super().__init__(operation)
        self.operation = operation
        self.result = result
        self.audit_failure = None


_UNIT = re.compile(r'(?:omnilyzer-deployment-(?:broker\.service|analytics-executor\.(?:service|socket))|omnilyzer-task014-ci-[0-9a-f]{12}-(?:broker\.service|analytics\.(?:service|socket)))\Z')
_PROPERTIES = frozenset(('ActiveState', 'MainPID', 'Job', 'NeedDaemonReload', 'ExecStart', 'ExecStartPost', 'ExecMainStatus', 'User', 'Group', 'FragmentPath', 'DropInPaths', 'NoNewPrivileges', 'PrivateTmp', 'PrivateDevices', 'ProtectHome', 'ProtectSystem', 'ReadWritePaths', 'TemporaryFileSystem', 'BindReadOnlyPaths', 'CapabilityBoundingSet', 'AmbientCapabilities', 'SupplementaryGroups', 'WorkingDirectory', 'RestrictAddressFamilies', 'RestrictNamespaces', 'SocketUser', 'SocketGroup', 'SocketMode'))


def systemctl(operation: str, *arguments: str, timeout: float = 30) -> CommandResult:
    """Run systemctl without a shell; cap each pipe while it is captured.

    The caller keeps native stderr in its root-private audit. It must not print
    arbitrary command output in a public deployment response.
    """
    if operation not in {'show', 'stop', 'start', 'reset-failed', 'daemon-reload'}:
        raise ValueError('unapproved_service_operation')
    if operation == 'daemon-reload':
        if arguments:
            raise ValueError('invalid_reload_arguments')
    elif not arguments or not _UNIT.fullmatch(arguments[0]):
        raise ValueError('unapproved_service_unit')
    elif operation == 'show':
        tail = arguments[1:]
        if not tail or len(tail) % 2 or any(tail[i] != '-p' or tail[i+1] not in _PROPERTIES for i in range(0, len(tail), 2)):
            raise ValueError('unapproved_service_properties')
    elif len(arguments) != 1:
        raise ValueError('invalid_service_arguments')
    argv = ('/usr/bin/systemctl', operation, *arguments)
    output = [bytearray(), bytearray()]
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': '/root'},
    )
    deadline = time.monotonic() + timeout
    primary = None
    result = None
    cleanup_errors = []
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ServiceFailure('service_command_timeout')
                for key, _ in selector.select(remaining):
                    try:
                        chunk = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    space = 32768 - len(output[key.data])
                    output[key.data].extend(chunk[:space])
                    if len(chunk) > space:
                        raise ServiceFailure('service_command_output_limit')
        while True:
            info = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if info is not None:
                break
            if time.monotonic() >= deadline:
                raise ServiceFailure('service_command_timeout')
            time.sleep(0.01)
        returncode = info.si_status if info.si_code == os.CLD_EXITED else -info.si_status
        result = CommandResult(
            operation, argv, returncode,
            output[0].decode('utf-8', errors='replace'),
            output[1].decode('utf-8', errors='replace'),
        )
    except BaseException as error:
        primary = error
    finally:
        # An unreaped leader pins the process group until cleanup completes.
        # Reap only after the group kill attempt; independently close both pipes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            cleanup_errors.append(type(error).__name__)
        try:
            process.wait(timeout=5)
        except BaseException as error:
            cleanup_errors.append(type(error).__name__)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except BaseException as error:
                cleanup_errors.append(type(error).__name__)
    if primary is not None:
        if isinstance(primary, ServiceFailure) and primary.result is None:
            primary.result = CommandResult(operation, argv, process.returncode,
                                           output[0].decode('utf-8', errors='replace'),
                                           output[1].decode('utf-8', errors='replace'))
        if cleanup_errors:
            primary.add_note('service_command_cleanup:' + ','.join(cleanup_errors))
        raise primary
    if cleanup_errors:
        raise ServiceFailure('service_command_cleanup', result)
    return result


class AnalyticsServiceControl:
    """Task-local controls; no public service or generic deployment framework."""
    def __init__(self, broker: str, listener: str, executor: str,
                 audit: Callable[[CommandResult], None] | None = None):
        units = (broker, listener, executor)
        actual = (
            'omnilyzer-deployment-broker.service',
            'omnilyzer-deployment-analytics-executor.socket',
            'omnilyzer-deployment-analytics-executor.service',
        )
        ci = r'omnilyzer-task014-ci-([0-9a-f]{12})-(broker\.service|analytics\.socket|analytics\.service)'
        matches = [re.fullmatch(ci, value) for value in units]
        if units != actual and not (
            all(matches) and len({m.group(1) for m in matches}) == 1
            and [m.group(2) for m in matches] ==
            ['broker.service', 'analytics.socket', 'analytics.service']
        ):
            raise ValueError('unapproved_analytics_units')
        self.broker, self.listener, self.executor = units
        self.units = units
        self.audit = audit

    def call(self, operation: str, *arguments: str) -> CommandResult:
        if operation != 'daemon-reload' and (not arguments or arguments[0] not in self.units):
            raise ValueError('unapproved_analytics_unit')
        try:
            result = systemctl(operation, *arguments)
        except ServiceFailure as error:
            if error.result is not None and self.audit is not None:
                try:
                    self.audit(error.result)
                except Exception as audit_error:
                    error.audit_failure = type(audit_error).__name__
                    error.add_note('private_audit_failed:' + error.audit_failure)
            raise
        if self.audit is not None:
            try:
                self.audit(result)
            except Exception as audit_error:
                error = ServiceFailure('command_' + operation if result.returncode else 'private_audit_failed', result)
                error.audit_failure = type(audit_error).__name__
                raise error from audit_error
        return result

    def properties(self, unit: str, *keys: str) -> dict[str, str]:
        if unit not in self.units:
            raise ValueError('unapproved_analytics_unit')
        argv = [unit]
        for key in keys:
            if not re.fullmatch(r'[A-Za-z]+', key):
                raise ValueError('invalid_property')
            argv += ['-p', key]
        result = self.call('show', *argv)
        if result.returncode:
            raise ServiceFailure('observe_' + unit, result)
        try:
            values = dict(row.split('=', 1) for row in result.stdout.splitlines())
        except ValueError:
            raise ServiceFailure('invalid_service_properties', result) from None
        # systemctl255 emits no row for a supported empty Exec* array, even
        # with --all. Only this explicitly supported optional array is empty.
        if 'ExecStartPost' in keys and 'ExecStartPost' not in values:
            values['ExecStartPost'] = ''
        if set(values) != set(keys):
            raise ServiceFailure('incomplete_service_properties', result)
        for key in ('ExecStart','ExecStartPost'):
            if key in values and values[key]:
                match = re.findall(r'argv\[\]=([^;]+?) ;', values[key])
                if len(match) != 1:
                    raise ServiceFailure('invalid_exec_start', result)
                values[key] = match[0]
        return values

    def require_stopped(self) -> None:
        """Safety is actual state/PID/job, not reset-failed's exit status."""
        failures = []
        for unit in self.units:
            try:
                values = self.properties(unit, 'ActiveState', 'MainPID', 'Job') if unit.endswith('.service') else self.properties(unit, 'ActiveState', 'Job')
                if values['ActiveState'] not in ('inactive', 'failed') or values.get('MainPID', '0') != '0' or values['Job']:
                    failures.append(unit)
            except Exception:
                failures.append(unit)
        if failures:
            raise ServiceFailure('control_plane_stop_unconfirmed')

    def stop_and_confirm(self) -> None:
        """Attempt every stop and preserve diagnostics; prove final state."""
        control = None
        for unit in self.units:
            try:
                self.call('stop', unit)
            except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
                if control is None:
                    control = error
            except Exception:
                # State verification below decides whether stopping succeeded.
                # A nonzero command is still retained by call() in the audit.
                pass
        self.require_stopped()
        if control is not None:
            raise control

    def clear_failed_counters(self) -> None:
        """Unloaded inactive units are not a failed stop or a failed reset."""
        for unit in (self.executor, self.listener):
            result = self.call('reset-failed', unit)
            if result.returncode:
                values = self.properties(unit, 'ActiveState', 'Job')
                if values['ActiveState'] != 'inactive' or values['Job']:
                    raise ServiceFailure('reset_failed_' + unit, result)

    def reload_and_verify(self, expected: dict[str, dict[str, str]]) -> None:
        """Replace loaded configuration BEFORE any socket/service activation."""
        self.require_stopped()
        result = self.call('daemon-reload')
        if result.returncode:
            raise ServiceFailure('daemon_reload', result)
        if set(expected) != set(self.units):
            raise ValueError('incomplete_analytics_runtime_authority')
        for unit, properties in expected.items():
            values = self.properties(unit, 'NeedDaemonReload', *properties)
            if values.pop('NeedDaemonReload') != 'no' or values != properties:
                raise ServiceFailure('effective_runtime_mismatch_' + unit)

    def start(self, unit: str) -> None:
        if unit not in self.units:
            raise ValueError('unapproved_analytics_unit')
        result = self.call('start', unit)
        if result.returncode:
            raise ServiceFailure('start_' + unit, result)
        if self.properties(unit, 'ActiveState')['ActiveState'] != 'active':
            raise ServiceFailure('not_active_' + unit, result)

    def require_stable_broker(self, expected: dict[str, str]) -> None:
        """Observe a stable real broker process/runtime after Type=exec starts."""
        deadline = time.monotonic() + 1.0
        pid = None
        while True:
            values = self.properties(self.broker, 'ActiveState', 'MainPID', 'Job')
            current = values['MainPID']
            if values['ActiveState'] != 'active' or not current.isdigit() or int(current) <= 0 or values['Job'] or (pid is not None and pid != current):
                raise ServiceFailure('broker_not_stable')
            pid = current
            if self.properties(self.broker, *expected) != expected:
                raise ServiceFailure('broker_runtime_changed')
            if time.monotonic() >= deadline:
                return
            time.sleep(0.1)


def resume_analytics(
    control: AnalyticsServiceControl, *, no_application: Callable[[], None],
    prepare: Callable[[], None], restore: Callable[[], None],
    expected: dict[str, dict[str, str]], probe: Callable[[], None],
    checkpoint: Callable[[str], None],
    restored_expected: dict[str, dict[str, str]] | None = None,
    broker_ready: Callable[[], None] | None = None,
) -> dict[str, object]:
    """Resume a separately verified coherent generation; recover stopped.

    No source publication or application operation is implemented here. The
    owner entrypoint supplies frozen authority, private audit and an exact
    workflow-only metadata update. It must verify all protected bytes first.
    """
    changed = False
    primary = None
    recovery_errors = []
    try:
        control.stop_and_confirm()
        checkpoint('control_plane_stopped')
        no_application()  # Close the active-broker preflight race.
        changed = True  # An interrupted atomic publication may have succeeded.
        prepare()
        checkpoint('metadata_published')
        control.reload_and_verify(expected)
        checkpoint('manager_reloaded_and_verified')
        control.clear_failed_counters()
        control.start(control.listener)
        probe()
        checkpoint('native_probe_passed')
        no_application()
        control.start(control.broker)
        control.require_stable_broker(expected[control.broker])
        if broker_ready is not None:
            broker_ready()
        checkpoint('ready_for_signed_task014')
        return {'status': 'ready_for_signed_task014', 'primary_error': None,
                'recovery_errors': [], 'application_acceptance': False}
    except BaseException as error:
        primary = error
        try:
            control.stop_and_confirm()
        except BaseException as stop_error:
            recovery_errors.append(type(stop_error).__name__ + ':' + str(stop_error))
        if not recovery_errors and changed:
            try:
                no_application()
                restore()
                control.reload_and_verify(restored_expected if restored_expected is not None else expected)
                checkpoint('metadata_restored_control_plane_stopped')
            except BaseException as restore_error:
                recovery_errors.append(type(restore_error).__name__ + ':' + str(restore_error))
        # Original failure is retained separately; cleanup never replaces it.
        outcome = {
            'status': 'stopped_recovered' if not recovery_errors else 'manual_recovery_required',
            'primary_error': type(primary).__name__ + ':' + str(primary),
            'recovery_errors': recovery_errors, 'application_acceptance': False,
        }
        if isinstance(primary, (KeyboardInterrupt, SystemExit, GeneratorExit)):
            raise primary
        return outcome
