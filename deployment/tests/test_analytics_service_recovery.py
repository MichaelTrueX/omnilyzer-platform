"""File: deployment/tests/test_analytics_service_recovery.py

Purpose: Narrow state/error regressions, complementary to native systemd CI.
Related: deployment/analytics_service_recovery.py; accept_task014_analytics_recovery.py.
No live service, privileged path, credential, Docker or network operation.
"""
import unittest
import ast
import runpy
import os
from pathlib import Path
import subprocess
import time
from unittest.mock import patch
from deployment import analytics_service_recovery as recovery


class StateRegressions(unittest.TestCase):
    def setUp(self):
        self.control = recovery.AnalyticsServiceControl(
            'omnilyzer-deployment-broker.service',
            'omnilyzer-deployment-analytics-executor.socket',
            'omnilyzer-deployment-analytics-executor.service',
        )

    def test_stop_error_cannot_override_confirmed_inactive_state(self):
        def properties(unit, *keys):
            return {key: {'ActiveState': 'inactive', 'MainPID': '0', 'Job': ''}[key] for key in keys}
        with patch.object(self.control, 'call', side_effect=recovery.ServiceFailure('native_stop_error')), patch.object(self.control, 'properties', side_effect=properties):
            self.control.stop_and_confirm()

    def test_running_process_is_not_a_stopped_control_plane(self):
        def properties(unit, *keys):
            return {key: {'ActiveState': 'inactive', 'MainPID': '91', 'Job': ''}[key] for key in keys}
        with patch.object(self.control, 'call'), patch.object(self.control, 'properties', side_effect=properties):
            with self.assertRaisesRegex(recovery.ServiceFailure, 'control_plane_stop_unconfirmed'):
                self.control.stop_and_confirm()

    def test_reset_error_on_inactive_unloaded_unit_is_not_a_stop_failure(self):
        result = recovery.CommandResult('reset-failed', (), 1, '', 'Unit not loaded')
        with patch.object(self.control, 'call', return_value=result), patch.object(self.control, 'properties', return_value={'ActiveState': 'inactive', 'Job': ''}):
            self.control.clear_failed_counters()

    def test_reset_error_while_unit_remains_failed_is_not_ignored(self):
        result = recovery.CommandResult('reset-failed', (), 1, '', 'Denied')
        with patch.object(self.control, 'call', return_value=result), patch.object(self.control, 'properties', return_value={'ActiveState': 'failed', 'Job': ''}):
            with self.assertRaises(recovery.ServiceFailure) as caught:
                self.control.clear_failed_counters()
        self.assertIs(caught.exception.result, result)

    def test_post_stop_application_guard_precedes_metadata_publication(self):
        def guard():raise recovery.ServiceFailure('application_present')
        with patch.object(self.control, 'stop_and_confirm'), patch.object(self.control, 'reload_and_verify'), patch.object(self.control, 'start') as start, patch('builtins.print'):
            prepare = unittest.mock.Mock()
            result = recovery.resume_analytics(self.control, no_application=guard, prepare=prepare, restore=unittest.mock.Mock(), expected={}, probe=unittest.mock.Mock(), checkpoint=lambda phase: None)
        prepare.assert_not_called();start.assert_not_called()
        self.assertIn('application_present', result['primary_error'])

    def test_only_supported_empty_exec_array_is_normalized(self):
        result = recovery.CommandResult('show', (), 0, 'User=nobody\n', '')
        with patch.object(self.control, 'call', return_value=result):
            self.assertEqual(self.control.properties(self.control.broker, 'User', 'ExecStartPost'), {'User': 'nobody', 'ExecStartPost': ''})
            with self.assertRaisesRegex(recovery.ServiceFailure, 'incomplete_service_properties'):
                self.control.properties(self.control.broker, 'User', 'WorkingDirectory')

    def test_unit_argument_rejected_before_process_creation(self):
        with patch.object(recovery.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError):self.control.call('stop', 'unrelated.service')
            with self.assertRaises(ValueError):recovery.systemctl('stop', 'unrelated.service')
            with self.assertRaises(ValueError):recovery.systemctl('show', self.control.broker, '-p', 'Environment')
            with self.assertRaises(ValueError):recovery.systemctl('daemon-reload', self.control.broker)
        spawn.assert_not_called()

    def test_audit_write_failure_preserves_timeout_and_native_partial_result(self):
        result = recovery.CommandResult('start', (), -9, 'partial', 'native diagnostic')
        original = recovery.ServiceFailure('service_command_timeout', result)
        self.control.audit = lambda result: (_ for _ in ()).throw(OSError('disk_full'))
        with patch.object(recovery, 'systemctl', side_effect=original):
            with self.assertRaises(recovery.ServiceFailure) as caught:
                self.control.call('start', self.control.broker)
        self.assertIs(caught.exception, original)
        self.assertIs(caught.exception.result, result)
        self.assertEqual(caught.exception.audit_failure, 'OSError')

    def test_nonzero_command_survives_audit_write_failure(self):
        result = recovery.CommandResult('start', (), 1, '', 'native start failure')
        self.control.audit = lambda result: (_ for _ in ()).throw(OSError('disk_full'))
        with patch.object(recovery, 'systemctl', return_value=result):
            with self.assertRaises(recovery.ServiceFailure) as caught:
                self.control.call('start', self.control.broker)
        self.assertEqual(caught.exception.operation, 'command_start')
        self.assertIs(caught.exception.result, result)

    def test_native_fixture_imports_and_queries_only_supported_properties(self):
        path = Path(__file__).with_name('accept_task014_analytics_recovery.py')
        namespace = runpy.run_path(str(path), run_name='native_fixture_import_check')
        self.assertIs(namespace['AnalyticsServiceControl'], recovery.AnalyticsServiceControl)
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='properties':
                for value in node.args[1:]:
                    if isinstance(value,ast.Constant) and isinstance(value.value,str):
                        self.assertIn(value.value,recovery._PROPERTIES)

    def test_native_completion_property_is_explicitly_allowed(self):
        self.assertIn('ExecMainStatus', recovery._PROPERTIES)


class RealProcessCapture(unittest.TestCase):
    """Real harmless child processes, no systemctl or privileged operation."""
    def run_script(self, script, timeout):
        original = subprocess.Popen
        processes = []
        def spawn(argv, **kwargs):
            process = original(['/usr/bin/python3', '-I', '-u', '-c', script], **kwargs)
            processes.append(process)
            return process
        with patch.object(recovery.subprocess, 'Popen', side_effect=spawn):
            try:
                result = recovery.systemctl('show', 'omnilyzer-deployment-broker.service', '-p', 'ActiveState', timeout=timeout)
                return result, None, processes[0]
            except recovery.ServiceFailure as error:
                return error.result, error, processes[0]

    def test_timeout_preserves_both_partial_pipes_and_reaps_child(self):
        result, error, process = self.run_script('import os,time;os.write(1,b"PARTIAL_STDOUT");os.write(2,b"PARTIAL_STDERR");time.sleep(30)', 0.5)
        self.assertEqual(error.operation, 'service_command_timeout')
        self.assertEqual(result.stdout, 'PARTIAL_STDOUT');self.assertEqual(result.stderr, 'PARTIAL_STDERR')
        self.assertIsInstance(result.returncode, int)
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_output_limit_retains_only_bounded_output(self):
        result, error, process = self.run_script('import os;os.write(1,b"X"*1000000)', 2)
        self.assertEqual(error.operation, 'service_command_output_limit')
        self.assertEqual(len(result.stdout), 32768)
        self.assertIsNotNone(process.returncode)

    def test_inherited_pipe_cannot_keep_descendant_running_after_timeout(self):
        script = 'import subprocess,sys;child=subprocess.Popen(["/usr/bin/python3","-I","-c","import time;time.sleep(30)"]);print(child.pid,flush=True)'
        result, error, process = self.run_script(script, 0.5)
        self.assertEqual(error.operation, 'service_command_timeout')
        pid = int(result.stdout.strip())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                state = Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')', 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == 'Z':break
            time.sleep(0.01)
        else:self.fail('owned_descendant_still_running')
        self.assertIsNotNone(process.returncode)


if __name__ == '__main__':
    unittest.main()
