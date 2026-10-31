"""File: deployment/tests/test_analytics_service_recovery.py

Purpose: Narrow state/error regressions, complementary to native systemd CI.
Related: deployment/analytics_service_recovery.py; accept_task014_analytics_recovery.py.
No live service, privileged path, credential, Docker or network operation.
"""
import unittest
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


if __name__ == '__main__':
    unittest.main()
