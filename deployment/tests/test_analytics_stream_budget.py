"""File: deployment/tests/test_analytics_stream_budget.py

Purpose: Prove bounded Analytics completion, admission expiry and stop reserve.
Related: analytics_first_install.py, analytics_private_registry.py,
         analytics_unix_boundary.py and original short-lived credential tests.
Use existing real sealed-FD/command-contract fixtures; no server operation.
"""
import unittest
from unittest.mock import patch

from deployment import analytics_first_install as install
from deployment import analytics_private_registry as registry
from deployment.analytics_unix_boundary import AnalyticsUnixExecutorTransport, ANALYTICS_RESPONSE_TIMEOUT_MS
from deployment.private_registry_fd import MAX_LIFETIME_SECONDS
from deployment.private_registry_pull import PRIVATE_PULL_TIMEOUT_SECONDS, MIN_POST_PREFLIGHT_VALIDITY_SECONDS
from deployment.unix_transport import UnixExecutorTransport, RESPONSE_TIMEOUT_MS
from deployment.tests import test_analytics_first_install as first_fixture
from deployment.tests.test_analytics_first_install import (
    SyntheticRootlessDocker, EXPECTED, NOW,
)


class Clock:
    def __init__(self):self.value=0.0
    def __call__(self):return self.value


class TimedDocker(SyntheticRootlessDocker):
    def __init__(self,clock,*,network=0,pull=0,start=0):
        super().__init__();self.clock=clock;self.network=network;self.pull=pull;self.start=start;self.timeouts=[]
    def run(self,argv,*,cwd,environment,timeout):
        self.timeouts.append((argv,timeout))
        result=super().run(argv,cwd=cwd,environment=environment,timeout=timeout)
        if len(argv)>5 and argv[5]=='pull':self.clock.value+=self.pull
        elif 'network' in argv:self.clock.value+=self.network
        elif 'up' in argv:self.clock.value+=self.start
        return result


class StreamBudgetTests(unittest.TestCase):
    setUp=first_fixture.ExactFirstInstallTests.setUp
    deploy=first_fixture.ExactFirstInstallTests.deploy

    def timed(self,**delays):
        clock=Clock();self.runner=TimedDocker(clock,**delays)
        self.registry=registry.AnalyticsPrivateZotPullAdapter(self.runner,reviewed_installed_source=EXPECTED)
        self.operation=install.AnalyticsFirstInstallOperation(runner=self.runner,private_registry=self.registry,reviewed_installed_source=EXPECTED)
        object.__setattr__(self.operation,'_clock',clock)
        return clock

    def test_long_admitted_work_does_not_extend_the_input_credential(self):
        clock=self.timed(pull=350)
        with patch('deployment.analytics_private_registry.time.time',side_effect=lambda:NOW+int(clock.value)):
            self.assertIsNone(self.deploy())
        self.assertGreater(clock.value,270)
        self.assertEqual(self.runner.state,'running')
        self.assertEqual(MAX_LIFETIME_SECONDS,300)
        self.assertEqual(MIN_POST_PREFLIGHT_VALIDITY_SECONDS,225)

    def test_pull_is_clamped_to_the_remaining_whole_operation_budget(self):
        self.timed(network=100)
        self.deploy()
        pulls=[timeout for argv,timeout in self.runner.timeouts if len(argv)>5 and argv[5]=='pull']
        self.assertEqual(pulls,[470.0])

    def test_late_successful_pull_cannot_start_compose(self):
        self.timed(pull=571)
        with self.assertRaises(install.AnalyticsFirstInstallError):self.deploy()
        self.assertFalse(any('up' in argv for argv in self.runner.calls))
        self.assertFalse(self.runner.started)

    def test_late_successful_compose_is_stopped_using_the_cleanup_reserve(self):
        self.timed(start=571)
        with self.assertRaises(install.AnalyticsFirstInstallError):self.deploy()
        self.assertEqual(self.runner.state,'stopped')
        cleanup=[(argv,timeout) for argv,timeout in self.runner.timeouts if 'stop' in argv or '--status' in argv]
        self.assertEqual([timeout for argv,timeout in cleanup],[45.0,30.0])
        count=len(self.runner.calls)
        self.assertIsNone(self.operation.rollback_first_analytics(self.request))
        self.assertEqual(len(self.runner.calls),count)

    def test_final_health_success_after_deadline_is_not_reported_as_complete(self):
        clock=self.timed()
        def late_health(_instance,_container):clock.value=571.0
        with patch.object(install.AnalyticsFirstInstallOperation,'_private_ready',late_health):
            with self.assertRaises(install.AnalyticsFirstInstallError):self.deploy()
        self.assertEqual(self.runner.state,'stopped')
        self.assertIsNone(object.__getattribute__(self.operation,'_completed_request_hash'))

    def test_late_preflight_call_cannot_begin_the_pull(self):
        self.timed(network=571)
        with self.assertRaises(install.AnalyticsFirstInstallError):self.deploy()
        self.assertFalse(any(argv and argv[0]=='pull' for argv in self.runner.calls))
        self.assertFalse(self.runner.started)

    def test_invalid_pull_durations_fail_before_the_authenticated_command(self):
        from deployment.private_registry_pull import scoped_private_zot_request
        for timeout in (0.0,-1.0,501.0,float('nan'),float('inf'),True,1):
            self.runner.calls.clear()
            with self.subTest(timeout=repr(timeout)),scoped_private_zot_request(self.fd,self.request.canonical_bytes()):
                with self.assertRaises(registry.AnalyticsPrivateRegistryError):self.registry.pull_analytics(self.request,timeout=timeout)
            self.assertEqual(self.runner.calls,[])

    def test_response_budget_fits_the_existing_edge_and_preserves_canary(self):
        transport=AnalyticsUnixExecutorTransport(expected_executor_uid=991,expected_executor_gid=991,expected_socket_group_gid=993,reviewed_installed_source=EXPECTED)
        canary=UnixExecutorTransport(expected_executor_uid=991,expected_executor_gid=991,expected_socket_group_gid=993)
        self.assertEqual(object.__getattribute__(transport,'_configuration')[4],720_000)
        self.assertEqual(object.__getattribute__(canary,'_configuration')[4],600_000)
        self.assertEqual(RESPONSE_TIMEOUT_MS,600_000)
        self.assertEqual(PRIVATE_PULL_TIMEOUT_SECONDS,180.0)
        self.assertLess(install.ANALYTICS_OPERATION_TIMEOUT_SECONDS+75+30+15,ANALYTICS_RESPONSE_TIMEOUT_MS/1000)
        self.assertLess(117+ANALYTICS_RESPONSE_TIMEOUT_MS/1000,900)


if __name__=='__main__':unittest.main()
