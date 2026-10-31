"""File: deployment/tests/test_analytics_task014_resume.py

Purpose: Verify owner-entry authority, secret-safe public output and programs.
Related: deployment/analytics_task014_resume.py; native recovery acceptance.
No root/DEV action, secret access, Docker, database or service mutation.
"""
import ast
import io
import json
from contextlib import redirect_stdout
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

from deployment import analytics_task014_resume as owner


class OwnerAuthority(unittest.TestCase):
    def test_wrong_host_or_unprivileged_actor_stops_before_helper_access(self):
        for uid, host in [(1005, 'omnilyzerdev'), (0, 'different-host')]:
            with self.subTest(uid=uid, host=host), patch.object(owner.os, 'getuid', return_value=uid), patch.object(owner.os, 'geteuid', return_value=uid), patch.object(owner.socket, 'gethostname', return_value=host), patch.object(owner, 'load_helper') as load:
                with self.assertRaisesRegex(owner.ServiceFailure, 'owner_local_dev_root_required'):
                    owner.main(['--workflow-sha', 'a' * 40])
                load.assert_not_called()

    def test_unreviewed_or_noop_workflow_denied_before_helper_access(self):
        for target in ['main', '0' * 40, owner.CURRENT_WORKFLOW]:
            with self.subTest(target=target), patch.object(owner.os, 'getuid', return_value=0), patch.object(owner.os, 'geteuid', return_value=0), patch.object(owner.socket, 'gethostname', return_value='omnilyzerdev'), patch.object(owner, 'load_helper') as load:
                with self.assertRaisesRegex(owner.ServiceFailure, 'explicit_reviewed_workflow_required'):
                    owner.main(['--workflow-sha', target])
                load.assert_not_called()

    def test_public_result_never_repeats_arbitrary_exception_data(self):
        value = {'primary_error': 'ValueError:secret-example-value'}
        self.assertEqual(owner.public_error(value), 'operation_failed_see_private_audit')
        self.assertEqual(owner.public_error({'primary_error': 'ServiceFailure:daemon_reload'}), 'daemon_reload')

    def test_literal_probe_has_no_valid_deployment_or_database_request(self):
        for name in ('CONTEXT_CHILD', 'NEGATIVE_CLIENT'):
            compile(getattr(owner, name), name, 'exec')
        self.assertIn('GET', owner.CONTEXT_CHILD)
        self.assertIn('/_ping', owner.CONTEXT_CHILD)
        self.assertNotIn('POST', owner.CONTEXT_CHILD)
        constants = [n.value for n in ast.walk(ast.parse(owner.NEGATIVE_CLIENT)) if isinstance(n, ast.Constant)]
        self.assertIn(b'FAIL', constants)
        self.assertNotIn('BEGIN', owner.CONTEXT_CHILD)
        self.assertNotIn('JWT_SECRET', owner.CONTEXT_CHILD)

    def test_owner_runtime_properties_are_all_allowed_nonsecret_observations(self):
        from deployment.analytics_service_recovery import _PROPERTIES
        runtime = owner.expected_runtime({})
        for unit, properties in runtime.items():
            self.assertTrue(set(properties).issubset(_PROPERTIES))
        self.assertEqual(set(runtime), {owner.BROKER, owner.LISTENER, owner.EXECUTOR})

    def test_failed_postgres_identity_blocks_sql_and_keeps_network_independent(self):
        helper = SimpleNamespace(
            postgres_state=Mock(side_effect=RuntimeError('container_identity_failed')),
            postgres_network=Mock(return_value=True), postgres_count=Mock(),
            bounded_file=Mock(side_effect=RuntimeError('fixture_no_host_files')),
            service_state=Mock(), secret_directory_metadata=Mock(),
            secret_file_metadata=Mock(), command=Mock(return_value=b''), DOCKER=('fixture-docker',),
        )
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(owner.ServiceFailure, 'complete_preflight_failed'):
            owner.inspect_generation(helper, SimpleNamespace(require_stopped=lambda: None), 'a' * 40)
        helper.postgres_count.assert_not_called();helper.postgres_network.assert_called_once()
        checks = {row['name']: row for row in json.loads(output.getvalue())['checks']}
        for name in ('postgres_force_rls', 'postgres_restricted_roles'):
            self.assertEqual(checks[name]['status'], 'BLOCKED')
            self.assertEqual(checks[name]['dependency'], 'postgres_identity')

    def test_bundled_owner_keeps_the_reviewed_service_logic_unchanged(self):
        from deployment import analytics_service_recovery as services
        service_source = Path(services.__file__).read_bytes()
        owner_source = Path(owner.__file__).read_bytes()
        bundle = owner.build_owner_bundle(service_source, owner_source)
        self.assertIn(service_source, bundle)
        compile(bundle, 'owner_bundle', 'exec')
        before = next(n for n in ast.parse(service_source).body if isinstance(n, ast.FunctionDef) and n.name == 'resume_analytics')
        after = next(n for n in ast.parse(bundle).body if isinstance(n, ast.FunctionDef) and n.name == 'resume_analytics')
        self.assertEqual(ast.dump(before, include_attributes=False), ast.dump(after, include_attributes=False))


if __name__ == '__main__':
    unittest.main()
