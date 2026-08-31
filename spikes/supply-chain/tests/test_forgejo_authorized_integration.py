"""File: spikes/supply-chain/tests/test_forgejo_authorized_integration.py

Purpose: Focused policy tests for Task 008C Forgejo Authorized Integration probes.

Related:
    - .github/workflows/task008-publish.yml
    - .github/workflows/task008-consume.yml
    - spikes/supply-chain/tests/test_supply_chain.py
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PUBLISH = (
    REPOSITORY_ROOT / ".github/workflows/task008-publish.yml"
).read_text(encoding="utf-8")
CONSUME = (
    REPOSITORY_ROOT / ".github/workflows/task008-consume.yml"
).read_text(encoding="utf-8")


def job(workflow: str, name: str) -> str:
    """Return one top-level workflow job as a static source-policy boundary."""

    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow has no {name!r} job")
    return match.group(0)


class ForgejoAuthorizedIntegrationPolicyTests(unittest.TestCase):
    """Keep Task 008C isolated from the historical Cloudsmith release paths."""

    def test_task008c_branch_can_activate_only_the_matching_permission_probe(self) -> None:
        """Verify the Task 008C branch activates only its matching probe."""

        cases = (
            (PUBLISH, "publisher-permissions.trigger"),
            (CONSUME, "consumer-permissions.trigger"),
        )
        for workflow, trigger in cases:
            with self.subTest(trigger=trigger):
                header = workflow.split("permissions: {}", 1)[0]
                gate = job(workflow, "gate")
                self.assertEqual(header.count("- spike/008c-forgejo-registry"), 1)
                self.assertIn("refs/heads/spike/008c-forgejo-registry", gate)
                self.assertIn(f'"spikes/supply-chain/control/{trigger}"', gate)
                self.assertIn(f"$'M\\tspikes/supply-chain/control/{trigger}'", gate)
                self.assertIn("mode=permission", gate)
                self.assertIn('"refs/heads/spike/008-supply-chain"', gate)

        publish_gate = job(PUBLISH, "gate")
        consume_gate = job(CONSUME, "gate")
        self.assertRegex(
            publish_gate,
            r'(?s)refs/heads/spike/008-supply-chain.*publish\.trigger.*mode=release',
        )
        self.assertRegex(
            consume_gate,
            r'(?s)refs/heads/spike/008-supply-chain.*consume\.trigger.*mode=release',
        )
        self.assertRegex(
            consume_gate,
            r'(?s)refs/heads/spike/008-supply-chain.*tamper-negative\.trigger.*mode=tamper',
        )
        self.assertRegex(
            consume_gate,
            r'(?s)refs/heads/spike/008-supply-chain.*rollback-retention\.trigger.*mode=rollback',
        )

    def test_exact_forgejo_endpoint_owner_and_audiences_are_bound(self) -> None:
        """Verify probes bind the expected Forgejo endpoint, owner, and audiences."""

        publisher = job(PUBLISH, "publisher-permission-probe")
        consumer = job(CONSUME, "consumer-permission-probe")
        for probe in (publisher, consumer):
            self.assertIn("FORGEJO_URL: https://registry-dev.omnilyzer.ai", probe)
            self.assertIn("FORGEJO_OWNER: omnilyzer", probe)
            self.assertIn("/api/packages/${FORGEJO_OWNER}/generic/", probe)
        self.assertIn(
            "FORGEJO_OIDC_AUDIENCE: u:2:316bec9a-53e4-4807-9557-7febdc979d0a",
            publisher,
        )
        self.assertIn(
            "FORGEJO_OIDC_AUDIENCE: u:3:b94ad035-e71f-46c5-b934-1bbde9692311",
            consumer,
        )

    def test_runner_oidc_is_job_scoped_masked_and_never_persisted(self) -> None:
        """Verify runner OIDC credentials stay scoped, masked, and ephemeral."""

        combined = PUBLISH + CONSUME
        self.assertEqual(combined.count("ACTIONS_ID_TOKEN_REQUEST_URL"), 2)
        self.assertEqual(combined.count("ACTIONS_ID_TOKEN_REQUEST_TOKEN"), 2)
        self.assertEqual(combined.count('echo "::add-mask::$jwt"'), 2)

        for workflow, name in (
            (PUBLISH, "publisher-permission-probe"),
            (CONSUME, "consumer-permission-probe"),
        ):
            probe = job(workflow, name)
            permissions = probe.split("    permissions:\n", 1)[1].split(
                "    runs-on:", 1
            )[0]
            self.assertEqual(
                permissions.strip().splitlines(),
                ["contents: read", "      id-token: write"],
            )
            self.assertIn('json.load(sys.stdin).get("value")', probe)
            self.assertIn('unset token_response', probe)
            forgejo_step = probe.split("- name: Prove Forgejo", 1)[1]
            self.assertEqual(
                forgejo_step.count("$jwt"),
                forgejo_step.count('Authorization: Bearer $jwt') + 1,
            )
            self.assertEqual(forgejo_step.count('echo "::add-mask::$jwt"'), 1)
            self.assertNotIn("actions/upload-artifact", forgejo_step)
            self.assertNotIn("set -x", forgejo_step)
            self.assertNotIn("$jwt\" >>", forgejo_step)

        build = job(PUBLISH, "build")
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_", build)
        self.assertNotIn("FORGEJO_", build)

    def test_no_static_forgejo_credential_or_cloudsmith_migration(self) -> None:
        """Verify probes use no static Forgejo credential or Cloudsmith migration."""

        combined = PUBLISH + CONSUME
        for prohibited in (
            "secrets.FORGEJO",
            "FORGEJO_PAT",
            "FORGEJO_PASSWORD",
            "FORGEJO_API_KEY",
        ):
            self.assertNotIn(prohibited, combined)

        publisher = job(PUBLISH, "publisher-permission-probe")
        consumer = job(CONSUME, "consumer-permission-probe")
        for probe in (publisher, consumer):
            forgejo_step = probe.split("- name: Prove Forgejo", 1)[1]
            self.assertNotIn("cloudsmith", forgejo_step.lower())
            self.assertIsNone(
                re.search(
                    r"(?im)^\s*(?:docker|cosign|npm|pip)(?:\s|$)",
                    forgejo_step,
                )
            )
        self.assertIn("Authenticate short-lived Cloudsmith publisher", publisher)
        self.assertIn("Authenticate short-lived read-only Cloudsmith consumer", consumer)
        self.assertGreater(PUBLISH.count("cloudsmith"), 10)
        self.assertGreater(CONSUME.count("cloudsmith"), 10)

    def test_publisher_create_read_and_delete_probe_fail_closed(self) -> None:
        """Verify the publisher create, read, and delete probe fails closed."""

        probe = job(PUBLISH, "publisher-permission-probe").split(
            "- name: Prove Forgejo", 1
        )[1]
        self.assertIn('package="task008c-authorized-integration-probe"', probe)
        self.assertIn('version="1.0.0"', probe)
        self.assertIn('filename="publisher.txt"', probe)
        self.assertIn("task008c-publisher-ok", probe)
        self.assertIn("--request PUT", probe)
        self.assertIn("--request DELETE", probe)
        self.assertIn('[[ "$delete_status" =~ ^2[0-9]{2}$ ]]', probe)
        self.assertIn('[[ "$post_delete_status" != "200" ]]', probe)
        self.assertIn("SECURITY FINDING", probe)
        self.assertIn("SECURITY FAILURE", probe)
        self.assertIn('if [[ "$delete_status" != "403" ]]', probe)
        self.assertIn("INCONCLUSIVE:", probe)
        self.assertIn("cmp --silent", probe)

    def test_consumer_authenticated_read_and_write_denial_fail_closed(self) -> None:
        """Verify the consumer read and denied-write probe fails closed."""

        probe = job(CONSUME, "consumer-permission-probe").split(
            "- name: Prove Forgejo", 1
        )[1]
        self.assertIn('package="task008c-authorized-integration-probe"', probe)
        self.assertIn('version="1.0.0"', probe)
        self.assertIn("task008c-publisher-ok", probe)
        self.assertIn("cmp --silent", probe)
        self.assertIn("--request PUT", probe)
        baseline_read = probe.index('--output "$baseline_download" "$baseline_url"')
        write_attempt = probe.index("--request PUT")
        self.assertLess(baseline_read, write_attempt)
        self.assertIn('if [[ "$write_status" =~ ^2[0-9]{2}$ ]]', probe)
        self.assertIn("SECURITY FAILURE", probe)
        self.assertIn('if [[ ! "$write_status" =~ ^(401|403)$ ]]', probe)
        self.assertIn(
            "Accept 401 only because this same JWT authenticated and read the private baseline immediately above.",
            probe,
        )
        self.assertIn("INCONCLUSIVE:", probe)
        self.assertIn('HTTP $write_status denied', probe)
        self.assertNotIn("HTTP 403 denied", probe)
        self.assertNotIn("--request DELETE", probe)


if __name__ == "__main__":
    unittest.main()
