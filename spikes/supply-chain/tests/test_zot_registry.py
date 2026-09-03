"""Local policy, fixture, and final evidence tests for Task 008D zot."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[3]
SPIKE = ROOT / "spikes/supply-chain"
SCRIPTS = SPIKE / "scripts"
ZOT = SPIKE / "zot"
PUBLISH = ROOT / ".github/workflows/task008-zot-publish.yml"
CONSUME = ROOT / ".github/workflows/task008-zot-consume.yml"
ADR = ROOT / "docs/adr/0010-forgejo-and-zot-package-registries.md"
TECHNOLOGY_DECISIONS = ROOT / "docs/architecture/technology-decisions.md"
PUBLISH_ID = "MichaelTrueX/omnilyzer-platform/.github/workflows/task008-zot-publish.yml@refs/heads/spike/008d-zot-registry"
CONSUME_ID = "MichaelTrueX/omnilyzer-platform/.github/workflows/task008-zot-consume.yml@refs/heads/spike/008d-zot-registry"
ZERO_SHA = "0" * 40

spec = importlib.util.spec_from_file_location("zot_oci_common", SCRIPTS / "zot_oci_common.py")
if spec is None or spec.loader is None:
    raise RuntimeError("unable to import zot OCI support")
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def job(text: str, name: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z][a-z0-9-]*:\n|\Z)", text)
    if match is None:
        raise AssertionError(f"missing job {name}")
    return match.group(0)


def classified(statuses: list[tuple[str, str]], trigger: str) -> str:
    return "active" if statuses == [("M", trigger)] else "none"


def gate_lifecycle(before: str, after: str, statuses: list[tuple[str, str]],
                   trigger: str, commits_exist: bool = True) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", before) is None or re.fullmatch(
        r"[0-9a-f]{40}", after
    ) is None:
        raise ValueError("malformed event SHA")
    if before == ZERO_SHA:
        return "none"
    if not commits_exist:
        raise ValueError("push range commit is unavailable")
    return classified(statuses, trigger)


class ZotConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = json.loads((ZOT / "config.example.json").read_text())
        cls.publish = PUBLISH.read_text()
        cls.consume = CONSUME.read_text()

    def test_workflows_and_safe_initial_triggers_exist(self) -> None:
        self.assertTrue(PUBLISH.is_file())
        self.assertTrue(CONSUME.is_file())
        self.assertEqual((SPIKE / "control/zot-publish.trigger").read_text(),
                         "task008d-zot-publish-probe-v2\n")
        self.assertEqual((SPIKE / "control/zot-consume.trigger").read_text(),
                         '{"state":"ready","tag":"task008d-33814874276-1",'
                         '"manifest_digest":"sha256:869121fdf10de171eff2f2622fa4190939573abc1e5bb24e7502b8757d4f6059",'
                         '"config_digest":"sha256:8ac6c44b9181a6d92469b5b701417f9ab13c5f0b8c462ffd68a7f4d098e9614d",'
                         '"layer_digest":"sha256:6747a1b2afcb45cb4e398e8f08158b305575e98f78fefee20c14e415dccfc89b"}\n')

    def test_only_exact_trigger_modification_activates(self) -> None:
        for trigger in ("spikes/supply-chain/control/zot-publish.trigger",
                        "spikes/supply-chain/control/zot-consume.trigger"):
            self.assertEqual(classified([("M", trigger)], trigger), "active")
            for changes in ([('A', trigger)], [('D', trigger)], [('R100', trigger)],
                            [('M', trigger), ('M', 'README.md')], [('M', 'README.md')]):
                self.assertEqual(classified(changes, trigger), "none")

    def test_initial_branch_creation_always_emits_none(self) -> None:
        after = "a" * 40
        cases = ((self.publish, "spikes/supply-chain/control/zot-publish.trigger"),
                 (self.consume, "spikes/supply-chain/control/zot-consume.trigger"))
        for text, trigger in cases:
            with self.subTest(trigger=trigger):
                self.assertEqual(gate_lifecycle(ZERO_SHA, after, [("M", trigger)], trigger), "none")
                gate = job(text, "gate")
                zero_check = gate.index('if [[ "$BEFORE_SHA" == 0000000000000000000000000000000000000000 ]]')
                self.assertGreater(gate.index("printf 'mode=none\\n'", zero_check), zero_check)
                self.assertGreater(gate.index("exit 0", zero_check), zero_check)
                self.assertGreater(gate.index("git cat-file", zero_check), gate.index("exit 0", zero_check))

    def test_initial_branch_creation_cannot_reach_privileged_jobs(self) -> None:
        cases = ((self.publish, "publish", "publisher-probe"),
                 (self.consume, "consume", "consumer-probe"))
        for text, mode, probe in cases:
            with self.subTest(mode=mode):
                self.assertIn(f"needs.gate.outputs.mode == '{mode}'", job(text, "fixture-build"))
                privileged = job(text, probe)
                self.assertIn(f"needs.gate.outputs.mode == '{mode}'", privileged)
                self.assertIn("id-token: write", privileged)
                self.assertNotEqual("none", mode)

    def test_malformed_or_missing_ordinary_push_range_fails_closed(self) -> None:
        for trigger in ("spikes/supply-chain/control/zot-publish.trigger",
                        "spikes/supply-chain/control/zot-consume.trigger"):
            with self.subTest(trigger=trigger):
                with self.assertRaises(ValueError):
                    gate_lifecycle("not-a-sha", "a" * 40, [("M", trigger)], trigger)
                with self.assertRaises(ValueError):
                    gate_lifecycle("b" * 40, "not-a-sha", [("M", trigger)], trigger)
                with self.assertRaises(ValueError):
                    gate_lifecycle("b" * 40, "a" * 40, [("M", trigger)], trigger,
                                   commits_exist=False)

    def test_workflow_gates_are_branch_and_range_bound(self) -> None:
        for text, trigger in ((self.publish, "zot-publish.trigger"),
                              (self.consume, "zot-consume.trigger")):
            gate = job(text, "gate")
            self.assertIn("refs/heads/spike/008d-zot-registry", gate)
            self.assertIn("github.event.before", gate)
            self.assertIn("github.sha", gate)
            self.assertIn("--no-renames", gate)
            self.assertIn("$'M\\tspikes/supply-chain/control/" + trigger + "'", gate)
            self.assertNotIn("$'A\\tspikes/supply-chain/control/" + trigger + "'", gate)

    def test_gate_and_build_have_no_oidc_authority(self) -> None:
        for text in (self.publish, self.consume):
            self.assertNotIn("id-token", job(text, "gate"))
            self.assertNotIn("id-token", job(text, "fixture-build"))
            self.assertIn("contents: read", job(text, "gate"))

    def test_id_token_is_only_on_probe_jobs(self) -> None:
        self.assertEqual(self.publish.count("id-token: write"), 1)
        self.assertEqual(self.consume.count("id-token: write"), 1)
        self.assertIn("id-token: write", job(self.publish, "publisher-probe"))
        self.assertIn("id-token: write", job(self.consume, "consumer-probe"))

    def test_checkout_and_third_party_actions_are_pinned(self) -> None:
        for text in (self.publish, self.consume):
            self.assertNotRegex(text, r"uses:\s+[^\s@]+@(?![0-9a-f]{40}(?:\s|$))")
            self.assertNotIn("persist-credentials: true", text)

    def test_no_long_lived_registry_credentials(self) -> None:
        combined = (self.publish + self.consume + json.dumps(self.config)).lower()
        for forbidden in ("password:", "registry_password", "api_key", "htpasswd", "github secret"):
            self.assertNotIn(forbidden, combined)
        self.assertNotIn("secrets.", combined)

    def test_exact_oidc_issuer_audience_and_claim_validation(self) -> None:
        oidc = self.config["http"]["auth"]["bearer"]["oidc"][0]
        self.assertEqual(oidc["issuer"], "https://token.actions.githubusercontent.com")
        self.assertEqual(oidc["audiences"], ["https://oci-dev.omnilyzer.ai"])
        mapping = json.dumps(oidc["claimMapping"])
        self.assertIn("vars.owner == 'MichaelTrueX'", mapping)
        self.assertIn("vars.repository == 'MichaelTrueX/omnilyzer-platform'", mapping)
        self.assertIn("claims.workflow_ref", mapping)
        self.assertNotIn("claims.job_workflow_ref", mapping)
        self.assertNotIn("*", mapping)

    def test_exact_workflow_identities_are_mapped(self) -> None:
        mapping = json.dumps(self.config["http"]["auth"]["bearer"]["oidc"][0]["claimMapping"])
        self.assertIn(PUBLISH_ID, mapping)
        self.assertIn(CONSUME_ID, mapping)
        self.assertIn('"username": "claims.workflow_ref"', mapping)

    def test_acl_users_exactly_match_workflow_ref_identities(self) -> None:
        policies = self.config["http"]["accessControl"]["repositories"][common.REPOSITORY]["policies"]
        self.assertEqual([policy["users"] for policy in policies], [[PUBLISH_ID], [CONSUME_ID]])

    def test_no_job_workflow_ref_dependency_remains(self) -> None:
        executable = json.dumps(self.config) + self.publish + self.consume
        executable += "".join(path.read_text() for path in SCRIPTS.glob("zot_*.py"))
        self.assertNotIn("job_workflow_ref", executable)

    def test_publisher_actions_are_exactly_read_create(self) -> None:
        policies = self.config["http"]["accessControl"]["repositories"][common.REPOSITORY]["policies"]
        publisher = next(policy for policy in policies if PUBLISH_ID in policy["users"])
        self.assertEqual(publisher["actions"], ["read", "create"])
        self.assertNotIn("update", publisher["actions"])
        self.assertNotIn("delete", publisher["actions"])

    def test_consumer_is_exactly_read_only(self) -> None:
        policies = self.config["http"]["accessControl"]["repositories"][common.REPOSITORY]["policies"]
        consumer = next(policy for policy in policies if CONSUME_ID in policy["users"])
        self.assertEqual(consumer["actions"], ["read"])
        script = (SCRIPTS / "zot_consumer_probe.py").read_text()
        for method in ('"PUT"', '"POST"', '"DELETE"', "ensure_blob"):
            self.assertNotIn(method, script)

    def test_unknown_and_anonymous_authority_is_empty(self) -> None:
        repositories = self.config["http"]["accessControl"]["repositories"]
        for policy in (repositories["**"], repositories[common.REPOSITORY]):
            self.assertEqual(policy["defaultPolicy"], [])
            self.assertEqual(policy["anonymousPolicy"], [])

    def test_gc_is_explicitly_disabled_and_storage_is_persistent(self) -> None:
        self.assertIs(self.config["storage"]["gc"], False)
        self.assertEqual(self.config["storage"]["rootDirectory"], "/var/lib/zot")
        self.assertNotIn("retention", self.config["storage"])

    def test_backend_is_loopback_only(self) -> None:
        self.assertEqual(self.config["http"]["address"], "127.0.0.1")
        self.assertEqual(self.config["http"]["port"], "5000")
        self.assertEqual(self.config["http"]["externalUrl"], "https://oci-dev.omnilyzer.ai")
        self.assertIn("proxy_pass http://127.0.0.1:5000", (ZOT / "nginx.example.conf").read_text())

    def test_bearer_realm_is_absolute_same_origin_zot_token_service(self) -> None:
        http = self.config["http"]
        bearer = http["auth"]["bearer"]
        realm = bearer["realm"]
        self.assertEqual(realm, "https://oci-dev.omnilyzer.ai/zot/auth/token")
        self.assertNotEqual(realm, "zot")
        parsed_realm = urlparse(realm)
        parsed_external = urlparse(http["externalUrl"])
        self.assertEqual(parsed_realm.scheme, "https")
        self.assertEqual(parsed_realm.netloc, parsed_external.netloc)
        self.assertEqual(parsed_realm.path, "/zot/auth/token")
        self.assertEqual(parsed_realm.query, "")
        self.assertEqual(parsed_realm.fragment, "")
        self.assertEqual(bearer["service"], "oci-dev.omnilyzer.ai")
        self.assertEqual(bearer["oidc"][0]["issuer"],
                         "https://token.actions.githubusercontent.com")
        self.assertEqual(bearer["oidc"][0]["audiences"],
                         ["https://oci-dev.omnilyzer.ai"])

    def test_nginx_does_not_implement_immutability(self) -> None:
        nginx = (ZOT / "nginx.example.conf").read_text()
        self.assertNotIn("limit_except", nginx)
        self.assertNotIn("request_method", nginx)
        self.assertNotIn("DELETE", nginx)
        self.assertIn("proxy_request_buffering off", nginx)

    def test_service_is_unprivileged_and_write_paths_are_explicit(self) -> None:
        unit = (ZOT / "zot.service.example").read_text()
        self.assertIn("User=zot", unit)
        self.assertIn("Group=zot", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ReadWritePaths=/var/lib/zot /var/log/zot", unit)

    def test_version_and_reviewed_digests_are_pinned(self) -> None:
        install = (ZOT / "install-zot.sh").read_text()
        readme = (ZOT / "README.md").read_text()
        self.assertIn("v2.1.20", install)
        self.assertIn("a9fe260d8259084d884f2135f33a6f63ce898665e2c1115b76c871a196df6653", install)
        self.assertIn("sha256:95a837a0afacf5b7edc0c92493f04beee6891989b8d2fd50a00cf65a1e6d4fd5", readme)
        self.assertLess(install.index("checksums.sha256.txt\" | sha256sum --check"),
                        install.index("zot-linux-amd64\""))


class ZotProbeTests(unittest.TestCase):
    def test_fixture_is_deterministic_and_variants_are_distinct(self) -> None:
        tag = "task008d-12345-1"
        with tempfile.TemporaryDirectory() as tmp:
            first = common.build_handoff(Path(tmp) / "one", "a" * 40, tag)
            second = common.build_handoff(Path(tmp) / "two", "a" * 40, tag)
            self.assertEqual(first, second)
            self.assertNotEqual(first["baseline"]["manifest_digest"],
                                first["replacement"]["manifest_digest"])
            self.assertEqual(first["tag"], first["version"])

    def test_fixture_manifests_bind_exact_config_and_layer_digests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "handoff"
            record = common.build_handoff(root, "b" * 40, "task008d-22-3")
            validated = common.validate_handoff(root, "b" * 40, "task008d-22-3")
            for name in ("baseline", "replacement"):
                manifest = json.loads(validated[name]["bytes"]["manifest"])
                self.assertEqual(manifest["config"]["digest"], record[name]["config_digest"])
                self.assertEqual(manifest["layers"][0]["digest"], record[name]["layer_digest"])

    def test_direct_bearer_and_no_redirect_client_exist(self) -> None:
        source = (SCRIPTS / "zot_oci_common.py").read_text()
        self.assertIn('"Authorization": f"Bearer {self.token}"', source)
        self.assertIn("class NoRedirect", source)
        self.assertIn("build_opener(NoRedirect())", source)

    def test_upload_location_validation_rejects_unsafe_values(self) -> None:
        client = object.__new__(common.RegistryClient)
        client.base = "https://oci-dev.omnilyzer.ai"
        client.origin = ("https", "oci-dev.omnilyzer.ai", 443)
        good = "/v2/omnilyzer/task008d-supply-chain-spike/blobs/uploads/uuid"
        result = client.validate_upload_location(good, common.REPOSITORY, "sha256:" + "a" * 64)
        self.assertTrue(result.endswith("digest=sha256%3A" + "a" * 64))
        for bad in ("http://oci-dev.omnilyzer.ai/v2/x/blobs/uploads/u",
                    "https://evil.example/v2/omnilyzer/task008d-supply-chain-spike/blobs/uploads/u",
                    "https://user@oci-dev.omnilyzer.ai/v2/omnilyzer/task008d-supply-chain-spike/blobs/uploads/u",
                    good + "#fragment", good + "/../escape", good + "%00", good.replace("/v2/", "/wrong/")):
            with self.subTest(location=bad), self.assertRaises(RuntimeError):
                client.validate_upload_location(bad, common.REPOSITORY, "sha256:" + "a" * 64)

    def test_publisher_requires_exact_baseline_201_and_denial_403(self) -> None:
        source = (SCRIPTS / "zot_publisher_probe.py").read_text()
        self.assertIn("expected={201}", source)
        self.assertIn("if replace_status == 403", source)
        self.assertIn("elif replace_status == 201", source)
        self.assertIn('tag_result = "FAIL"', source)
        self.assertIn("delete_status == 403", source)

    def test_digest_and_blob_verification_remain_mandatory_after_denials(self) -> None:
        source = (SCRIPTS / "zot_publisher_probe.py").read_text()
        replacement = source.index("Same-tag replacement HTTP")
        self.assertGreater(source.index("verify_baseline(client, record, by_tag=False)", replacement), replacement)
        self.assertGreater(source.rindex("verify_baseline(client, record, by_tag=False)"),
                           source.index('client.request(\n            "DELETE"'))

    def test_docker_uses_oidc_stdin_pull_only_and_logout_trap(self) -> None:
        for text in (PUBLISH.read_text(), CONSUME.read_text()):
            self.assertIn("docker login oci-dev.omnilyzer.ai --username oidc --password-stdin", text)
            self.assertIn("docker pull", text)
            self.assertIn("docker logout", text)
            self.assertIn("trap cleanup EXIT", text)
            self.assertNotIn("docker run", text)

    def test_oidc_occurs_only_after_handoff_verification(self) -> None:
        for text in (PUBLISH.read_text(), CONSUME.read_text()):
            self.assertLess(text.index("Verify complete handoff") if "Verify complete handoff" in text else text.index("Verify handoff and recorded"),
                            text.index("Request short-lived") if "Request short-lived" in text else text.index("Request independent"))

    def test_tokens_are_masked_file_protected_and_removed(self) -> None:
        for text in (PUBLISH.read_text(), CONSUME.read_text()):
            self.assertIn("::add-mask::", text)
            self.assertIn("chmod 0600", text)
            self.assertIn("token_path.unlink()", (SCRIPTS / "zot_oci_common.py").read_text())
            self.assertNotIn("print(token", text)

    def test_error_diagnostics_are_bounded_and_token_redacted(self) -> None:
        source = (SCRIPTS / "zot_oci_common.py").read_text()
        self.assertIn("ERROR_LIMIT = 512", source)
        self.assertIn('replace(self.token, "[REDACTED]")', source)

    def test_final_live_results_are_documented(self) -> None:
        readme = (SPIKE / "README.md").read_text()
        self.assertIn("TASK 008D — PASS", readme)
        self.assertIn("Publisher run `33814063124`", readme)
        self.assertIn("Publisher v2 run `33814874276`", readme)
        self.assertIn("Consumer run `33815051427`", readme)
        self.assertIn("sha256:869121fdf10de171eff2f2622fa4190939573abc1e5bb24e7502b8757d4f6059", readme)
        self.assertIn("| Standard Docker interoperability | PASS |", readme)
        self.assertIn("| Restart persistence | PASS |", readme)
        self.assertIn("| Independent read-only retrieval | PASS |", readme)
        self.assertIn("| Exact-digest rollback readiness | PASS |", readme)
        self.assertIn("does not prove indefinite retention", readme)

    def test_split_registry_decision_preserves_failed_and_cost_evidence(self) -> None:
        self.assertTrue(ADR.is_file())
        adr = ADR.read_text()
        self.assertIn("- Status: Proposed", adr)
        self.assertIn("Forgejo behind protected Nginx ingress", adr)
        self.assertIn("Generic / PyPI / npm", adr)
        self.assertRegex(adr, r"(?s)zot.*OCI")
        self.assertIn("short-lived OIDC workload identity", adr)
        self.assertIn("no long-lived registry password", adr)
        self.assertIn("previously retrievable manifest digest returned `MANIFEST_UNKNOWN`", adr)
        self.assertIn("recurring commercial cost is unacceptable", adr)
        self.assertIn("garbage collection remains disabled for the Task 008D evidence", adr)
        self.assertIn("not indefinite retention", adr)

    def test_architecture_matrix_records_proposed_split_without_acceptance(self) -> None:
        decisions = TECHNOLOGY_DECISIONS.read_text()
        rows = [line for line in decisions.splitlines()
                if line.startswith("| Package registry / trusted publishing |")]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIn("Forgejo + protected Nginx ingress for Generic, PyPI, and npm", row)
        self.assertIn("zot for OCI", row)
        self.assertIn("ADR 0010, Proposed", row)
        self.assertIn("| TO VALIDATE |", row)
        self.assertNotIn("ACCEPTED DIRECTION", row)
        self.assertNotIn("provider TBD", row)
        self.assertIn("Forgejo Generic, PyPI, and npm", row)
        self.assertIn("same-tag replacement was accepted", row)
        self.assertIn("original digest became unavailable", row)
        self.assertIn("Task 008D passed zot OCI", row)
        self.assertIn("GitHub OIDC publisher/consumer identities", row)
        self.assertIn("Docker interoperability", row)
        self.assertIn("restart persistence", row)
        self.assertIn("exact-digest rollback readiness", row)
        self.assertIn("Cloudsmith was technically validated", row)
        self.assertIn("recurring commercial cost is unacceptable", row)
        self.assertIn("does not prove indefinite retention", row)
        self.assertIn("ADR 0010 review and acceptance", row)

    def test_adr_date_status_and_supply_chain_related_link(self) -> None:
        adr = ADR.read_text()
        self.assertIn("- Status: Proposed", adr)
        self.assertIn("- Date: 2026-09-04", adr)
        related = (SPIKE / "README.md").read_text().split("-->", 1)[0]
        self.assertIn("docs/adr/0005-versioned-platform-packaging-and-distribution.md", related)
        self.assertIn("docs/adr/0006-immutable-oci-deployment-and-promotion.md", related)
        self.assertIn("docs/adr/0010-forgejo-and-zot-package-registries.md", related)

    def test_registry_adr_number_does_not_collide_with_observability_adrs(self) -> None:
        old_registry_adr = ROOT / "docs/adr" / ("0007-" + "forgejo-and-zot-package-registries.md")
        self.assertFalse(old_registry_adr.exists())
        self.assertTrue((ROOT / "docs/adr/0007-product-observability-contract.md").is_file())
        self.assertTrue((ROOT / "docs/adr/0008-prometheus-metrics-scraper-and-query.md").is_file())
        self.assertTrue((ROOT / "docs/adr/0009-grafana-operator-visualization.md").is_file())
        decisions = TECHNOLOGY_DECISIONS.read_text()
        self.assertIn("ADR 0007 accepts the product-side observability contract", decisions)
        self.assertIn("ADR 0008 accepts Prometheus", decisions)
        self.assertIn("ADR 0009 is Proposed", decisions)
        self.assertIn("ADR 0010, Proposed", decisions)


if __name__ == "__main__":
    unittest.main()
