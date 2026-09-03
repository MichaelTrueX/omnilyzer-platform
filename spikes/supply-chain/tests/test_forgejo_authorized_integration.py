"""File: spikes/supply-chain/tests/test_forgejo_authorized_integration.py

Purpose: Focused policy tests for Task 008C Forgejo Authorized Integration probes.

Related:
    - .github/workflows/task008-publish.yml
    - .github/workflows/task008-consume.yml
    - spikes/supply-chain/tests/test_supply_chain.py
"""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PUBLISH = (
    REPOSITORY_ROOT / ".github/workflows/task008-publish.yml"
).read_text(encoding="utf-8")
CONSUME = (
    REPOSITORY_ROOT / ".github/workflows/task008-consume.yml"
).read_text(encoding="utf-8")
NPM_PROBE_PATH = REPOSITORY_ROOT / "spikes/supply-chain/scripts/forgejo_npm_probe.py"
OCI_PROBE_PATH = REPOSITORY_ROOT / "spikes/supply-chain/scripts/forgejo_oci_probe.py"


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
        self.assertEqual(combined.count("ACTIONS_ID_TOKEN_REQUEST_URL"), 5)
        self.assertEqual(combined.count("ACTIONS_ID_TOKEN_REQUEST_TOKEN"), 5)
        self.assertEqual(combined.count('echo "::add-mask::$jwt"'), 5)

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

        pypi_build = job(PUBLISH, "pypi-probe-build")
        self.assertNotIn("id-token: write", pypi_build)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_", pypi_build)
        self.assertNotIn("FORGEJO_", pypi_build)

        npm_build = job(PUBLISH, "npm-probe-build")
        self.assertNotIn("id-token: write", npm_build)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_", npm_build)
        self.assertNotIn("FORGEJO_", npm_build)

    def test_npm_trigger_and_gate_are_distinct_and_fail_closed(self) -> None:
        """Grant npm OIDC authority only for one modified trigger path."""

        trigger = "spikes/supply-chain/control/npm-permissions.trigger"
        header = PUBLISH.split("permissions: {}", 1)[0]
        gate = job(PUBLISH, "gate")
        self.assertEqual(header.count(f"- {trigger}"), 1)
        self.assertIn('"${#changed_paths[@]}" -eq 1', gate)
        self.assertIn("--no-renames", gate)
        self.assertIn(f'"{trigger}"', gate)
        self.assertIn(f"$'M\\t{trigger}'", gate)
        self.assertNotIn(f"$'A\\t{trigger}'", gate)
        self.assertIn("mode=npm-permission", gate)
        self.assertIn("mode=pypi-permission", gate)
        self.assertIn("mode=permission", gate)

    def test_oci_trigger_and_gate_are_exact_single_modify_only(self) -> None:
        """Activate OCI authority only for one modified OCI trigger."""

        trigger = "spikes/supply-chain/control/oci-permissions.trigger"
        header = PUBLISH.split("permissions: {}", 1)[0]
        gate = job(PUBLISH, "gate")
        self.assertEqual(header.count(f"- {trigger}"), 1)
        self.assertIn('"${#changed_paths[@]}" -eq 1', gate)
        self.assertIn("--no-renames", gate)
        self.assertIn(f'"{trigger}"', gate)
        self.assertIn(f"$'M\\t{trigger}'", gate)
        self.assertNotIn(f"$'A\\t{trigger}'", gate)
        self.assertIn("mode=oci-permission", gate)

        def selects(paths: list[str], status: str) -> bool:
            return len(paths) == 1 and paths[0] == trigger and status == f"M\t{trigger}"

        cases = (
            ("addition", [trigger], f"A\t{trigger}"),
            ("deletion", [trigger], f"D\t{trigger}"),
            ("rename", [trigger, "renamed.trigger"], f"D\t{trigger}"),
            ("mixed", [trigger, "README.md"], f"M\t{trigger}"),
            ("unrelated", ["README.md"], "M\tREADME.md"),
        )
        self.assertTrue(selects([trigger], f"M\t{trigger}"))
        for name, paths, status in cases:
            with self.subTest(name=name):
                self.assertFalse(selects(paths, status))

    def test_oci_build_is_non_oidc_and_exports_deterministic_components(self) -> None:
        """Build A and B without credentials or a container daemon."""

        build = job(PUBLISH, "oci-probe-build")
        probe = job(PUBLISH, "oci-permission-probe")
        permissions = build.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(permissions.strip(), "contents: read")
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_", build)
        self.assertNotIn("docker", build.lower())
        self.assertIn("forgejo_oci_probe.py build", build)
        self.assertIn('--source-commit "$GITHUB_SHA"', build)
        self.assertIn('--run-id "$GITHUB_RUN_ID"', build)
        self.assertIn('--run-attempt "$GITHUB_RUN_ATTEMPT"', build)
        self.assertIn("task008c-oci-handoff", build)
        self.assertIn("needs:\n      - gate\n      - oci-probe-build", probe)
        self.assertIn("if: needs.gate.outputs.mode == 'oci-permission'", probe)

    def test_oci_probe_verifies_handoff_before_receiving_oidc_authority(self) -> None:
        """Keep image construction outside the privileged OCI probe job."""

        probe = job(PUBLISH, "oci-permission-probe")
        permissions = probe.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(
            permissions.strip().splitlines(),
            ["contents: read", "      id-token: write"],
        )
        verification = probe.index("Verify OCI handoff before OIDC authentication")
        authentication = probe.index("ACTIONS_ID_TOKEN_REQUEST_URL")
        self.assertLess(verification, authentication)
        self.assertIn("forgejo_oci_probe.py validate", probe)
        self.assertIn('echo "::add-mask::$jwt"', probe)
        self.assertIn("unset token_response", probe)
        self.assertIn("unset jwt", probe)
        self.assertNotIn("secrets.", probe)
        self.assertNotRegex(probe, r"https?://[^\s\"']*\$jwt")

    def test_oci_handoff_is_deterministic_and_content_addressed(self) -> None:
        """Construct exact valid A/B OCI components with one identity."""

        spec = importlib.util.spec_from_file_location("task008c_oci_probe", OCI_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C OCI probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as root:
            first = Path(root) / "first"
            second = Path(root) / "second"
            source = "a" * 40
            one = module.build_handoff(first, source, "123", "1")
            two = module.build_handoff(second, source, "123", "1")
            checked = module.validate_handoff(first, source, "123", "1")
            self.assertEqual(one, two)
            self.assertEqual(checked["repository"], module.REPOSITORY)
            self.assertEqual(checked["tag"], checked["version"])
            self.assertEqual(checked["baseline"]["marker"], "baseline")
            self.assertEqual(checked["replacement"]["marker"], "replacement")
            self.assertNotEqual(
                checked["baseline"]["manifest_digest"],
                checked["replacement"]["manifest_digest"],
            )
            for name in ("baseline", "replacement"):
                manifest = json.loads(checked[name]["bytes"]["manifest"])
                self.assertEqual(
                    manifest["config"]["digest"], checked[name]["config_digest"]
                )
                self.assertEqual(
                    manifest["layers"][0]["digest"], checked[name]["layer_digest"]
                )

    def test_oci_core_auth_is_direct_bearer_and_upload_locations_are_confined(self) -> None:
        """Use the JWT only as a same-origin Authorization Bearer value."""

        script = OCI_PROBE_PATH.read_text(encoding="utf-8")
        self.assertIn('{"Authorization": f"Bearer {self.token}"}', script)
        self.assertNotIn("Basic ", script)
        self.assertNotIn("docker login", script)
        self.assertNotIn("/api/v1/user", script)
        self.assertNotIn("PAT", script)
        self.assertIn("NoRedirect", script)
        self.assertIn("unsafe OCI blob upload Location", script)
        self.assertNotRegex(script, r"https?://[^\s\"']*\{self\.token\}")

        spec = importlib.util.spec_from_file_location("task008c_oci_probe", OCI_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C OCI probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        probe = object.__new__(module.Probe)
        probe.base_url = "https://registry-dev.omnilyzer.ai"
        probe.origin = ("https", "registry-dev.omnilyzer.ai", 443)
        probe.registry_path = "/v2/omnilyzer/task008c-supply-chain-spike"
        probe.token = "test-secret-jwt"

        class Response:
            status = 200
            headers: dict[str, str] = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self) -> bytes:
                return b""

        class Opener:
            request = None

            def open(self, request, timeout):
                self.request = request
                return Response()

        probe.opener = Opener()
        probe.request("GET", "/v2/")
        request = probe.opener.request
        self.assertEqual(request.get_header("Authorization"), "Bearer test-secret-jwt")
        self.assertNotIn("test-secret-jwt", request.full_url)

        blob_digest = "sha256:" + "a" * 64
        safe = probe.upload_url(
            "/v2/omnilyzer/task008c-supply-chain-spike/blobs/uploads/id?_state=x",
            blob_digest,
        )
        self.assertIn("digest=sha256%3A", safe)
        for unsafe in (
            "https://attacker.example/v2/omnilyzer/task008c-supply-chain-spike/blobs/uploads/id",
            "/v2/omnilyzer/task008c-supply-chain-spike/blobs/uploads/%2e%2e/manifests/x",
            "https://user:password@registry-dev.omnilyzer.ai/v2/omnilyzer/task008c-supply-chain-spike/blobs/uploads/id",
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaisesRegex(RuntimeError, "unsafe OCI blob upload Location"):
                    probe.upload_url(unsafe, blob_digest)

    def test_oci_summary_has_independent_security_classifications(self) -> None:
        """Keep tag, digest, DELETE, and rollback outcomes distinct."""

        script = OCI_PROBE_PATH.read_text(encoding="utf-8")
        for row in (
            "GitHub OIDC JWT acquisition",
            "OCI Bearer authentication",
            "baseline manifest PUT status",
            "baseline tag HEAD status",
            "baseline digest HEAD status",
            "tags/list status",
            "exact tag present in tags/list",
            "baseline manifest integrity",
            "same-tag replacement HTTP result",
            "tag digest before replacement",
            "tag digest after replacement",
            "OCI tag immutability",
            "original digest integrity",
            "DELETE tag",
            "DELETE manifest digest",
            "DELETE blob",
            "Public DELETE boundary",
            "post-DELETE manifest integrity",
            "exact-digest rollback after DELETE",
            "Standard Docker/OCI client + OIDC JWT",
            "OCI digest append-only / rollback",
            "Exact-digest rollback",
        ):
            self.assertIn(f'"{row}"', script)

    def test_oci_manifest_get_errors_are_contextual_bounded_and_redacted(self) -> None:
        """Identify the exact failed reference without exposing credentials."""

        spec = importlib.util.spec_from_file_location("task008c_oci_probe", OCI_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C OCI probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        probe = object.__new__(module.Probe)
        probe.registry_path = "/v2/omnilyzer/task008c-supply-chain-spike"
        probe.token = "secret-test-jwt"
        reference = "sha256:" + "a" * 64
        response = (
            b'{"errors":[{"code":"MANIFEST_UNKNOWN","detail":"'
            b"Authorization: Bearer secret-test-jwt "
            + b"x" * 800
            + b'"}]}'
        )
        probe.request = lambda *args, **kwargs: (404, response, {})
        with self.assertRaises(RuntimeError) as raised:
            probe.get_manifest(reference, "baseline digest A")
        message = str(raised.exception)
        self.assertIn(
            f"baseline digest A: OCI manifest GET {reference} returned HTTP 404",
            message,
        )
        self.assertNotIn("secret-test-jwt", message)
        self.assertNotIn("Authorization: Bearer", message)
        detail = message.split("registry response: ", 1)[1]
        self.assertLessEqual(len(detail), module.ERROR_BODY_LIMIT + 1)

    def test_every_oci_manifest_get_has_context_and_diagnostics_precede_gets(self) -> None:
        """Keep HEAD and tag-list evidence while retaining all mandatory GETs."""

        script = OCI_PROBE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(script)
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get_manifest"
        ]
        self.assertGreaterEqual(len(calls), 3)
        self.assertTrue(all(len(call.args) == 2 for call in calls))
        run = script.split("    def run(self)", 1)[1].split(
            "\n    def write_summary", 1
        )[0]
        baseline_put = run.index("self.put_manifest(self.tag")
        tag_head = run.index('self.head_manifest(\n            self.tag, "baseline tag"')
        digest_head = run.index('a["manifest_digest"], "baseline digest A"')
        tags_list = run.index("self.list_tags()")
        tag_get = run.index('self.tag, "baseline tag after PUT"')
        digest_get = run.index(
            'a["manifest_digest"], "baseline", "baseline digest A"'
        )
        self.assertLess(baseline_put, tag_head)
        self.assertLess(tag_head, tag_get)
        self.assertLess(digest_head, digest_get)
        self.assertLess(tags_list, tag_get)
        self.assertIn('self.tag in tags', script)
        self.assertIn("status != 201", run)
        self.assertIn('"baseline manifest PUT status"', script)
        self.assertIn('"same-tag replacement HTTP result"', script)

    def test_oci_tags_list_validates_repository_and_exact_tag_presence(self) -> None:
        """Record whether Forgejo made the exact newly published tag visible."""

        spec = importlib.util.spec_from_file_location("task008c_oci_probe", OCI_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C OCI probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        probe = object.__new__(module.Probe)
        probe.repository = "omnilyzer/task008c-supply-chain-spike"
        probe.registry_path = f"/v2/{probe.repository}"
        probe.tag = "0.0.1231"
        probe.rows = {
            "tags/list status": "NOT RUN",
            "tags/list repository": "NOT RUN",
            "exact tag present in tags/list": "NOT RUN",
        }
        probe.failures = []
        probe.phase = lambda message: None
        payload = json.dumps({"name": probe.repository, "tags": [probe.tag]}).encode()
        probe.request = lambda *args, **kwargs: (200, payload, {})

        self.assertEqual(probe.list_tags(), [probe.tag])
        self.assertEqual(probe.rows["tags/list status"], "HTTP 200")
        self.assertEqual(probe.rows["tags/list repository"], probe.repository)
        self.assertEqual(probe.rows["exact tag present in tags/list"], "PASS")
        self.assertEqual(probe.failures, [])

        payload = json.dumps({"name": probe.repository, "tags": ["other"]}).encode()
        self.assertEqual(probe.list_tags(), ["other"])
        self.assertEqual(probe.rows["exact tag present in tags/list"], "FAIL")
        self.assertIn("baseline exact tag was absent from tags/list", probe.failures)

    def test_oci_phase_markers_are_non_secret_and_cover_live_boundaries(self) -> None:
        """Make live progress visible without including the JWT."""

        script = OCI_PROBE_PATH.read_text(encoding="utf-8")
        run = script.split("    def run(self)", 1)[1].split(
            "\n    def write_summary", 1
        )[0]
        self.assertNotIn("self.token", run)
        self.assertNotIn("Authorization", run)
        for marker in (
            "registry API check passed",
            "registry authentication passed",
            "baseline config blob available",
            "baseline layer blob available",
            "publishing baseline manifest A",
            "resolving baseline tag",
            "resolving baseline digest A",
            "uploading replacement B",
            "replacement PUT",
            "resolving tag after replacement",
            "verifying original digest A",
            "DELETE probes",
            "post-DELETE verification",
        ):
            self.assertIn(marker, run)

    def test_oci_registry_deletes_require_exact_http_403(self) -> None:
        """Distinguish explicit denial from success and inconclusive statuses."""

        spec = importlib.util.spec_from_file_location("task008c_oci_probe", OCI_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C OCI probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        probe = object.__new__(module.Probe)

        probe.rows = {"DELETE manifest digest": "NOT RUN"}
        probe.failures = []
        for status, expected in (
            (403, "PASS"), (202, "SECURITY FAILURE"), (405, "INCONCLUSIVE")
        ):
            probe.request = lambda *args, observed=status, **kwargs: (observed, b"", {})
            probe.delete("DELETE manifest digest", "/v2/example/manifests/value")
            with self.subTest(status=status):
                self.assertTrue(probe.rows["DELETE manifest digest"].startswith(expected))

    def test_oci_successful_tag_movement_continues_through_digest_survival(self) -> None:
        """Exercise the expected mutable-tag path through the final PASS result."""

        spec = importlib.util.spec_from_file_location("task008c_oci_probe", OCI_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C OCI probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        probe = object.__new__(module.Probe)
        digest_a, digest_b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        probe.repository = "omnilyzer/task008c-supply-chain-spike"
        probe.registry_path = f"/v2/{probe.repository}"
        probe.tag = "0.0.1231"
        probe.record = {
            "version": probe.tag,
            "baseline": {
                "manifest_digest": digest_a, "config_digest": "sha256:" + "c" * 64,
                "layer_digest": "sha256:" + "d" * 64,
                "bytes": {"manifest": b"a", "config": b"c", "layer": b"d"},
            },
            "replacement": {
                "manifest_digest": digest_b, "config_digest": "sha256:" + "e" * 64,
                "layer_digest": "sha256:" + "f" * 64,
                "bytes": {"manifest": b"b", "config": b"e", "layer": b"f"},
            },
        }
        probe.failures = []
        probe.rows = probe.initial_rows()
        observed: list[str] = []
        resolutions = iter(
            ((digest_a, b"a"), (digest_b, b"b"), (digest_b, b"b"))
        )
        probe.request = lambda *args, **kwargs: (200, b"", {})
        probe.ensure_blob = lambda *args: observed.append("blob-upload")
        probe.phase = lambda message: observed.append(f"phase:{message}")
        probe.head_manifest = lambda reference, context: (200, digest_a)
        def list_tags() -> list[str]:
            probe.rows["tags/list status"] = "HTTP 200"
            probe.rows["tags/list repository"] = probe.repository
            probe.rows["exact tag present in tags/list"] = "PASS"
            return [probe.tag]
        probe.list_tags = list_tags
        pushes = iter(((201, {"Docker-Content-Digest": digest_a}),
                       (201, {"Docker-Content-Digest": digest_b})))
        probe.put_manifest = lambda *args: next(pushes)
        probe.get_manifest = lambda *args: next(resolutions)
        probe.verify_variant = lambda reference, name, context: observed.append(
            f"verify:{reference}:{context}"
        )
        def deny(row: str, path: str) -> None:
            probe.rows[row] = "PASS (HTTP 403)"
            observed.append(row)
        probe.delete = deny

        probe.run()

        self.assertTrue(probe.rows["OCI tag immutability"].startswith("FAIL"))
        self.assertEqual(probe.rows["OCI digest append-only / rollback"], "PASS")
        self.assertEqual(probe.rows["Exact-digest rollback"], "PASS")
        self.assertEqual(
            len([item for item in observed if item.startswith(f"verify:{digest_a}:")]),
            3,
        )
        self.assertEqual(
            [item for item in observed if item.startswith("DELETE")],
            ["DELETE manifest digest", "DELETE tag", "DELETE blob"],
        )

    def test_npm_build_is_non_oidc_and_constructs_different_exact_identities(self) -> None:
        """Build two same-identity tarballs with deliberately different bytes."""

        build = job(PUBLISH, "npm-probe-build")
        permissions = build.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(permissions.strip(), "contents: read")
        self.assertNotIn("id-token: write", build)
        self.assertIn("prepare_release.py", build)
        self.assertIn("node-version: '24.20.0'", build)
        self.assertIn('version="0.0.${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}"', build)
        self.assertEqual(build.count("npm pack"), 2)
        self.assertEqual(build.count("--ignore-scripts"), 2)
        self.assertIn("task008c-replacement", build)
        self.assertIn("baseline.name != replacement.name", build)
        self.assertIn("baseline_sha256 == replacement_sha256", build)
        for field in (
            "package_name",
            "version",
            "tarball_filename",
            "baseline_sha256",
            "replacement_sha256",
            "baseline_sha1",
            "baseline_sha512",
            "source_commit",
        ):
            self.assertIn(f'"{field}"', build)
        artifact = build.split("Upload the minimal npm probe handoff", 1)[1]
        self.assertIn("task008c-npm-handoff", artifact)

    def test_npm_oidc_job_permissions_and_pre_auth_handoff_gate_are_narrow(self) -> None:
        """Validate both tarballs completely before npm OIDC acquisition."""

        probe = job(PUBLISH, "npm-permission-probe")
        permissions = probe.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(
            permissions.strip().splitlines(),
            ["contents: read", "      id-token: write"],
        )
        self.assertIn("needs:\n      - gate\n      - npm-probe-build", probe)
        self.assertIn("if: needs.gate.outputs.mode == 'npm-permission'", probe)
        self.assertIn("node-version: '24.20.0'", probe)
        verification = probe.index("Verify npm handoff before OIDC authentication")
        oidc = probe.index("ACTIONS_ID_TOKEN_REQUEST_URL")
        self.assertLess(verification, oidc)
        self.assertIn("replacement.name != baseline.name", probe)
        self.assertIn('package.get("name") != manifest["package_name"]', probe)
        self.assertIn('package.get("version") != manifest["version"]', probe)
        self.assertIn('echo "::add-mask::$jwt"', probe)
        self.assertIn('token_file="$RUNNER_TEMP/task008c-forgejo-npm-oidc.jwt"', probe)
        self.assertNotIn("secrets.", probe)
        self.assertNotRegex(probe, r"https?://[^\s\"']*\$jwt")

    def test_npm_probe_uses_scoped_token_without_public_fallback(self) -> None:
        """Use normal npm Bearer token auth without credentialed URLs."""

        script = (
            REPOSITORY_ROOT / "spikes/supply-chain/scripts/forgejo_npm_probe.py"
        ).read_text(encoding="utf-8")
        self.assertIn('f"@omnilyzer:registry={self.registry}\\n"', script)
        self.assertIn('f"{auth_scope}={self.token}\\n"', script)
        self.assertIn('"NPM_CONFIG_USERCONFIG": str(self.npmrc)', script)
        self.assertIn('"NPM_CONFIG_LOGS_MAX": "0"', script)
        self.assertIn("self.npmrc.chmod(0o600)", script)
        self.assertIn("if self.token in combined_output:", script)
        self.assertIn("SECURITY FAILURE: npm output contained the OIDC JWT", script)
        self.assertNotIn("registry.npmjs.org", script)
        self.assertNotRegex(script, r"https?://[^\s\"']*\{self\.token\}")
        self.assertIn('"--provenance=false"', script)
        self.assertIn('"--ignore-scripts"', script)
        self.assertIn('"--offline"', script)
        self.assertIn('"Standard npm + OIDC JWT"] = "PASS"', script)

    def test_npm_round_trip_replacement_and_delete_fail_closed(self) -> None:
        """Require exact bytes, real install, strong replacement, and DELETE 403."""

        script = (
            REPOSITORY_ROOT / "spikes/supply-chain/scripts/forgejo_npm_probe.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("Path(parsed.path).name != self.tarball_name", script)
        self.assertIn("destination_directory / self.tarball_name", script)
        self.assertIn('headers={"Authorization": f"Bearer {self.token}"}', script)
        self.assertIn("quote(self.package_name, safe='')", script)
        self.assertIn('file_digest(tarball, "sha256")', script)
        self.assertIn("observed != self.baseline_sha256", script)
        self.assertIn("observed == self.replacement_sha256", script)
        run = script.split("    def run(self)", 1)[1].split(
            "\n\n    def close", 1
        )[0]
        self.assertLess(run.index("self.download("), run.index("self.install_downloaded"))
        self.assertLess(
            run.index("self.require_baseline_integrity(initial)"),
            run.index("self.install_downloaded(initial"),
        )
        self.assertIn("SECURITY FAILURE: npm same-version replacement succeeded", script)
        self.assertIn("REPLACEMENT_PATTERN.search", script)
        self.assertIn("SECURITY FAILURE: npm unpublish succeeded", script)
        self.assertIn("UNPUBLISH_DENIAL_PATTERN.search", script)
        self.assertIn("status == 403", script)
        self.assertIn("SECURITY FAILURE: npm package-version DELETE succeeded", script)
        self.assertIn("INCONCLUSIVE: npm package-version DELETE", script)
        self.assertIn('"post-replacement integrity"', script)
        self.assertIn('"post-DELETE integrity"', script)
        for label in (
            "Task 008C Forgejo npm probe",
            "npm metadata SHA-1",
            "npm metadata SHA-512 integrity",
            "standard npm pack/download",
            "same-version replacement",
            "npm unpublish denied",
            "REST DELETE",
            "STANDARD_NPM_OIDC_AUTH =",
            "Core npm append-only",
        ):
            self.assertIn(label, script)

    def test_npm_tarball_url_treats_registry_object_path_as_opaque(self) -> None:
        """Accept opaque Forgejo storage routes within the exact npm registry."""

        spec = importlib.util.spec_from_file_location("task008c_npm_probe", NPM_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C npm probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        probe = object.__new__(module.Probe)
        probe.registry = (
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/"
        )
        probe.package_name = "@omnilyzer/supply-chain-spike"
        probe.tarball_name = "omnilyzer-supply-chain-spike-0.0.123.tgz"

        valid = (
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/package/123/file",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/"
            "internal/storage/object.tgz",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/"
            "@something/whatever",
        )
        for value in valid:
            with self.subTest(value=value):
                self.assertEqual(probe.validate_tarball_url(value), value)

        invalid = (
            "http://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/object",
            "https://packages.example.invalid/api/packages/omnilyzer/npm/object",
            "https://registry-dev.omnilyzer.ai:444/api/packages/omnilyzer/npm/object",
            "https://user@registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/object",
            "https://user:password@registry-dev.omnilyzer.ai/"
            "api/packages/omnilyzer/npm/object",
            "https://registry-dev.omnilyzer.ai/api/packages/another-owner/npm/object",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/generic/object",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm-evil/object",
            "https://registry-dev.omnilyzer.ai/outside/npm/object",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/object?x=1",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/object#fragment",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/./object",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/%2e%2e/object",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/a\\object",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/a%5cobject",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/a%00object",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm/",
            "https://registry-dev.omnilyzer.ai/api/packages/omnilyzer/npm//",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    probe.validate_tarball_url(value)

    def test_npm_metadata_requires_exact_package_and_version_identity(self) -> None:
        """Reject a tarball URL unless exact requested metadata identity precedes it."""

        spec = importlib.util.spec_from_file_location("task008c_npm_probe", NPM_PROBE_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to load Task 008C npm probe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        probe = object.__new__(module.Probe)
        probe.package_name = "@omnilyzer/supply-chain-spike"
        probe.version = "0.0.123"
        probe.results = {"npm metadata read": "FAIL"}

        payload = {
            "name": probe.package_name,
            "version": probe.version,
            "dist": {"tarball": "https://registry-dev.omnilyzer.ai/opaque"},
        }

        def metadata_for(candidate: dict[str, object]) -> dict[str, object]:
            probe.npm = lambda *args, **kwargs: SimpleNamespace(
                returncode=0, stdout=json.dumps(candidate)
            )
            return probe.metadata({}, "identity-test")

        self.assertEqual(metadata_for(payload), payload["dist"])
        for field, changed in (("name", "@omnilyzer/other"), ("version", "0.0.124")):
            candidate = dict(payload)
            candidate[field] = changed
            with self.subTest(field=field):
                with self.assertRaisesRegex(RuntimeError, "metadata identity mismatch"):
                    metadata_for(candidate)

    def test_pypi_trigger_and_gate_are_distinct_and_fail_closed(self) -> None:
        """Grant PyPI OIDC authority only for one modified trigger path."""

        trigger = "spikes/supply-chain/control/pypi-permissions.trigger"
        header = PUBLISH.split("permissions: {}", 1)[0]
        gate = job(PUBLISH, "gate")
        self.assertEqual(header.count(f"- {trigger}"), 1)
        self.assertIn('"${#changed_paths[@]}" -eq 1', gate)
        self.assertIn("--no-renames", gate)
        self.assertIn(f'"{trigger}"', gate)
        self.assertIn(f"$'M\\t{trigger}'", gate)
        self.assertNotIn(f"$'A\\t{trigger}'", gate)
        self.assertIn("mode=pypi-permission", gate)
        self.assertNotEqual(
            gate.index("mode=pypi-permission"), gate.index("mode=permission")
        )

    def test_pypi_build_is_non_oidc_and_handoff_is_minimal(self) -> None:
        """Build one prepared fixture wheel before entering the OIDC job."""

        build = job(PUBLISH, "pypi-probe-build")
        probe = job(PUBLISH, "pypi-permission-probe")
        build_permissions = build.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(build_permissions.strip(), "contents: read")
        self.assertIn("prepare_release.py", build)
        self.assertIn('version="0.0.${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}"', build)
        self.assertIn("build==1.6.0 hatchling==1.32.0", build)
        self.assertIn('"${#wheels[@]}" -ne 1', build)
        for field in (
            "package_name",
            "version",
            "wheel_filename",
            "sha256",
            "source_commit",
        ):
            self.assertIn(f'"{field}"', build)
        self.assertIn("task008c-pypi-handoff", build)
        self.assertNotIn("id-token: write", build)
        self.assertIn("needs:\n      - gate\n      - pypi-probe-build", probe)
        self.assertIn("if: needs.gate.outputs.mode == 'pypi-permission'", probe)
        self.assertLess(
            probe.index("Verify handoff manifest and wheel"),
            probe.index("ACTIONS_ID_TOKEN_REQUEST_URL"),
        )

    def test_pypi_probe_credentials_and_permissions_are_narrow(self) -> None:
        """Keep the JWT masked, out of URLs/artifacts, and under RUNNER_TEMP."""

        probe = job(PUBLISH, "pypi-permission-probe")
        permissions = probe.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(
            permissions.strip().splitlines(),
            ["contents: read", "      id-token: write"],
        )
        self.assertIn('echo "::add-mask::$jwt"', probe)
        self.assertIn('token_file="$RUNNER_TEMP/task008c-forgejo-oidc.jwt"', probe)
        self.assertIn("unset token_response", probe)
        self.assertIn("unset jwt", probe)
        self.assertNotIn("secrets.", probe)
        self.assertNotRegex(probe, r"https?://[^\s\"']*\$jwt")
        artifact_step = probe.split("Download the isolated PyPI probe handoff", 1)[1]
        self.assertNotIn("upload-artifact", artifact_step)

    def test_pypi_protocol_and_standard_clients_are_independent(self) -> None:
        """Assert the probe distinguishes Bearer behavior from Basic clients."""

        workflow_probe = job(PUBLISH, "pypi-permission-probe")
        script = (
            REPOSITORY_ROOT
            / "spikes/supply-chain/scripts/forgejo_pypi_probe.py"
        ).read_text(encoding="utf-8")
        self.assertIn("twine==7.0.0", workflow_probe)
        self.assertIn('f"{self.base_url}/api/v1/user"', script)
        self.assertIn('"TWINE_USERNAME": login', script)
        self.assertIn('"TWINE_PASSWORD": self.token', script)
        self.assertIn('repository.session.headers["Authorization"]', script)
        self.assertIn("repository.session.auth = BearerAuth(self.token)", script)
        self.assertIn('request.headers["Authorization"]', script)
        self.assertIn('"NETRC": str(netrc)', script)
        self.assertIn('"PIP_INDEX_URL":', script)
        self.assertNotIn("self.token}@", script)
        self.assertIn("--no-index", script)
        self.assertIn("--no-deps", script)
        self.assertIn("report())", script)

    def test_current_user_403_continues_to_bearer_publication(self) -> None:
        """Treat REST identity denial as optional, not a PyPI prerequisite."""

        script = (
            REPOSITORY_ROOT
            / "spikes/supply-chain/scripts/forgejo_pypi_probe.py"
        ).read_text(encoding="utf-8")
        current_user = script.split("    def current_user", 1)[1].split(
            "    def twine_upload", 1
        )[0]
        run = script.split("    def run(self)", 1)[1].split(
            "\n\ndef parse_arguments", 1
        )[0]
        self.assertIn("response.status_code in (401, 403)", current_user)
        self.assertIn('f"FAIL (HTTP {response.status_code})"', current_user)
        self.assertIn("return None", current_user)
        self.assertIn("unexpected HTTP", current_user)
        self.assertIn("FAIL (malformed response)", current_user)
        no_login = run.index("if login is None:")
        bearer_fallback = run.index("if not twine_passed and not baseline_exists:")
        bearer_upload = run.index("response = self.bearer_upload()", bearer_fallback)
        self.assertLess(no_login, bearer_fallback)
        self.assertLess(bearer_fallback, bearer_upload)
        self.assertNotIn("raise", run[no_login:run.index("else:", no_login)])

    def test_unavailable_login_makes_standard_clients_inconclusive(self) -> None:
        """Do not guess a Basic-auth username when current-user API is forbidden."""

        script = (
            REPOSITORY_ROOT
            / "spikes/supply-chain/scripts/forgejo_pypi_probe.py"
        ).read_text(encoding="utf-8")
        run = script.split("    def run(self)", 1)[1].split(
            "\n\ndef parse_arguments", 1
        )[0]
        self.assertIn(
            'unavailable = "INCONCLUSIVE (Forgejo login unavailable)"', run
        )
        self.assertIn(
            'self.results["Standard Twine + OIDC JWT"] = unavailable', run
        )
        self.assertIn(
            'self.results["Standard pip + OIDC JWT"] = unavailable', run
        )
        self.assertIn("if login is not None and not twine_passed:", run)
        self.assertIn("if login is not None:\n            self.results", run)
        self.assertNotRegex(script, r"TWINE_USERNAME[\"']?\s*:\s*[\"'][^\"']+")

    def test_package_bearer_pass_requires_a_successful_registry_operation(self) -> None:
        """JWT issuance alone must not prove package-registry authentication."""

        script = (
            REPOSITORY_ROOT
            / "spikes/supply-chain/scripts/forgejo_pypi_probe.py"
        ).read_text(encoding="utf-8")
        initialization = script.split("    def verify_handoff", 1)[0]
        current_user = script.split("    def current_user", 1)[1].split(
            "    def twine_upload", 1
        )[0]
        bearer_upload = script.split("    def bearer_upload", 1)[1].split(
            "    def exact_wheel_url", 1
        )[0]
        simple_read = script.split("    def exact_wheel_url", 1)[1].split(
            "    def download_exact", 1
        )[0]
        self.assertIn('"GitHub OIDC JWT acquisition": "FAIL"', initialization)
        self.assertIn(
            'self.results["GitHub OIDC JWT acquisition"] = "PASS"',
            initialization,
        )
        self.assertIn('"Package Bearer authentication": "FAIL"', initialization)
        self.assertNotIn('"Package Bearer authentication"] = "PASS"', current_user)
        self.assertIn("if 200 <= response.status_code < 300:", bearer_upload)
        self.assertIn(
            'self.results["Package Bearer authentication"] = "PASS"',
            bearer_upload,
        )
        self.assertLess(
            simple_read.index("require_status(response, 200"),
            simple_read.index(
                'self.results["Package Bearer authentication"] = "PASS"'
            ),
        )

    def test_registry_downloads_preserve_exact_wheel_filename(self) -> None:
        """Keep each downloaded copy isolated with pip-valid original basename."""

        script = (
            REPOSITORY_ROOT
            / "spikes/supply-chain/scripts/forgejo_pypi_probe.py"
        ).read_text(encoding="utf-8")
        download = script.split("    def download_exact", 1)[1].split(
            "    def wheel_destination", 1
        )[0]
        destination = script.split("    def wheel_destination", 1)[1].split(
            "    def require_integrity", 1
        )[0]
        run = script.split("    def run(self)", 1)[1].split(
            "\n\ndef parse_arguments", 1
        )[0]
        self.assertIn("destination.name != self.wheel_name", download)
        self.assertIn("destination_directory.mkdir()", destination)
        self.assertIn("return destination_directory / self.wheel_name", destination)
        for probe_name in (
            "after-twine",
            "initial",
            "after-duplicate",
            "after-delete",
        ):
            self.assertIn(f'self.wheel_destination("{probe_name}")', run)
        initial = run.index('initial = self.wheel_destination("initial")')
        downloaded = run.index("self.download_exact(initial)")
        integrity = run.index("self.require_integrity(initial)")
        install = run.index("self.install_wheel(initial)")
        self.assertLess(initial, downloaded)
        self.assertLess(downloaded, integrity)
        self.assertLess(integrity, install)
        for invalid_name in (
            "task008c-initial-wheel.whl",
            "task008c-after-duplicate.whl",
            "task008c-after-delete.whl",
        ):
            self.assertNotIn(invalid_name, script)

    def test_pypi_duplicate_delete_and_integrity_fail_closed(self) -> None:
        """Require duplicate denial, exact hashes, REST DELETE 403, and rereads."""

        script = (
            REPOSITORY_ROOT
            / "spikes/supply-chain/scripts/forgejo_pypi_probe.py"
        ).read_text(encoding="utf-8")
        self.assertIn("SECURITY FAILURE: duplicate PyPI publication succeeded", script)
        self.assertIn("DUPLICATE_PATTERN.search", script)
        self.assertIn('self.results["Post-duplicate integrity"] = "PASS"', script)
        self.assertIn("/api/v1/packages/{quote(self.owner)}/pypi/", script)
        self.assertIn("deleted.status_code == 403", script)
        self.assertIn("SECURITY FAILURE: PyPI package-version DELETE succeeded", script)
        self.assertIn("INCONCLUSIVE: PyPI package-version DELETE", script)
        self.assertIn('self.results["Post-DELETE retrieval"] = "PASS"', script)
        self.assertIn('self.results["Post-DELETE integrity"] = "PASS"', script)
        for label in (
            "Task 008C Forgejo PyPI probe",
            "GitHub OIDC JWT acquisition",
            "Package Bearer authentication",
            "Current-user API",
            "PyPI publish",
            "Standard Twine + OIDC JWT",
            "Standard pip + OIDC JWT",
            "STANDARD_TWINE_OIDC_AUTH =",
            "STANDARD_PIP_OIDC_AUTH =",
        ):
            self.assertIn(label, script)

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
