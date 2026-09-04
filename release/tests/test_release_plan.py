from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from release.release_plan import (
    FORGEJO_ORIGIN, ZOT_ORIGIN, PlanError, load_json, materialize, validate_environment,
    validate_plan, validate_semver,
)

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "release/fixtures/task013-canary/release-plan-template.json"
SHA = "f2575b9a90c0f3a03ec0730c2a5ff7fea1ed17e5"


class ReleasePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "plan.json"
        self.plan = materialize(TEMPLATE, "1.2.3", SHA, self.path, ROOT)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def reject(self, mutate) -> None:
        value = copy.deepcopy(self.plan)
        mutate(value)
        with self.assertRaises(PlanError):
            validate_plan(value, ROOT)

    def test_strict_semver(self) -> None:
        for accepted in ("0.0.0", "1.2.3", "10.20.30"):
            self.assertEqual(validate_semver(accepted), accepted)
        for rejected in ("1", "1.2", "v1.2.3", "1.2.3-rc1", "01.2.3", "latest", "1.2.3 "):
            with self.subTest(rejected=rejected), self.assertRaises(PlanError):
                validate_semver(rejected)

    def test_closed_schema_rejects_unknown_and_missing_fields(self) -> None:
        self.reject(lambda plan: plan.update({"extra": True}))
        self.reject(lambda plan: plan.pop("artifacts"))

    def test_source_sha_is_exact_nonzero_commit(self) -> None:
        self.reject(lambda plan: plan.update(source_commit="0" * 40))
        self.reject(lambda plan: plan.update(source_commit="A" * 40))

    def test_absolute_traversal_backslash_and_outside_sources_are_rejected(self) -> None:
        for value in ("/tmp", "../outside", "release/../docs", "release\\fixtures"):
            with self.subTest(value=value):
                self.reject(lambda plan, value=value: plan["sources"].update(python=value))

    def test_source_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            link = Path(temp) / "link"
            link.symlink_to(ROOT / "release/fixtures/task013-canary/python", target_is_directory=True)
            relative = link.relative_to(ROOT).as_posix()
            self.reject(lambda plan: plan["sources"].update(python=relative))

    def test_registry_hosts_are_an_exact_allowlist(self) -> None:
        self.assertEqual(self.plan["registries"], {"forgejo_origin": FORGEJO_ORIGIN, "zot_origin": ZOT_ORIGIN})
        self.reject(lambda plan: plan["registries"].update(zot_origin="https://attacker.example"))

    def test_artifact_filenames_are_plain_unique_and_versioned(self) -> None:
        self.reject(lambda plan: plan["artifacts"].update(python_wheel="../escape.whl"))
        self.reject(lambda plan: plan["artifacts"]["sboms"].update(python="npm-sbom.cdx.json"))
        self.reject(lambda plan: plan["artifacts"].update(npm_tarball="release-canary-latest.tgz"))

    def test_package_destination_cannot_contain_tag_digest_or_wildcard(self) -> None:
        for value in ("omnilyzer/canary:latest", "omnilyzer/canary@sha256:abc", "omnilyzer/*"):
            with self.subTest(value=value):
                self.reject(lambda plan, value=value: plan["packages"]["oci"].update(repository=value))
        self.reject(lambda plan: plan["packages"]["python"].update(name="../../escape"))
        self.reject(lambda plan: plan["packages"]["npm"].update(name="@scope/../../escape"))
        self.reject(lambda plan: plan["packages"]["evidence"].update(owner="other/owner"))
        self.reject(lambda plan: plan["packages"]["npm"].update(name="@another-scope/package"))
        self.reject(lambda plan: plan["packages"]["oci"].update(repository="another-owner/package"))
        self.reject(lambda plan: plan["packages"]["python"].update(owner="another-owner"))

    def test_environment_is_fixed_and_phase1_disabled(self) -> None:
        environment = validate_environment(load_json(ROOT / "release/environments/dev.json"))
        self.assertFalse(environment["publishing_enabled"])
        self.assertEqual(environment["forgejo_origin"], FORGEJO_ORIGIN)
        self.assertEqual(environment["zot_origin"], ZOT_ORIGIN)

    def test_materialized_plan_is_canonical_and_has_no_placeholders(self) -> None:
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("{version}", raw)
        self.assertNotIn("{source_commit}", raw)
        self.assertEqual(json.loads(raw), self.plan)

    def test_materialization_refuses_missing_binding_and_existing_output(self) -> None:
        with self.assertRaisesRegex(PlanError, "overwrite"):
            materialize(TEMPLATE, "1.2.3", SHA, self.path, ROOT)
        template = Path(self.temp.name) / "unbound.json"
        value = load_json(TEMPLATE)
        value["platform_version"] = "9.9.9"
        value["artifacts"]["python_wheel"] = "package-9.9.9.whl"
        value["artifacts"]["npm_tarball"] = "package-9.9.9.tgz"
        value["artifacts"]["oci_archive"] = "package-9.9.9.oci.tar"
        template.write_text(json.dumps(value))
        with self.assertRaisesRegex(PlanError, "bind"):
            materialize(template, "1.2.3", SHA, Path(self.temp.name) / "other.json", ROOT)
