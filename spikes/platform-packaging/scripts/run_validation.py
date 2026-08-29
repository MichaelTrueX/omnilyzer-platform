#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request
import venv
from pathlib import Path

from common import (PACKAGE_NAMES, REPOSITORY_ROOT, ROOT, VERSIONS,
                    clean_environment, dump_json, load_json, run,
                    sha256_file, source_tree_sha256)
from validate_compatibility import validate_contract_change
from verify_release import inspect_archives, validate_release_set, verify_hashes

TEMP_ROOT = Path("/tmp/omnilyzer-platform-packaging")


class Evidence:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.lines = []

    def check(self, name, action):
        try:
            action()
        except Exception as error:
            self.failed += 1
            self.lines.append(f"FAIL {name}: {error}")
            raise
        else:
            self.passed += 1
            self.lines.append(f"PASS {name}")

    def truth(self, name, condition, detail="assertion failed"):
        self.check(name, lambda: condition or (_ for _ in ()).throw(AssertionError(detail)))


def node_bin() -> Path:
    existing = Path("/tmp/omnilyzer-node-v24.20.0/bin")
    if (existing / "node").exists():
        return existing
    archive_name = "node-v24.20.0-linux-x64.tar.xz"
    base = "https://nodejs.org/dist/v24.20.0"
    download = TEMP_ROOT / archive_name
    sums = urllib.request.urlopen(f"{base}/SHASUMS256.txt", context=ssl.create_default_context()).read().decode()
    expected = next(line.split()[0] for line in sums.splitlines() if line.endswith(f"  {archive_name}"))
    urllib.request.urlretrieve(f"{base}/{archive_name}", download)
    if sha256_file(download) != expected:
        raise AssertionError("official Node archive SHA-256 verification failed")
    with tarfile.open(download) as archive:
        archive.extractall("/tmp", filter="data")
    extracted = Path("/tmp/node-v24.20.0-linux-x64")
    target = existing.parent
    extracted.rename(target)
    return existing


def create_tooling_venv() -> Path:
    directory = TEMP_ROOT / "tooling-venv"
    venv.EnvBuilder(with_pip=True, clear=True).create(directory)
    python = directory / "bin/python"
    run([python, "-m", "pip", "install", "--disable-pip-version-check", "-r", ROOT / "requirements-tooling.txt"])
    return python


def artifact_for(artifact_root: Path, version: str, package_name: str) -> Path:
    manifest = load_json(artifact_root / version / "release-manifest.json")
    item = next(item for item in manifest["artifacts"] if item["artifactPackageName"] == package_name)
    return artifact_root / version / item["artifactFilename"]


def compare_builds(first: Path, second: Path, evidence: Evidence):
    for version in VERSIONS:
        first_manifest = first / version / "release-manifest.json"
        second_manifest = second / version / "release-manifest.json"
        evidence.truth(f"{version} release manifest deterministic", first_manifest.read_bytes() == second_manifest.read_bytes())
        manifest = load_json(first_manifest)
        for item in manifest["artifacts"]:
            other = second / version / item["artifactFilename"]
            evidence.truth(
                f"{version} {item['artifactPackageName']} artifact deterministic",
                (first / version / item["artifactFilename"]).read_bytes() == other.read_bytes(),
            )


def source_and_contract_checks(artifact_root: Path, evidence: Evidence):
    for version in VERSIONS:
        manifest = load_json(artifact_root / version / "release-manifest.json")
        validate_release_set(manifest)
        for item in manifest["artifacts"]:
            fixture = next(key for key, value in PACKAGE_NAMES.items() if value == item["artifactPackageName"])
            source = ROOT / "release-sources" / version / fixture
            if item["sourceTreeSha256"] != source_tree_sha256(source):
                raise AssertionError("manifest source-tree hash mismatch")
        evidence.passed += 1
        evidence.lines.append(f"PASS {version} coordinated release/source traceability")
    for fixture in ("python-core", "web-contract", "design-governance"):
        def load_contract(version):
            directory = ROOT / "release-sources" / version / fixture
            path = next(directory.rglob("public-contract.json"))
            return load_json(path)
        evidence.check(f"{fixture} same-major public contract", lambda f=fixture: validate_contract_change("1.0.0", load_contract("1.0.0"), "1.1.0", load_contract("1.1.0")))
    old = load_json(next((ROOT / "release-sources/1.0.0/python-core").rglob("public-contract.json")))
    broken = {"publicApi": old["publicApi"][:-1]}
    def rejected_removal():
        try:
            validate_contract_change("1.0.0", old, "1.1.0", broken)
        except AssertionError:
            return
        raise AssertionError("same-major public API removal was accepted")
    evidence.check("same-major removal negative test", rejected_removal)
    evidence.check("simulated 2.0.0 may break contract", lambda: validate_contract_change("1.0.0", old, "2.0.0", broken))
    mixed = load_json(artifact_root / "1.1.0/release-manifest.json")
    mixed["artifacts"][0]["artifactPackageVersion"] = "1.0.0"
    def rejected_mixed():
        try:
            validate_release_set(mixed)
        except AssertionError:
            return
        raise AssertionError("mixed release set was accepted")
    evidence.check("mixed coordinated release rejected before consumption", rejected_mixed)


def verify_source_copy_prohibition(evidence: Evidence):
    forbidden = ("spikes/", "release-sources/", str(REPOSITORY_ROOT), "../../platform source")
    def scan():
        for path in (ROOT / "consumers").rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                if any(token in text for token in forbidden):
                    raise AssertionError(f"source reference in {path.relative_to(ROOT)}")
    evidence.check("consumer fixtures prohibit source copies/references", scan)


def write_product_package_json(product: Path, artifact_root: Path, version: str):
    web = artifact_for(artifact_root, version, "@omnilyzer/platform-web-contract")
    governance = artifact_for(artifact_root, version, "@omnilyzer/design-governance")
    dump_json(product / "package.json", {
        "name": f"fixture-{product.name}", "private": True, "type": "module",
        "dependencies": {
            "@omnilyzer/design-governance": f"file:{governance}",
            "@omnilyzer/platform-web-contract": f"file:{web}",
        },
    })
    pins = load_json(product / "platform-pins.json")
    for key in list(pins):
        pins[key] = version
    dump_json(product / "platform-pins.json", pins)


def reset_install(product: Path):
    for path in (product / ".backend-venv", product / "node_modules"):
        if path.exists():
            shutil.rmtree(path)
    lock = product / "package-lock.json"
    if lock.exists():
        lock.unlink()


def install_product(product: Path, artifact_root: Path, version: str, node: Path):
    reset_install(product)
    write_product_package_json(product, artifact_root, version)
    backend_venv = product / ".backend-venv"
    venv.EnvBuilder(with_pip=True).create(backend_venv)
    python = backend_venv / "bin/python"
    wheel = artifact_for(artifact_root, version, "omnilyzer-platform-core")
    env = clean_environment(node)
    run([python, "-m", "pip", "install", "--no-index", wheel], cwd=product, env=env)
    run([python, "-m", "pip", "check"], cwd=product, env=env)
    run([node / "npm", "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=product, env=env)
    for package in ("platform-web-contract", "design-governance"):
        installed = product / "node_modules/@omnilyzer" / package
        if not installed.is_dir() or installed.is_symlink():
            raise AssertionError(f"npm package is not an installed real directory: {package}")
        if load_json(installed / "package.json")["version"] != version:
            raise AssertionError(f"npm installed version mismatch: {package}")
    lock_text = (product / "package-lock.json").read_text()
    if '"integrity": "sha512-' not in lock_text or f'"version": "{version}"' not in lock_text:
        raise AssertionError("npm lock integrity/version evidence missing")
    return python, env


def execute_product(product: Path, artifact_root: Path, version: str, node: Path, expect_consumers=True):
    python, env = install_product(product, artifact_root, version, node)
    backend_code = (
        f"EXPECTED_PLATFORM_VERSION={version!r};REPOSITORY_ROOT={str(REPOSITORY_ROOT)!r};"
        "exec(compile(open('backend_consumer.py').read(),'backend_consumer.py','exec'))"
    )
    backend = subprocess.run([python, "-c", backend_code], cwd=product, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    web_env = env.copy()
    web_env["EXPECTED_PLATFORM_VERSION"] = version
    web = subprocess.run([node / "node", "web_consumer.mjs"], cwd=product, env=web_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lint = run([product / "node_modules/.bin/omnilyzer-semantic-lint", product / "frontend"], cwd=product, env=env)
    if expect_consumers and (backend.returncode or web.returncode):
        raise AssertionError(f"consumer failure\n{backend.stdout}\n{web.stdout}")
    if not expect_consumers and (backend.returncode == 0 or web.returncode == 0):
        raise AssertionError("Beta unexpectedly remained compatible with downgraded packages")
    return {"backend": backend.returncode, "web": web.returncode, "lint": lint.returncode}


def product_checks(artifact_root: Path, node: Path, evidence: Evidence):
    products_root = TEMP_ROOT / "products"
    alpha = products_root / "product-alpha"
    beta = products_root / "product-beta"
    shutil.copytree(ROOT / "consumers/product-alpha", alpha)
    shutil.copytree(ROOT / "consumers/product-beta", beta)
    evidence.check("Product Alpha isolated platform 1.0.0", lambda: execute_product(alpha, artifact_root, "1.0.0", node))
    evidence.check("Product Beta isolated platform 1.1.0", lambda: execute_product(beta, artifact_root, "1.1.0", node))
    evidence.truth("simultaneous independent adoption", (alpha / ".backend-venv").exists() and (beta / ".backend-venv").exists())
    code_hash = hashlib.sha256((alpha / "backend_consumer.py").read_bytes() + (alpha / "web_consumer.mjs").read_bytes()).hexdigest()
    evidence.check("Alpha unchanged upgrade to 1.1.0", lambda: execute_product(alpha, artifact_root, "1.1.0", node))
    evidence.truth("Alpha source unchanged during upgrade", code_hash == hashlib.sha256((alpha / "backend_consumer.py").read_bytes() + (alpha / "web_consumer.mjs").read_bytes()).hexdigest())
    evidence.check("Alpha unchanged rollback to 1.0.0", lambda: execute_product(alpha, artifact_root, "1.0.0", node))
    evidence.check("Beta package-only downgrade expected failure", lambda: execute_product(beta, artifact_root, "1.0.0", node, expect_consumers=False))
    bad = beta / "noncompliant"
    bad.mkdir()
    (bad / "Bad.jsx").write_text('export const Bad = () => <div className="bg-red-500" style={{color: "#fff"}} />;\n')
    env = clean_environment(node)
    def bad_lint_fails():
        result = subprocess.run([beta / "node_modules/.bin/omnilyzer-semantic-lint", bad], cwd=beta, env=env)
        if result.returncode == 0:
            raise AssertionError("installed governance CLI accepted non-compliant fixture")
    evidence.check("installed governance CLI rejects violations", bad_lint_fails)
    def private_boundary():
        web_env = env.copy()
        result = subprocess.run([node / "node", "-e", "import('@omnilyzer/platform-web-contract/internal.js')"], cwd=alpha, env=web_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            raise AssertionError("npm exports map permitted private deep import")
        py = alpha / ".backend-venv/bin/python"
        run([py, "-c", "import omnilyzer_platform_core as p; assert not hasattr(p, '_PRIVATE_SENTINEL')"], cwd=alpha, env=env)
    evidence.check("installed public/private package boundaries", private_boundary)


def run_unit_tests(evidence: Evidence):
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    evidence.passed += result.testsRun - len(result.failures) - len(result.errors)
    evidence.failed += len(result.failures) + len(result.errors)
    if not result.wasSuccessful():
        raise AssertionError("unit policy tests failed")
    evidence.lines.append(f"PASS {result.testsRun} unittest policy scenarios")


def write_results(evidence: Evidence, identity, hashes):
    result = ROOT / "results/platform-packaging-validation.md"
    result.parent.mkdir(exist_ok=True)
    result.write_text(f"""# Platform packaging validation

Recommendation: **adopt**

| Evidence | Result |
|---|---|
| Python wheel result | PASS — `omnilyzer-platform-core` 1.0.0 and 1.1.0 pure-Python wheels installed with `pip --no-index` |
| npm package result | PASS — both npm packages built and installed as standard `.tgz` artifacts at 1.0.0 and 1.1.0 |
| Coordinated release-set result | PASS — manifests contain all three same-version artifacts; mixed selection rejected |
| Artifact determinism result | PASS — two builds produced identical wheels, tarballs, and manifests |
| Integrity/tamper result | PASS — SHA-256 verification rejected a modified artifact |
| Archive-content result | PASS — allowlists and path/content checks passed; no lifecycle scripts or runtime dependencies |
| Public-boundary result | PASS — Python private symbol is not exported; npm deep import is blocked by `exports` |
| SemVer compatibility result | PASS — additive 1.1.0 accepted, same-major removal rejected, simulated 2.0.0 break permitted |
| Product Alpha 1.0 result | PASS |
| Product Beta 1.1 result | PASS |
| Simultaneous adoption result | PASS — isolated Alpha 1.0.0 and Beta 1.1.0 installations coexisted |
| Alpha upgrade result | PASS — unchanged consumers accepted 1.1.0 |
| Alpha rollback result | PASS — unchanged consumers returned to 1.0.0 |
| Beta downgrade negative test | PASS — package-only downgrade failed because Beta uses 1.1.0 APIs |
| Mixed-version rejection result | PASS — rejected before consumer execution |
| Governance-distribution result | PASS — installed CLI accepted compliant fixtures and rejected a temporary violation |
| Source-copy isolation result | PASS — products executed under `/tmp` with artifact-only installs and no source references |

Tests: **{evidence.passed} passed, {evidence.failed} failed**.

Runtime/tooling: Python {identity['python']}; Node {identity['node']}; npm {identity['npm']}; build {identity['build']}; Hatchling {identity['hatchling']}.

Artifact SHA-256 values are recorded in deterministic per-release manifests. Representative first-build hashes: {', '.join(hashes)}.

The hashes validate integrity and deterministic source-to-artifact traceability. They are not trusted signatures and do not prove artifact authenticity. Task 006 does not validate signed provenance, Sigstore, SLSA attestations, registry trusted publishing, or a protected signing identity.

## Rollback boundary

Package rollback works while consumer code remains compatible with the older public contract. Once a product adopts a newly introduced API, rollback generally requires restoring the product commit and exact package pins together; package downgrade alone is not universal rollback.

## Limitations

Not validated: an actual private registry; registry credentials, authentication, authorization, availability, retention, replication, or disaster recovery; GitHub Packages, private PyPI, npm private registry, or provider billing; signed provenance/Sigstore/SLSA or trusted publishing; production CI; real product repositories; Django reusable apps; React components; database migrations; independent package versioning; large dependency graphs; or very large product fleets.
""", encoding="utf-8")


def main():
    if Path.cwd().resolve() != ROOT:
        raise SystemExit(f"run from {ROOT}: python3 scripts/run_validation.py")
    if TEMP_ROOT.exists():
        shutil.rmtree(TEMP_ROOT)
    TEMP_ROOT.mkdir(parents=True)
    evidence = Evidence()
    node = node_bin()
    evidence.truth("Python 3.12 runtime", platform.python_version().startswith("3.12."), platform.python_version())
    evidence.truth("Node.js 24.20.0 runtime", run([node / "node", "--version"]).stdout.strip() == "v24.20.0")
    tooling_python = create_tooling_venv()
    tool_output = run([tooling_python, "-c", "import importlib.metadata as m; print(m.version('build'), m.version('hatchling'))"]).stdout.strip()
    evidence.truth("pinned isolated Python build tooling", tool_output == "1.6.0 1.32.0", tool_output)
    first = TEMP_ROOT / "build-first"
    second = TEMP_ROOT / "build-second"
    for output in (first, second):
        run([tooling_python, ROOT / "scripts/build_releases.py", output, tooling_python, node])
    compare_builds(first, second, evidence)
    artifact_root = TEMP_ROOT / "artifact-repository"
    shutil.copytree(first, artifact_root)
    for version in VERSIONS:
        evidence.check(f"{version} manifest artifact hashes", lambda v=version: verify_hashes(artifact_root / v))
        evidence.check(f"{version} archive security allowlists", lambda v=version: inspect_archives(artifact_root / v))
    source_and_contract_checks(artifact_root, evidence)
    tampered = TEMP_ROOT / "tampered"
    shutil.copytree(artifact_root / "1.0.0", tampered)
    target = next(tampered.glob("*.whl"))
    content = bytearray(target.read_bytes())
    content[len(content) // 2] ^= 1
    target.write_bytes(content)
    def tamper_rejected():
        try:
            verify_hashes(tampered)
        except AssertionError:
            return
        raise AssertionError("tampered artifact was accepted")
    evidence.check("tampered artifact rejected", tamper_rejected)
    verify_source_copy_prohibition(evidence)
    run_unit_tests(evidence)
    product_checks(artifact_root, node, evidence)
    identity = load_json(artifact_root / "1.0.0/release-manifest.json")["buildRuntimeToolIdentity"]
    hashes = [f"{item['artifactPackageName']}@1.0.0 `{item['artifactSha256']}`" for item in load_json(artifact_root / "1.0.0/release-manifest.json")["artifacts"]]
    write_results(evidence, identity, hashes)
    print("\n".join(evidence.lines))
    print(f"TOTAL: {evidence.passed} passed, {evidence.failed} failed")
    if evidence.failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
