from __future__ import annotations

import gzip
import hashlib
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import sys
import tarfile
import tempfile
from threading import Thread
import unittest
import urllib.request

import yaml

from release.executable_oci import (
    BASE_IMAGE_DIGEST,
    ExecutableOCIError,
    verify_executable_archive,
)


ROOT = Path(__file__).resolve().parents[2]
CANARY = ROOT / "release/fixtures/task013-canary/oci"
sys.path.insert(0, str(CANARY))
from canary_runtime import CanaryApplication, handler  # noqa: E402
from migration import MigrationError, execute, expected_migration  # noqa: E402


VERSION = "0.14.0"
SOURCE_SHA = "728a5ef4d53342bd7bfa5a094a1e90dd3d6ade56"
REPOSITORY = "omnilyzer/task013-release-canary"
BASE_ENVIRONMENT = {
    "CANARY_RELEASE_VERSION": VERSION,
    "CANARY_SOURCE_SHA": SOURCE_SHA,
}
PROTECTED_HASHES = {
    ".github/workflows/platform-release.yml": "53485cfafd1d1b8cdf0b1cb80c34bab12be12bfc07d7f7e6629a8c489be53471",
    "release/vulnerability-policy.json": "475ad38ef4ae8d89dcf7d4e03eeb76701085fdcd4ebdb8ae9aa41a7bce2cde8f",
    "release/publish_forgejo.py": "a30497ac6af29c35c860f09342d8b3a5d34e0baf092ea1fec0aba818105b42bd",
    "release/publish_zot.py": "e6271f96d3eb7b66df06f2bea6e90addbad88d44b0e461de8bdcd26b085b8ea7",
    "release/provenance.py": "845c3758c9a0b503b582a5264942b6622aae331ab21013be641ae36d4235d443",
    "deployment/environments/dev.json": "4b1cf03bdcd1fa7d8fd848862137a4dca7dc834b1cc45fa1d7cffd2756722ae8",
    "deployment/environments/staging.json": "7fde448d38022e4e435218c1fe6049c629ee091031845fce93156dcc787a7358",
    "deployment/environments/prod.json": "a08cd3d718ffa0531071ed7ad0aeafc19b4edeb0a82e74bd87a6044bbabebcce",
    ".github/workflows/platform-promote.yml": "3846ae1e48c945dacb563da8967e588b3fbb6fffa2580276f816496396b3c134",
}


class CanaryRuntimeTests(unittest.TestCase):
    def test_livez_returns_200(self) -> None:
        status, body = CanaryApplication(BASE_ENVIRONMENT, Path("/absent")).response("/livez")
        self.assertEqual((status, body), (200, {"live": True}))

    def test_livez_is_process_only(self) -> None:
        environment = {
            **BASE_ENVIRONMENT,
            "CANARY_DEPENDENCY_REQUIRED": "true",
            "CANARY_DEPENDENCY_HOST": "127.0.0.1",
            "CANARY_DEPENDENCY_PORT": "1",
        }
        status, _ = CanaryApplication(environment, Path("/absent")).response("/livez")
        self.assertEqual(status, 200)

    def test_readyz_fails_without_runtime_configuration(self) -> None:
        status, body = CanaryApplication(BASE_ENVIRONMENT, Path("/absent")).response("/readyz")
        self.assertEqual(status, 503)
        self.assertFalse(body["checks"]["runtime_configuration"])

    def test_readyz_fails_before_explicit_migration(self) -> None:
        environment = {**BASE_ENVIRONMENT, "CANARY_RUNTIME_CONFIG_ID": "task014-dev"}
        status, body = CanaryApplication(environment, Path("/absent")).response("/readyz")
        self.assertEqual(status, 503)
        self.assertFalse(body["checks"]["migration"])

    def test_readyz_succeeds_after_all_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definition = root / "migration-definition.json"
            definition.write_bytes((CANARY / "migration-definition.json").read_bytes())
            marker = root / "migration.json"
            execute(marker, root / "migration.lock", definition)
            application = CanaryApplication(
                {**BASE_ENVIRONMENT, "CANARY_RUNTIME_CONFIG_ID": "task014-dev"},
                marker,
                definition,
            )
            status, body = application.response("/readyz")
            self.assertEqual(status, 200)
            self.assertTrue(body["ready"])

    def test_required_dependency_must_be_reachable(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        environment = {
            **BASE_ENVIRONMENT,
            "CANARY_DEPENDENCY_REQUIRED": "true",
            "CANARY_DEPENDENCY_HOST": host,
            "CANARY_DEPENDENCY_PORT": str(port),
        }
        try:
            self.assertTrue(CanaryApplication(environment, Path("/absent"))._dependency_ready())
        finally:
            listener.close()

    def test_readyz_fails_when_required_dependency_is_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definition = root / "migration-definition.json"
            definition.write_bytes((CANARY / "migration-definition.json").read_bytes())
            marker = root / "migration.json"
            execute(marker, root / "migration.lock", definition)
            environment = {
                **BASE_ENVIRONMENT,
                "CANARY_RUNTIME_CONFIG_ID": "task014-dev",
                "CANARY_DEPENDENCY_REQUIRED": "true",
                "CANARY_DEPENDENCY_HOST": "127.0.0.1",
                "CANARY_DEPENDENCY_PORT": "1",
            }
            status, body = CanaryApplication(environment, marker, definition).response("/readyz")
            self.assertEqual(status, 503)
            self.assertFalse(body["checks"]["dependency"])

    def test_readyz_accepts_reachable_required_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definition = root / "migration-definition.json"
            definition.write_bytes((CANARY / "migration-definition.json").read_bytes())
            marker = root / "migration.json"
            execute(marker, root / "migration.lock", definition)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            host, port = listener.getsockname()
            environment = {
                **BASE_ENVIRONMENT,
                "CANARY_RUNTIME_CONFIG_ID": "task014-dev",
                "CANARY_DEPENDENCY_REQUIRED": "true",
                "CANARY_DEPENDENCY_HOST": host,
                "CANARY_DEPENDENCY_PORT": str(port),
            }
            try:
                status, body = CanaryApplication(environment, marker, definition).response("/readyz")
            finally:
                listener.close()
            self.assertEqual(status, 200)
            self.assertTrue(body["ready"])

    def test_metadata_returns_exact_build_identity(self) -> None:
        status, body = CanaryApplication(BASE_ENVIRONMENT, Path("/absent")).response("/metadata")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"canary": True, "release_version": VERSION, "source_sha": SOURCE_SHA})

    def test_unknown_or_ambiguous_route_returns_404(self) -> None:
        application = CanaryApplication(BASE_ENVIRONMENT, Path("/absent"))
        for target in ("/unknown", "/metadata?secret=value"):
            with self.subTest(target=target):
                self.assertEqual(application.response(target)[0], 404)

    def test_responses_never_reflect_environment_or_secrets(self) -> None:
        environment = {**BASE_ENVIRONMENT, "CANARY_RUNTIME_CONFIG_ID": "private-config", "SECRET_TOKEN": "do-not-return"}
        application = CanaryApplication(environment, Path("/absent"))
        encoded = json.dumps([application.response(path) for path in ("/livez", "/readyz", "/metadata")])
        self.assertNotIn("private-config", encoded)
        self.assertNotIn("do-not-return", encoded)
        self.assertLess(len(encoded), 1024)

    def test_http_handler_returns_bounded_json(self) -> None:
        application = CanaryApplication(BASE_ENVIRONMENT, Path("/absent"))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(application))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/metadata") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(json.load(response)["source_sha"], SOURCE_SHA)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class MigrationCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.definition = self.root / "migration-definition.json"
        self.definition.write_bytes((CANARY / "migration-definition.json").read_bytes())
        self.marker = self.root / "migration.json"
        self.lock = self.root / "migration.lock"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_application_startup_does_not_run_migration(self) -> None:
        CanaryApplication(BASE_ENVIRONMENT, self.marker)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.lock.exists())

    def test_explicit_migration_records_identity_and_checksum(self) -> None:
        identity, checksum = expected_migration(self.definition)
        execute(self.marker, self.lock, self.definition)
        value = json.loads(self.marker.read_text())
        self.assertEqual(value["migration_identity"], identity)
        self.assertEqual(value["migration_checksum"], checksum)
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)

    def test_changed_migration_checksum_fails_closed(self) -> None:
        execute(self.marker, self.lock, self.definition)
        self.definition.write_bytes(self.definition.read_bytes().rstrip(b"\n") + b" \n")
        with self.assertRaises(MigrationError):
            execute(self.marker, self.lock, self.definition)

    def test_malformed_migration_identity_fails_closed(self) -> None:
        value = json.loads(self.definition.read_text())
        value["migration_identity"] = "../../escape"
        self.definition.write_text(json.dumps(value))
        with self.assertRaises(MigrationError):
            expected_migration(self.definition)

    def test_migration_uses_serialized_lock_without_down_operation(self) -> None:
        source = (CANARY / "migration.py").read_text()
        self.assertIn("fcntl.LOCK_EX", source)
        self.assertNotIn("down_migration", source)


def _descriptor(raw: bytes, media_type: str) -> dict[str, object]:
    return {"mediaType": media_type, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _oci_archive(path: Path, mutate=None) -> str:
    layers = [gzip.compress(b"base", mtime=0), gzip.compress(b"canary", mtime=0)]
    configuration = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "User": "10001:10001",
            "Entrypoint": ["/usr/bin/python", "/app/canary_runtime.py"],
            "Env": [
                f"CANARY_RELEASE_VERSION={VERSION}", f"CANARY_SOURCE_SHA={SOURCE_SHA}",
                "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1",
            ],
            "ExposedPorts": {"8080/tcp": {}},
            "Labels": {
                "org.opencontainers.image.title": REPOSITORY,
                "org.opencontainers.image.version": VERSION,
                "org.opencontainers.image.revision": SOURCE_SHA,
                "ai.omnilyzer.canary": "true",
                "ai.omnilyzer.base.digest": BASE_IMAGE_DIGEST,
            },
        },
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(x).hexdigest() for x in layers]},
    }
    if mutate is not None:
        mutate(configuration)
    config = (json.dumps(configuration, sort_keys=True, separators=(",", ":")) + "\n").encode()
    layer_descriptors = [_descriptor(raw, "application/vnd.oci.image.layer.v1.tar+gzip") for raw in layers]
    manifest = (json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": _descriptor(config, "application/vnd.oci.image.config.v1+json"),
        "layers": layer_descriptors,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest_descriptor = _descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    index = (json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [manifest_descriptor],
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}\n', "index.json": index}
    for raw in [config, manifest, *layers]:
        files[f"blobs/sha256/{hashlib.sha256(raw).hexdigest()}"] = raw
    with tarfile.open(path, "w") as archive:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return manifest_descriptor["digest"]


class ImageAndPipelineTests(unittest.TestCase):
    def test_dockerfile_is_digest_pinned_and_has_non_root_runtime_contract(self) -> None:
        dockerfile = (CANARY / "Dockerfile").read_text()
        self.assertEqual(BASE_IMAGE_DIGEST, "sha256:bbdc4d1e20995d9bb9f9935188844c824b40969de4bb1f0eaadacda4c8d4121e")
        self.assertEqual(dockerfile.splitlines()[0], f"FROM cgr.dev/chainguard/python@{BASE_IMAGE_DIGEST}")
        self.assertNotIn("cgr.dev/chainguard/python:", dockerfile)
        self.assertNotRegex(dockerfile, r"(?im)^\s*RUN\b")
        self.assertNotRegex(dockerfile, r"\b(apk|apt-get|bash|busybox|pip|gcc)\b")
        self.assertIn("COPY --chown=10001:10001", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("EXPOSE 8080", dockerfile)
        self.assertIn('ENTRYPOINT ["/usr/bin/python", "/app/canary_runtime.py"]', dockerfile)
        self.assertIn("CMD []", dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^FROM\s+[^\s@]+:[^\s@]+\s*$")

    def test_old_base_is_absent_only_from_active_configuration(self) -> None:
        old = "09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217"
        # Historical spikes record their actual validated base and are out of scope.
        for path in (CANARY / "Dockerfile", ROOT / "release/executable_oci.py",
                     ROOT / ".github/workflows/platform-release.yml"):
            self.assertNotIn(old, path.read_text())

    def test_verifier_rejects_unreviewed_runtime_and_base(self) -> None:
        cases = [
            ("User", "65532"),
            ("Entrypoint", ["python3", "/app/canary_runtime.py"]),
            ("Entrypoint", ["/usr/bin/python"]),
            ("Entrypoint", ["python", "/app/canary_runtime.py"]),
            ("Cmd", ["unexpected"]),
            ("ExposedPorts", {"8080/tcp": {}, "80/tcp": {}}),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "canary.tar"
                _oci_archive(archive, lambda c: c["config"].__setitem__(key, value))
                with self.assertRaises(ExecutableOCIError):
                    verify_executable_archive(archive, VERSION, SOURCE_SHA, REPOSITORY)
        for digest in ("sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217",
                       "sha256:" + "f" * 64):
            with self.subTest(digest=digest), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "canary.tar"
                _oci_archive(archive, lambda c: c["config"]["Labels"].__setitem__("ai.omnilyzer.base.digest", digest))
                with self.assertRaises(ExecutableOCIError):
                    verify_executable_archive(archive, VERSION, SOURCE_SHA, REPOSITORY)

    def test_identity_remains_fail_closed_without_shell_validation(self) -> None:
        for key in ("org.opencontainers.image.version", "org.opencontainers.image.revision",
                    "org.opencontainers.image.title"):
            for value in (None, "", "mismatched"):
                with self.subTest(label=key, value=value), tempfile.TemporaryDirectory() as directory:
                    archive = Path(directory) / "canary.tar"
                    def mutate(config):
                        labels = config["config"]["Labels"]
                        if value is None:
                            labels.pop(key)
                        else:
                            labels[key] = value
                    _oci_archive(archive, mutate)
                    with self.assertRaises(ExecutableOCIError):
                        verify_executable_archive(archive, VERSION, SOURCE_SHA, REPOSITORY)
        for key in ("CANARY_RELEASE_VERSION", "CANARY_SOURCE_SHA"):
            for value in (None, "", "mismatched"):
                with self.subTest(environment=key, value=value), tempfile.TemporaryDirectory() as directory:
                    archive = Path(directory) / "canary.tar"
                    def mutate(config):
                        env = config["config"]["Env"]
                        env[:] = [entry for entry in env if not entry.startswith(key + "=")]
                        if value is not None:
                            env.append(f"{key}={value}")
                    _oci_archive(archive, mutate)
                    with self.assertRaises(ExecutableOCIError):
                        verify_executable_archive(archive, VERSION, SOURCE_SHA, REPOSITORY)

    def test_final_oci_is_exact_digest_addressable_and_tamper_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "canary.oci.tar"
            expected = _oci_archive(archive)
            self.assertEqual(verify_executable_archive(archive, VERSION, SOURCE_SHA, REPOSITORY), expected)
            with self.assertRaises(ExecutableOCIError):
                verify_executable_archive(archive, "0.14.1", SOURCE_SHA, REPOSITORY)
            with self.assertRaises(ExecutableOCIError):
                verify_executable_archive(archive, VERSION, "f" * 40, REPOSITORY)
            with tarfile.open(archive, "a") as output:
                duplicate = tarfile.TarInfo("index.json")
                duplicate.size = 2
                output.addfile(duplicate, io.BytesIO(b"{}"))
            with self.assertRaises((ExecutableOCIError, tarfile.TarError)):
                verify_executable_archive(archive, VERSION, SOURCE_SHA, REPOSITORY)

    def test_workflow_builds_once_then_scans_final_oci_without_build_oidc(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/platform-release.yml").read_text())
        build = workflow["jobs"]["build"]
        self.assertEqual(build["permissions"], {"contents": "read"})
        self.assertNotIn("id-token", build["permissions"])
        steps = build["steps"]
        names = [step["name"] for step in steps]
        self.assertEqual(names.count("Build executable OCI canary exactly once"), 1)
        build_index = names.index("Build executable OCI canary exactly once")
        scan_index = names.index("Generate CycloneDX 1.6 SBOM and Grype evidence")
        self.assertLess(build_index, scan_index)
        scan = steps[scan_index]["run"]
        self.assertIn('syft scan "oci-archive:$oci_archive"', scan)
        self.assertIn('"$GRYPE_COMMAND" "sbom:$handoff/oci-sbom.cdx.json"', scan)

    def test_builder_actions_and_tools_are_immutable_or_version_pinned(self) -> None:
        raw = (ROOT / ".github/workflows/platform-release.yml").read_text()
        self.assertIn("docker/setup-buildx-action@e468171a9de216ec08956ac3ada2f0791b6bd435", raw)
        self.assertIn("docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83", raw)
        self.assertIn("version: v0.36.1", raw)
        self.assertIn("moby/buildkit:v0.24.0@sha256:6eceb8971ce4fceb3daca562832642706238b7eea72941fcf9896c93c3c4a53e", raw)

    def test_publishers_and_disabled_deployment_foundation_are_unchanged(self) -> None:
        for relative, expected in PROTECTED_HASHES.items():
            with self.subTest(relative=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)
        workflow = yaml.safe_load((ROOT / ".github/workflows/platform-release.yml").read_text())
        capable = [name for name, job in workflow["jobs"].items()
                   if job.get("permissions", {}).get("id-token") == "write"]
        self.assertEqual(capable, ["publish-zot", "publish-forgejo"])


if __name__ == "__main__":
    unittest.main()
