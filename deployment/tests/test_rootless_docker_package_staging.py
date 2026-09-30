"""deployment/tests/test_rootless_docker_package_staging.py - C32ZU tests.

Purpose:
- prove exact-network, private-file, resumable-prefix, locking, and atomic
  publication behavior without contacting package hosts or mutating the host;
- reject unreviewed payloads, redirects, unsafe partial files, unexpected
  directory entries, caller-selected paths, and cleanup shortcuts.

Linked file:
- deployment/rootless_docker_package_staging.py
"""

from dataclasses import FrozenInstanceError
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment.rootless_docker_installation_authority import (
    INSTALLATION_AUTHORITY,
    PackagePayloadAuthority,
)
from deployment import rootless_docker_package_staging as module


class _Response:
    """Minimal deterministic HTTPS response used by downloader tests."""

    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        length: str | None = None,
        encoding: str | None = None,
        transfer_encoding: str | None = None,
        content_range: str | None = None,
        location: str | None = None,
    ):
        self._payload = payload
        self._offset = 0
        self.status = status
        self._headers = {
            "Content-Length": str(len(payload)) if length is None else length,
            "Content-Encoding": encoding,
            "Transfer-Encoding": transfer_encoding,
            "Content-Range": content_range,
            "Location": location,
        }
        self.closed = False

    def getheader(self, name):
        """Return one fixed response header."""

        return self._headers.get(name)

    def read(self, size=-1):
        """Return bounded response bytes."""

        if self._offset >= len(self._payload):
            return b""
        if size is None or size < 0:
            size = len(self._payload) - self._offset
        end = min(len(self._payload), self._offset + size)
        result = self._payload[self._offset:end]
        self._offset = end
        return result

    def close(self):
        """Record response close."""

        self.closed = True


class _OverreadResponse(_Response):
    """Response that violates the requested read bound."""

    def read(self, size=-1):
        """Return one byte more than requested when possible."""

        if self._offset >= len(self._payload):
            return b""
        if size is None or size < 0:
            size = len(self._payload) - self._offset
        end = min(len(self._payload), self._offset + size + 1)
        result = self._payload[self._offset:end]
        self._offset = end
        return result


class _Connection:
    """Minimal deterministic HTTPS connection used by downloader tests."""

    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, path, headers):
        """Record the exact request shape."""

        self.requests.append((method, path, headers))

    def getresponse(self):
        """Return the prepared response."""

        return self.response

    def close(self):
        """Record connection close."""

        self.closed = True


def _fake_authority(content: bytes, root: Path):
    """Return a tiny authority compatible with staging helpers."""

    digest = hashlib.sha256(content).hexdigest()
    payload = PackagePayloadAuthority(
        "test-package",
        "test-package_1_amd64.deb",
        len(content),
        digest,
        "https://archive.ubuntu.com/ubuntu/test-package_1_amd64.deb",
    )
    authority = SimpleNamespace(
        payloads=(payload,),
        staged_package_mode=0o600,
        staging_directory_mode=0o700,
        staging_directory=str(root / ".rootless-docker-install"),
        bundle_size=lambda: len(content),
    )
    return authority, payload


class RootlessDockerPackageStagingTests(unittest.TestCase):
    """Focused adversarial tests for the C32ZU staging boundary."""

    def test_public_evidence_is_closed_and_immutable(self) -> None:
        value = module.RootlessDockerPackageStagingEvidence(
            INSTALLATION_AUTHORITY.staging_directory,
            INSTALLATION_AUTHORITY.bundle_size(),
            tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads),
        )
        with self.assertRaises(FrozenInstanceError):
            value.total_size = 1
        with self.assertRaises(ValueError):
            module.RootlessDockerPackageStagingEvidence(
                INSTALLATION_AUTHORITY.staging_directory,
                1,
                value.sha256s,
            )

    def test_downloader_uses_exact_https_request_without_redirect_or_proxy(self) -> None:
        payload = INSTALLATION_AUTHORITY.payloads[0]
        body = b"x" * payload.size
        response = _Response(body)
        connection = _Connection(response)
        context = SimpleNamespace(minimum_version=None)
        with tempfile.TemporaryFile() as target, patch.object(
            module.ssl, "create_default_context", return_value=context,
        ) as context_factory, patch.object(
            module.http.client,
            "HTTPSConnection",
            return_value=connection,
        ) as constructor:
            module._download_payload(payload, target.fileno())
            target.seek(0)
            self.assertEqual(target.read(), body)

        context_factory.assert_called_once_with(
            cafile="/etc/ssl/certs/ca-certificates.crt"
        )
        constructor.assert_called_once_with(
            "archive.ubuntu.com",
            443,
            timeout=30.0,
            context=context,
        )
        self.assertEqual(len(connection.requests), 1)
        method, path, headers = connection.requests[0]
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/ubuntu/pool/main/s/shadow/libsubid4_4.13%2bdfsg1-4ubuntu3.2_amd64.deb")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["Connection"], "close")
        self.assertEqual(headers["User-Agent"], "Omnilyzer-C32ZU/1")
        self.assertTrue(response.closed)
        self.assertTrue(connection.closed)

    def test_downloader_rejects_status_length_encoding_and_location(self) -> None:
        payload = INSTALLATION_AUTHORITY.payloads[0]
        body = b"x" * payload.size
        cases = (
            _Response(body, status=302, location="https://example.com/elsewhere"),
            _Response(body, length=str(payload.size + 1)),
            _Response(body, encoding="gzip"),
            _Response(body, transfer_encoding="chunked"),
            _Response(body, content_range="bytes 0-1/2"),
        )
        for response in cases:
            connection = _Connection(response)
            context = SimpleNamespace(minimum_version=None)
            with self.subTest(status=response.status), tempfile.TemporaryFile() as target,                     patch.object(
                        module.ssl,
                        "create_default_context",
                        return_value=context,
                    ), patch.object(
                        module.http.client,
                        "HTTPSConnection",
                        return_value=connection,
                    ), self.assertRaises(OSError):
                module._download_payload(payload, target.fileno())

    def test_downloader_rejects_response_overread_before_write(self) -> None:
        payload = INSTALLATION_AUTHORITY.payloads[0]
        body = b"x" * (payload.size + 1)
        response = _OverreadResponse(body, length=str(payload.size))
        connection = _Connection(response)
        context = SimpleNamespace(minimum_version=None)
        with tempfile.TemporaryFile() as target, patch.object(
            module.ssl, "create_default_context", return_value=context,
        ), patch.object(
            module.http.client,
            "HTTPSConnection",
            return_value=connection,
        ), self.assertRaises(OSError):
            module._download_payload(payload, target.fileno())
            target.seek(0)
            self.assertEqual(target.read(), b"")

    def test_downloader_rejects_unreviewed_payload(self) -> None:
        forged = PackagePayloadAuthority(
            "forged",
            "forged_1_amd64.deb",
            1,
            "a" * 64,
            "https://archive.ubuntu.com/ubuntu/forged_1_amd64.deb",
        )
        with tempfile.TemporaryFile() as target, self.assertRaises(OSError):
            module._download_payload(forged, target.fileno())

    def test_exact_existing_payload_is_reused_without_network(self) -> None:
        content = b"reviewed payload"
        with tempfile.TemporaryDirectory(prefix="c32zu-stage-") as temporary:
            root = Path(temporary)
            authority, payload = _fake_authority(content, root)
            package_path = root / payload.filename
            package_path.write_bytes(content)
            package_path.chmod(0o600)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    module, "INSTALLATION_AUTHORITY", authority,
                ), patch.object(
                    module, "_ROOT_UID", os.getuid(),
                ), patch.object(
                    module, "_ROOT_GID", os.getgid(),
                ), patch.object(
                    module, "_download_payload",
                    side_effect=AssertionError("network"),
                ):
                    self.assertFalse(module._stage_payload(directory, payload))
            finally:
                os.close(directory)

    def test_safe_partial_payload_is_rewritten_and_resumable(self) -> None:
        content = b"complete reviewed payload"
        with tempfile.TemporaryDirectory(prefix="c32zu-stage-") as temporary:
            root = Path(temporary)
            authority, payload = _fake_authority(content, root)
            package_path = root / payload.filename
            package_path.write_bytes(content[:7])
            package_path.chmod(0o600)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)

            def download(_payload, descriptor):
                self.assertEqual(_payload, payload)
                module._write_all(descriptor, content)

            try:
                with patch.object(
                    module, "INSTALLATION_AUTHORITY", authority,
                ), patch.object(
                    module, "_ROOT_UID", os.getuid(),
                ), patch.object(
                    module, "_ROOT_GID", os.getgid(),
                ), patch.object(
                    module, "_download_payload", side_effect=download,
                ):
                    self.assertTrue(module._stage_payload(directory, payload))
            finally:
                os.close(directory)
            self.assertEqual(package_path.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(package_path.stat().st_mode), 0o600)

    def test_unsafe_existing_payload_is_never_repaired(self) -> None:
        content = b"reviewed payload"
        with tempfile.TemporaryDirectory(prefix="c32zu-stage-") as temporary:
            root = Path(temporary)
            authority, payload = _fake_authority(content, root)
            package_path = root / payload.filename
            package_path.write_bytes(content[:3])
            package_path.chmod(0o644)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    module, "INSTALLATION_AUTHORITY", authority,
                ), patch.object(
                    module, "_ROOT_UID", os.getuid(),
                ), patch.object(
                    module, "_ROOT_GID", os.getgid(),
                ), self.assertRaises(OSError):
                    module._stage_payload(directory, payload)
            finally:
                os.close(directory)
            self.assertEqual(stat.S_IMODE(package_path.stat().st_mode), 0o644)
            self.assertEqual(package_path.read_bytes(), content[:3])

    def test_existing_incoming_directory_wrong_mode_fails_without_repair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="c32zu-parent-") as temporary:
            parent = Path(temporary)
            incoming = parent / module._INCOMING_NAME
            incoming.mkdir(mode=0o755)
            incoming.chmod(0o755)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    module, "_ROOT_UID", os.getuid(),
                ), patch.object(
                    module, "_ROOT_GID", os.getgid(),
                ), self.assertRaises(OSError):
                    module._open_incoming(descriptor)
            finally:
                os.close(descriptor)
            self.assertEqual(stat.S_IMODE(incoming.stat().st_mode), 0o755)

    def test_unexpected_incoming_entry_fails_without_network_or_cleanup(self) -> None:
        content = b"reviewed payload"
        with tempfile.TemporaryDirectory(prefix="c32zu-parent-") as temporary:
            parent = Path(temporary)
            incoming = parent / module._INCOMING_NAME
            incoming.mkdir(mode=0o700)
            incoming.chmod(0o700)
            extra = incoming / "unexpected"
            extra.write_bytes(b"x")
            extra.chmod(0o600)
            authority, _payload = _fake_authority(content, parent)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    module, "INSTALLATION_AUTHORITY", authority,
                ), patch.object(
                    module, "_ROOT_UID", os.getuid(),
                ), patch.object(
                    module, "_ROOT_GID", os.getgid(),
                ), patch.object(
                    module, "_stage_payload",
                    side_effect=AssertionError("network-or-write"),
                ), self.assertRaises(OSError):
                    module._stage_incoming(descriptor, tuple())
            finally:
                os.close(descriptor)
            self.assertTrue(extra.is_file())
            self.assertEqual(extra.read_bytes(), b"x")

    def test_atomic_publish_never_replaces_existing_final_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="c32zu-rename-") as temporary:
            parent = Path(temporary)
            incoming = parent / module._INCOMING_NAME
            final = parent / module._FINAL_NAME
            incoming.mkdir()
            final.mkdir()
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError):
                    module._rename_incoming_noreplace(descriptor)
            finally:
                os.close(descriptor)
            self.assertTrue(incoming.is_dir())
            self.assertTrue(final.is_dir())

    def test_public_operation_holds_privileged_process_lock(self) -> None:
        expected = module.RootlessDockerPackageStagingEvidence(
            INSTALLATION_AUTHORITY.staging_directory,
            INSTALLATION_AUTHORITY.bundle_size(),
            tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads),
        )
        bundle = SimpleNamespace()
        token = object()
        chain = tuple()
        with patch.object(
            module, "_root_identity", return_value=(0, 0, 0, 0),
        ), patch.object(
            module.orchestration,
            "_acquire_process_lock",
            return_value=token,
        ) as acquire, patch.object(
            module, "_open_parent", return_value=(77, chain),
        ), patch.object(
            module, "_final_exists", return_value=True,
        ), patch.object(
            module, "_named_exists", return_value=False,
        ), patch.object(
            module,
            "qualify_rootless_docker_package_bundle",
            return_value=bundle,
        ), patch.object(
            module, "_result_from_bundle", return_value=expected,
        ), patch.object(
            module.os, "close",
        ), patch.object(
            module.orchestration, "_release_process_lock",
        ) as release:
            self.assertEqual(
                module.stage_rootless_docker_package_bundle(),
                expected,
            )
        acquire.assert_called_once_with()
        release.assert_called_once_with(token)

    def test_root_identity_is_required_before_lock_or_network(self) -> None:
        with patch.object(
            module, "_root_identity", side_effect=OSError,
        ), patch.object(
            module.orchestration, "_acquire_process_lock",
        ) as acquire, self.assertRaises(
            module.RootlessDockerPackageStagingError,
        ):
            module.stage_rootless_docker_package_bundle()
        acquire.assert_not_called()

    def test_lock_release_failure_fails_closed(self) -> None:
        expected = module.RootlessDockerPackageStagingEvidence(
            INSTALLATION_AUTHORITY.staging_directory,
            INSTALLATION_AUTHORITY.bundle_size(),
            tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads),
        )
        token = object()
        with patch.object(
            module, "_root_identity", return_value=(0, 0, 0, 0),
        ), patch.object(
            module.orchestration, "_acquire_process_lock", return_value=token,
        ), patch.object(
            module, "_open_parent", return_value=(77, tuple()),
        ), patch.object(
            module, "_final_exists", return_value=True,
        ), patch.object(
            module, "_named_exists", return_value=False,
        ), patch.object(
            module, "qualify_rootless_docker_package_bundle",
            return_value=SimpleNamespace(),
        ), patch.object(
            module, "_result_from_bundle", return_value=expected,
        ), patch.object(
            module.os, "close",
        ), patch.object(
            module.orchestration, "_release_process_lock", side_effect=OSError,
        ), self.assertRaises(module.RootlessDockerPackageStagingError):
            module.stage_rootless_docker_package_bundle()

    def test_new_bundle_requires_stable_preinstall_before_publication(self) -> None:
        expected = module.RootlessDockerPackageStagingEvidence(
            INSTALLATION_AUTHORITY.staging_directory,
            INSTALLATION_AUTHORITY.bundle_size(),
            tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads),
        )
        before = object()
        bundle = SimpleNamespace()
        token = object()
        with patch.object(
            module, "_root_identity", return_value=(0, 0, 0, 0),
        ), patch.object(
            module.orchestration, "_acquire_process_lock", return_value=token,
        ), patch.object(
            module, "_open_parent", return_value=(77, tuple()),
        ), patch.object(
            module, "_final_exists", return_value=False,
        ), patch.object(
            module, "qualify_rootless_docker_preinstall",
            side_effect=(before, before),
        ) as preflight, patch.object(
            module, "_stage_incoming", return_value=("one",),
        ) as stage, patch.object(
            module, "_publish",
        ) as publish, patch.object(
            module,
            "qualify_rootless_docker_package_bundle",
            return_value=bundle,
        ), patch.object(
            module, "_result_from_bundle", return_value=expected,
        ), patch.object(
            module.os, "close",
        ), patch.object(
            module.orchestration, "_release_process_lock",
        ):
            self.assertEqual(
                module.stage_rootless_docker_package_bundle(),
                expected,
            )
        self.assertEqual(preflight.call_count, 2)
        stage.assert_called_once_with(77, tuple())
        publish.assert_called_once_with(77, tuple())

    def test_preinstall_drift_prevents_publication(self) -> None:
        token = object()
        with patch.object(
            module, "_root_identity", return_value=(0, 0, 0, 0),
        ), patch.object(
            module.orchestration, "_acquire_process_lock", return_value=token,
        ), patch.object(
            module, "_open_parent", return_value=(77, tuple()),
        ), patch.object(
            module, "_final_exists", return_value=False,
        ), patch.object(
            module, "qualify_rootless_docker_preinstall",
            side_effect=(object(), object()),
        ), patch.object(
            module, "_stage_incoming", return_value=(),
        ), patch.object(
            module, "_publish",
        ) as publish, patch.object(
            module.os, "close",
        ), patch.object(
            module.orchestration, "_release_process_lock",
        ), self.assertRaises(module.RootlessDockerPackageStagingError):
            module.stage_rootless_docker_package_bundle()
        publish.assert_not_called()

    def test_public_boundary_has_no_caller_inputs_or_cleanup_shortcuts(self) -> None:
        import inspect

        self.assertEqual(
            tuple(
                inspect.signature(
                    module.stage_rootless_docker_package_bundle
                ).parameters
            ),
            (),
        )
        source = Path(module.__file__).read_text()
        for forbidden in (
            "subprocess",
            "os.unlink",
            "os.remove",
            "shutil.rmtree",
            "shell=True",
            "requests.",
            "urllib.request",
            "http_proxy",
            "https_proxy",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
