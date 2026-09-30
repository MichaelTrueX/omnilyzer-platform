"""deployment/tests/test_rootless_docker_package_bundle_qualification.py.

Purpose:
- prove C32ZS qualifies only an exact private package bundle and performs no
  mutation or network activity;
- exercise exact entry sets, metadata, hashing, stable revalidation, and the
  fixed root-only public boundary.

Linked files:
- deployment/rootless_docker_package_bundle_qualification.py
- deployment/rootless_docker_installation_authority.py
"""

from dataclasses import FrozenInstanceError, fields
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

from deployment import rootless_docker_package_bundle_qualification as module
from deployment.rootless_docker_installation_authority import (
    INSTALLATION_AUTHORITY,
    PackagePayloadAuthority,
)


ROOT = Path(__file__).resolve().parents[2]


class _SyntheticAuthority:
    """Small exact authority used to exercise real filesystem mechanics."""

    def __init__(self, path: str, payloads: tuple[PackagePayloadAuthority, ...]):
        self.staging_directory = path
        self.staging_directory_mode = 0o700
        self.staged_package_mode = 0o600
        self.payloads = payloads

    def bundle_size(self) -> int:
        """Return the exact synthetic bundle size."""

        return sum(item.size for item in self.payloads)


def _payload(name: str, filename: str, content: bytes) -> PackagePayloadAuthority:
    """Create one small payload that still passes the production URL model."""

    return PackagePayloadAuthority(
        name,
        filename,
        len(content),
        hashlib.sha256(content).hexdigest(),
        "https://archive.ubuntu.com/ubuntu/" + filename,
    )


class RootlessDockerPackageBundleQualificationTests(unittest.TestCase):
    """Adversarial tests for the exact staged-package qualifier."""

    def _fixture(self):
        """Create a private two-file bundle owned by the current test identity."""

        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name)
        os.chmod(path, 0o700)
        contents = {
            "alpha.deb": b"alpha-package-bytes",
            "beta.deb": b"beta-package-bytes",
        }
        payloads = (
            _payload("alpha", "alpha.deb", contents["alpha.deb"]),
            _payload("beta", "beta.deb", contents["beta.deb"]),
        )
        for filename, raw in contents.items():
            target = path / filename
            target.write_bytes(raw)
            os.chmod(target, 0o600)
        return temporary, path, contents, _SyntheticAuthority(str(path), payloads)

    def test_real_filesystem_exact_bundle_qualifies(self) -> None:
        temporary, path, _contents, authority = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch.object(module, "INSTALLATION_AUTHORITY", authority), \
                patch.object(module, "_ROOT_UID", os.getuid()), \
                patch.object(module, "_ROOT_GID", os.getgid()):
            evidence = module._qualify_at(
                str(path),
                uid=os.getuid(),
                gid=os.getgid(),
            )
        self.assertEqual(evidence.staging_directory, str(path))
        self.assertEqual(evidence.digest_algorithm, "sha256")
        self.assertEqual(evidence.total_size, authority.bundle_size())
        self.assertEqual(
            tuple(item.package for item in evidence.files),
            ("alpha", "beta"),
        )

    def test_extra_entry_wrong_mode_and_digest_fail_closed(self) -> None:
        for mutation in ("extra", "mode", "digest"):
            temporary, path, contents, authority = self._fixture()
            self.addCleanup(temporary.cleanup)
            if mutation == "extra":
                extra = path / "extra"
                extra.write_bytes(b"x")
                os.chmod(extra, 0o600)
            elif mutation == "mode":
                os.chmod(path / "alpha.deb", 0o644)
            else:
                (path / "alpha.deb").write_bytes(b"x" * len(contents["alpha.deb"]))
            with self.subTest(mutation=mutation), patch.object(
                module,
                "INSTALLATION_AUTHORITY",
                authority,
            ), patch.object(module, "_ROOT_UID", os.getuid()), patch.object(
                module, "_ROOT_GID", os.getgid(),
            ), self.assertRaises(OSError):
                module._qualify_at(
                    str(path),
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            temporary.cleanup()

    def test_symlink_parent_component_is_rejected(self) -> None:
        temporary, path, _contents, authority = self._fixture()
        self.addCleanup(temporary.cleanup)
        wrapper = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: wrapper.rmdir() if wrapper.exists() else None)
        link = wrapper / "bundle-link"
        link.symlink_to(path)
        linked_authority = _SyntheticAuthority(str(link), authority.payloads)
        with patch.object(module, "INSTALLATION_AUTHORITY", linked_authority), \
                patch.object(module, "_ROOT_UID", os.getuid()), \
                patch.object(module, "_ROOT_GID", os.getgid()), \
                self.assertRaises(OSError):
            module._qualify_at(
                str(link),
                uid=os.getuid(),
                gid=os.getgid(),
            )
        link.unlink()

    def test_symlink_payload_is_rejected(self) -> None:
        temporary, path, _contents, authority = self._fixture()
        self.addCleanup(temporary.cleanup)
        target = path / "alpha.deb"
        target.unlink()
        target.symlink_to(path / "beta.deb")
        with patch.object(module, "INSTALLATION_AUTHORITY", authority), \
                patch.object(module, "_ROOT_UID", os.getuid()), \
                patch.object(module, "_ROOT_GID", os.getgid()), \
                self.assertRaises(OSError):
            module._qualify_at(
                str(path),
                uid=os.getuid(),
                gid=os.getgid(),
            )

    def test_evidence_is_exact_and_immutable(self) -> None:
        payload = INSTALLATION_AUTHORITY.payloads[0]
        fingerprint = (
            0o100600,
            1,
            2,
            1,
            0,
            0,
            payload.size,
            3,
            4,
        )
        file_evidence = module.PackageBundleFileEvidence(
            payload.package,
            payload.filename,
            payload.size,
            payload.sha256,
            fingerprint,
        )
        with self.assertRaises(FrozenInstanceError):
            file_evidence.size = 1
        values = {
            item.name: getattr(file_evidence, item.name)
            for item in fields(file_evidence)
        }
        for field, bad in (
            ("filename", "other.deb"),
            ("size", payload.size + 1),
            ("sha256", "0" * 64),
            ("fingerprint", fingerprint[:-1]),
            (
                "fingerprint",
                fingerprint[:4] + (1,) + fingerprint[5:],
            ),
            (
                "fingerprint",
                (0o100644,) + fingerprint[1:],
            ),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.PackageBundleFileEvidence(**(values | {field: bad}))

    def test_bundle_evidence_rejects_nonprivate_directory_fingerprint(self) -> None:
        payloads = INSTALLATION_AUTHORITY.payloads
        file_evidence = tuple(
            module.PackageBundleFileEvidence(
                item.package,
                item.filename,
                item.size,
                item.sha256,
                (
                    0o100600,
                    index + 1,
                    10,
                    1,
                    0,
                    0,
                    item.size,
                    100 + index,
                    200 + index,
                ),
            )
            for index, item in enumerate(payloads)
        )
        with self.assertRaises(ValueError):
            module.RootlessDockerPackageBundleEvidence(
                INSTALLATION_AUTHORITY.staging_directory,
                "sha256",
                INSTALLATION_AUTHORITY.bundle_size(),
                (0o40755, 99, 10, 2, 0, 0, 0, 300, 400),
                file_evidence,
            )

    def test_public_boundary_is_fixed_root_only_and_double_observed(self) -> None:
        payloads = INSTALLATION_AUTHORITY.payloads
        file_evidence = tuple(
            module.PackageBundleFileEvidence(
                item.package,
                item.filename,
                item.size,
                item.sha256,
                (
                    0o100600,
                    index + 1,
                    10,
                    1,
                    0,
                    0,
                    item.size,
                    100 + index,
                    200 + index,
                ),
            )
            for index, item in enumerate(payloads)
        )
        evidence = module.RootlessDockerPackageBundleEvidence(
            INSTALLATION_AUTHORITY.staging_directory,
            "sha256",
            INSTALLATION_AUTHORITY.bundle_size(),
            (0o40700, 99, 10, 2, 0, 0, 0, 300, 400),
            file_evidence,
        )
        with patch.object(
            module,
            "_root_identity",
            return_value=(0, 0, 0, 0),
        ) as identity, patch.object(
            module,
            "_qualify_at",
            return_value=evidence,
        ) as qualify:
            self.assertEqual(
                module.qualify_rootless_docker_package_bundle(),
                evidence,
            )
        self.assertEqual(identity.call_count, 3)
        self.assertEqual(
            qualify.call_args_list,
            [
                call(
                    INSTALLATION_AUTHORITY.staging_directory,
                    uid=0,
                    gid=0,
                ),
                call(
                    INSTALLATION_AUTHORITY.staging_directory,
                    uid=0,
                    gid=0,
                ),
            ],
        )

    def test_public_boundary_collapses_operational_failure(self) -> None:
        with patch.object(
            module,
            "_root_identity",
            side_effect=OSError("private"),
        ), self.assertRaises(
            module.RootlessDockerPackageBundleQualificationError,
        ) as caught:
            module.qualify_rootless_docker_package_bundle()
        self.assertEqual(
            str(caught.exception),
            "rootless Docker package bundle qualification is unavailable",
        )
        self.assertNotIn("private", str(caught.exception))

    def test_module_has_no_network_or_mutation_surface(self) -> None:
        source = (
            ROOT / "deployment/rootless_docker_package_bundle_qualification.py"
        ).read_text()
        for forbidden in (
            "subprocess",
            "urllib",
            "requests",
            "socket.",
            "http.",
            "https.",
            "O_WRONLY",
            "O_CREAT",
            "mkdir",
            "makedirs",
            "unlink",
            "remove",
            "rename",
            "replace(",
            "chmod",
            "chown",
            "__main__",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
