"""File: deployment/tests/test_c34s_signed_python_provenance.py

Purpose: Independently replay C27 signed Ubuntu package-to-installed-byte
provenance by reusing C29's closed 658-entry payload qualification.
Related: deployment/python_interpreter_provenance.py,
deployment/dev_host_qualification.py,
deployment/c34r_installed_python_observation.py,
deployment/provenance/python3.12-3.12.3-1ubuntu0.17-amd64-payload.json,
docs/operations/task014-c34s-signed-python-provenance.md.

The full read-only host audit requires four already-downloaded, SHA-pinned
Ubuntu .deb archives plus Packages.xz in a private directory. The normal CI
suite runs the offline/negative tests without network or host qualification.
Neither mode installs software, modifies protected files or authorizes root.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import lzma
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deployment import c34r_installed_python_observation as c34r
from deployment import dev_host_qualification as c29
from deployment import python_interpreter_provenance as c27

_ROOT = Path(__file__).resolve().parents[2]
_PROVENANCE = c27.DevPythonInterpreterProvenance()
_ARCHIVE_VARIABLE = "OMNILYZER_C34S_ARCHIVE_DIR"


# Section 1: Exact signed package-index and package-record comparisons.
def _digest_match(data: bytes, sha256: str, size: int) -> bool:
    """Compare exact signed artifact length and SHA-256 without trusting names."""
    return type(data) is bytes and len(data) == size and (
        hashlib.sha256(data).hexdigest() == sha256
    )


def _signed_index_record(inrelease: bytes, name: str) -> tuple[str, int]:
    """Select a unique SHA256 entry from the signed InRelease checksum section."""
    body = inrelease.decode("utf-8")
    if body.count("\nSHA256:\n") != 1:
        raise ValueError("signed index unavailable")
    section = body.split("\nSHA256:\n", 1)[1].split("\nSHA512:\n", 1)[0]
    matches = [
        (digest, int(size))
        for digest, size, path in re.findall(
            r"^ ([0-9a-f]{64})\s+([0-9]+) (\S+)$", section, re.MULTILINE,
        )
        if path == name
    ]
    if len(matches) != 1:
        raise ValueError("signed index unavailable")
    return matches[0]


def _package_records(packages: bytes) -> dict[str, tuple[str, str, str, int, str]]:
    """Require one exact C27 entry per named archive inside verified Packages."""
    records: dict[str, tuple[str, str, str, int, str]] = {}
    required = {package.package: package for package in _PROVENANCE.packages}
    for paragraph in packages.decode("utf-8").split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if line.startswith(" "):
                continue
            if ": " in line:
                key, value = line.split(": ", 1)
                if key in fields:
                    raise ValueError("duplicate package field")
                fields[key] = value
        name = fields.get("Package")
        if name not in required:
            continue
        reviewed = required[name]
        if fields.get("Version") != reviewed.version or (
            fields.get("Architecture") != reviewed.architecture
        ):
            continue
        if name in records:
            raise ValueError("duplicate reviewed package")
        values = (
            fields.get("Version", ""),
            fields.get("Architecture", ""),
            fields.get("Filename", ""),
            int(fields.get("Size", "0")),
            fields.get("SHA256", ""),
        )
        expected = (
            reviewed.version, reviewed.architecture, reviewed.filename,
            reviewed.size, reviewed.sha256,
        )
        if values != expected:
            raise ValueError("wrong signed package record")
        records[name] = values
    if set(records) != set(required):
        raise ValueError("missing signed package")
    return records


# Section 2: Exact Debian payload comparison; never extract archives to disk.
def _tar_payload(deb_path: Path) -> dict[str, tuple[object, ...]]:
    """Inspect a SHA-verified Debian archive without installation or extraction."""
    completed = subprocess.run(
        ("/usr/bin/dpkg-deb", "--fsys-tarfile", str(deb_path)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False, check=True, timeout=25,
    )
    records: dict[str, tuple[object, ...]] = {}
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:*") as archive:
        for item in archive:
            if item.isdir():
                continue
            path = "/" + item.name.removeprefix("./").lstrip("/")
            if (path == "/" or "/../" in path or "/./" in path
                    or path in records):
                raise ValueError("noncanonical archive path")
            if item.isfile():
                opened = archive.extractfile(item)
                if opened is None:
                    raise ValueError("missing payload bytes")
                with opened:
                    data = opened.read()
                evidence = (
                    "regular_file", item.mode, item.uid, item.gid, len(data),
                    hashlib.sha256(data).hexdigest(), None,
                )
            elif item.issym():
                evidence = (
                    "symbolic_link", item.mode, item.uid, item.gid,
                    None, None, item.linkname,
                )
            else:
                raise ValueError("unexpected Debian payload entry")
            records[path] = evidence
    return records


def _expected_payload(entries: tuple[dict, ...], package: str) -> dict[str, tuple[object, ...]]:
    """Reuse the pinned C29 manifest without introducing another trust anchor."""
    return {
        item.path: (
            item.kind, item.mode, item.owner_uid, item.group_gid,
            item.size, item.sha256, item.target,
        )
        for wrapped in entries
        for item in (wrapped["observation"],)
        if item.package == package
    }


# Section 3: CI-safe negative tests on existing security contracts.
class SignedPythonProvenanceContracts(unittest.TestCase):
    """Detect forged or mismatched signed/installed evidence without network."""

    def test_a_retained_metadata_and_signed_checksums_agree(self) -> None:
        """The existing trusted C27/C29 records must agree exactly."""
        index = _PROVENANCE.packages_index
        release = (
            _ROOT / index.repository_inrelease_path
        ).read_bytes()
        self.assertTrue(_digest_match(
            release, index.inrelease_sha256, index.inrelease_size,
        ))
        for path, sha256, size in (
            (index.packages_path, index.packages_sha256, index.packages_size),
            (index.compressed_packages_path,
             index.compressed_packages_sha256, index.compressed_packages_size),
        ):
            self.assertEqual(_signed_index_record(release, path), (sha256, size))
        entries = c29._load_payload(_PROVENANCE)
        self.assertEqual(len(entries), 658)
        self.assertEqual(
            sum(e["observation"].path.endswith(".so") for e in entries), 46,
        )
        self.assertEqual(
            sum(e["observation"].kind == "regular_file" for e in entries), 651,
        )

    def test_b_changed_signed_package_bytes_rejected(self) -> None:
        """Even an identically sized archive with different bytes must fail."""
        index = _PROVENANCE.packages_index
        self.assertFalse(_digest_match(
            b"x" * index.compressed_packages_size,
            index.compressed_packages_sha256,
            index.compressed_packages_size,
        ))

    def test_c_forged_signer_section_rejected(self) -> None:
        """Malformed and duplicate signed index entries cannot be accepted."""
        index = _PROVENANCE.packages_index
        with self.assertRaises(ValueError):
            _signed_index_record(b"not an InRelease", index.packages_path)
        text = (
            "\nSHA256:\n " + index.packages_sha256 + " " +
            str(index.packages_size) + " " + index.packages_path + "\n"
        ).encode()
        with self.assertRaises(ValueError):
            _signed_index_record(text + text, index.packages_path)

    def test_d_mismatched_package_record_rejected(self) -> None:
        """Reject incorrect versions, archive checksums, and missing packages."""
        reviewed = _PROVENANCE.packages[0]
        stanza = (
            f"Package: {reviewed.package}\nVersion: wrong\nArchitecture: amd64\n"
            f"Filename: {reviewed.filename}\nSize: {reviewed.size}\n"
            f"SHA256: {reviewed.sha256}\n"
        )
        with self.assertRaises(ValueError):
            _package_records(stanza.encode())

    def test_e_modified_manifest_digest_rejected(self) -> None:
        """The retained installed payload cannot substitute another file list."""
        with patch.object(c29, "_PAYLOAD_SHA256", "0" * 64):
            with self.assertRaises(OSError):
                c29._load_payload(_PROVENANCE)

    def test_f_mismatched_native_library_rejected(self) -> None:
        """C29 detects a modified extension, not just a changed interpreter."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "_ssl.cpython-312-x86_64-linux-gnu.so"
            target.write_bytes(b"original module")
            target.chmod(0o755)
            st = target.stat()
            record = c29.HostPayloadFileObservation(
                "libpython3.12-stdlib", str(target), "regular_file",
                0o755, st.st_uid, st.st_gid, st.st_size,
                hashlib.sha256(b"original module").hexdigest(), None,
            )
            self.assertEqual(
                c29._observe_payload(({"observation": record},)), (record,),
            )
            target.write_bytes(b"modified module")
            with self.assertRaises(OSError):
                c29._observe_payload(({"observation": record},))

    def test_g_wrong_interpreter_hash_rejected(self) -> None:
        """An interpreter must match the C27 payload, not an observed-only hash."""
        entries = c29._load_payload(_PROVENANCE)
        installed = next(
            e["observation"] for e in entries
            if e["observation"].path == "/usr/bin/python3.12"
        )
        self.assertEqual(installed.sha256,
                         "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
        self.assertFalse(_digest_match(b"not python", installed.sha256, installed.size))

    def test_h_forged_root_approval_rejected(self) -> None:
        """Even a structurally valid receipt rejects every forged root gate."""
        observed = next(
            e["observation"] for e in c29._load_payload(_PROVENANCE)
            if e["observation"].path == "/usr/bin/python3.12"
        )
        original = c34r.C34RInstalledRuntimeReceipt(
            candidate_commit="a" * 40,
            source_manifest_sha256="b" * 64,
            populated_venv_manifest_sha256=c34r.environment._MANIFEST_SHA256,
            verified_regular_files=c34r.environment._FILE_COUNT,
            verified_directories=c34r.environment._DIRECTORY_COUNT,
            verified_symlinks=c34r.environment._SYMLINK_COUNT,
            interpreter=c34r.C34RInterpreterWitness(
                observed.path, observed.sha256, observed.size,
            ),
            installed_venv_tree_verified=True,
        )
        self.assertFalse(original.root_execution_approved)
        for flag in (
            "root_execution_approved", "interpreter_package_approved",
            "installed_executor_config_verified",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(original, **{flag: True})


# Section 4: Optional actual-host independent signature->deb->payload replay.
@unittest.skipUnless(os.environ.get(_ARCHIVE_VARIABLE), "offline archive directory not supplied")
class ActualHostSignedPackageAudit(unittest.TestCase):
    """Run only on an explicitly staged, nonprivileged artifact directory."""

    def test_signed_ubuntu_archives_match_all_installed_payload_bytes(self) -> None:
        """Verify complete independent signature-to-installed-package chain."""
        directory = Path(os.environ[_ARCHIVE_VARIABLE]).resolve(strict=True)
        if not directory.is_dir() or directory.stat().st_mode & 0o077:
            self.fail("staged artifact directory must be private")
        index = _PROVENANCE.packages_index
        key = _PROVENANCE.archive_key
        release = _ROOT / index.repository_inrelease_path
        key_file = _ROOT / key.repository_path
        if not _digest_match(release.read_bytes(), index.inrelease_sha256, index.inrelease_size):
            self.fail("reviewed release bytes mismatch")
        if not _digest_match(key_file.read_bytes(), key.sha256, key.size):
            self.fail("reviewed archive key bytes mismatch")
        with tempfile.TemporaryDirectory() as scratch:
            ring = Path(scratch) / "archive.gpg"
            subprocess.run(
                ("/usr/bin/gpg", "--batch", "--dearmor", "--output", str(ring),
                 str(key_file)),
                stdin=subprocess.DEVNULL, capture_output=True, check=True,
                timeout=10,
            )
            verified = subprocess.run(
                ("/usr/bin/gpgv", "--status-fd", "1", "--keyring", str(ring),
                 str(release)),
                stdin=subprocess.DEVNULL, capture_output=True, check=True,
                timeout=10,
            )
            self.assertIn(
                (b"[GNUPG:] VALIDSIG " + key.fingerprint.encode() + b" "),
                verified.stdout,
            )

        compressed = (directory / "Packages.xz").read_bytes()
        self.assertTrue(_digest_match(
            compressed, index.compressed_packages_sha256,
            index.compressed_packages_size,
        ))
        self.assertEqual(
            _signed_index_record(release.read_bytes(), index.compressed_packages_path),
            (index.compressed_packages_sha256, index.compressed_packages_size),
        )
        plain = lzma.decompress(compressed)
        self.assertTrue(_digest_match(
            plain, index.packages_sha256, index.packages_size,
        ))
        self.assertEqual(
            _signed_index_record(release.read_bytes(), index.packages_path),
            (index.packages_sha256, index.packages_size),
        )
        self.assertEqual(len(_package_records(plain)), 4)

        expected = c29._load_payload(_PROVENANCE)
        self.assertEqual(len(expected), 658)
        for package in _PROVENANCE.packages:
            artifact = directory / Path(package.filename).name
            self.assertTrue(_digest_match(
                artifact.read_bytes(), package.sha256, package.size,
            ), package.package)
            self.assertEqual(
                _tar_payload(artifact),
                _expected_payload(expected, package.package),
                package.package,
            )

        before = c34r._read_system_interpreter_witness()
        packages_before = c29._query_packages(_PROVENANCE)
        installed = c29._observe_payload(expected)
        packages_after = c29._query_packages(_PROVENANCE)
        after = c34r._read_system_interpreter_witness()
        self.assertEqual(packages_before, packages_after)
        self.assertEqual(len(installed), 658)
        self.assertEqual(before, after)
        interpreter = next(item for item in installed if item.path == before.path)
        self.assertEqual((interpreter.sha256, interpreter.size),
                         (after.sha256, after.size_bytes))
        self.assertEqual(sum(x.path.endswith(".so") for x in installed), 46)
        print("C34S_PASS signed_release packages_index=exact "
              "debs=4 installed_payload=658 native_so=46 root_approved=false")


if __name__ == "__main__":
    unittest.main()
