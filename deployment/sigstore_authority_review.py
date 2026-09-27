"""Pure C32I review of supplied exact retained public evidence bytes.

This is a review/build-time boundary, outside the installed runtime source set.
It reads no paths and performs no network, signature verification, installation,
TUF update or activation. Byte identities and closed structural checks do not
establish complete TUF trust-chain or Sigstore cryptographic verification.
"""

import base64 as _base64
from datetime import datetime as _datetime
import hashlib as _hashlib
from re import fullmatch as _fullmatch

from .jwks import parse_bounded_json as _parse_bounded_json
from .sigstore_authority_provenance import (
    DevSigstoreVerificationProvenance as _DevSigstoreVerificationProvenance,
)

__all__ = ("SigstoreAuthorityReviewError", "review_retained_sigstore_authority")
_ERROR = "retained Sigstore verification authority evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class SigstoreAuthorityReviewError(Exception):
    """The supplied retained bytes cannot establish the closed reviewed evidence."""


def _object(value: object, fields: set[str]) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise ValueError
    return value


def _list(value: object, size: int) -> list:
    if type(value) is not list or len(value) != size:
        raise ValueError
    return value


def _encoded(value: object, *, size: int | None = None) -> bytes:
    if type(value) is not str or not value or not value.isascii():
        raise ValueError
    decoded = _base64.b64decode(value, validate=True)
    if not decoded or _base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError
    if size is not None and len(decoded) != size:
        raise ValueError
    return decoded


def _der(value: object) -> None:
    # Only a DER sequence envelope check, not X.509/key cryptographic validation.
    raw = _encoded(value)
    if len(raw) < 2 or raw[0] != 0x30:
        raise ValueError
    length = raw[1]
    offset = 2
    if length & 0x80:
        count = length & 0x7f
        if not 1 <= count <= 4 or len(raw) < offset + count or raw[offset] == 0:
            raise ValueError
        length = int.from_bytes(raw[offset:offset + count], "big")
        offset += count
        if length < 128:
            raise ValueError
    if length == 0 or offset + length != len(raw):
        raise ValueError


def _validity(value: object) -> tuple[str, str | None]:
    if type(value) is not dict or set(value) not in ({"start"}, {"start", "end"}):
        raise ValueError
    for timestamp in value.values():
        if (type(timestamp) is not str
                or _fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z", timestamp) is None):
            raise ValueError
        _datetime.fromisoformat(timestamp)
    start, end = value["start"], value.get("end")
    if end is not None and _datetime.fromisoformat(end) < _datetime.fromisoformat(start):
        raise ValueError
    return start, end


def _review_logs(value: object, expected: dict[str, tuple[str, str, str | None]]) -> None:
    logs = _list(value, len(expected))
    seen: set[str] = set()
    for log in logs:
        _object(log, {"baseUrl", "hashAlgorithm", "publicKey", "logId"})
        url = log["baseUrl"]
        if type(url) is not str or url not in expected or url in seen:
            raise ValueError
        seen.add(url)
        if log["hashAlgorithm"] != "SHA2_256":
            raise ValueError
        key = _object(log["publicKey"], {"rawBytes", "keyDetails", "validFor"})
        details, start, end = expected[url]
        if key["keyDetails"] != details or _validity(key["validFor"]) != (start, end):
            raise ValueError
        _der(key["rawBytes"])
        _encoded(_object(log["logId"], {"keyId"})["keyId"], size=32)


def _review_authorities(value: object, *, timestamp: bool) -> None:
    expected = {
        ("2025-07-04T00:00:00Z", None): ("sigstore-tsa-selfsigned", 2),
    } if timestamp else {
        ("2021-03-07T03:20:29Z", "2022-12-31T23:59:59.999Z"): ("sigstore", 1),
        ("2022-04-13T20:06:15Z", None): ("sigstore", 2),
    }
    uri = "https://timestamp.sigstore.dev/api/v1/timestamp" if timestamp else "https://fulcio.sigstore.dev"
    seen: set[tuple[str, str | None]] = set()
    for authority in _list(value, len(expected)):
        _object(authority, {"subject", "uri", "certChain", "validFor"})
        validity = _validity(authority["validFor"])
        if validity not in expected or validity in seen or authority["uri"] != uri:
            raise ValueError
        seen.add(validity)
        common_name, chain_length = expected[validity]
        if _object(authority["subject"], {"organization", "commonName"}) != {
            "organization": "sigstore.dev", "commonName": common_name,
        }:
            raise ValueError
        chain = _object(authority["certChain"], {"certificates"})
        for certificate in _list(chain["certificates"], chain_length):
            _der(_object(certificate, {"rawBytes"})["rawBytes"])


def _review_trusted_root(value: object) -> None:
    _object(value, {"mediaType", "tlogs", "certificateAuthorities", "ctlogs", "timestampAuthorities"})
    if value["mediaType"] != "application/vnd.dev.sigstore.trustedroot+json;version=0.1":
        raise ValueError
    _review_logs(value["tlogs"], {
        "https://rekor.sigstore.dev": ("PKIX_ECDSA_P256_SHA_256", "2021-01-12T11:53:27Z", None),
        "https://log2025-1.rekor.sigstore.dev": ("PKIX_ED25519", "2025-09-23T00:00:00Z", None),
    })
    _review_logs(value["ctlogs"], {
        "https://ctfe.sigstore.dev/test": ("PKIX_ECDSA_P256_SHA_256", "2021-03-14T00:00:00Z", "2022-10-31T23:59:59.999Z"),
        "https://ctfe.sigstore.dev/2022": ("PKIX_ECDSA_P256_SHA_256", "2022-10-20T00:00:00Z", None),
    })
    _review_authorities(value["certificateAuthorities"], timestamp=False)
    _review_authorities(value["timestampAuthorities"], timestamp=True)


def _json(raw: bytes) -> dict:
    # Reuse C1's duplicate-key/nonfinite/depth/node/string/array bounded parser.
    return _parse_bounded_json(
        raw, maximum_bytes=8192, maximum_root_members=5,
        maximum_depth=10, maximum_nodes=512, maximum_array=32, maximum_string=4096,
    )


def _exact_bytes(raw: object, size: int, sha256: str, git_blob: str | None = None) -> None:
    if type(raw) is not bytes or len(raw) != size or _hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError
    if git_blob is not None:
        # Git object identity only; SHA-256 above binds the trusted exact content.
        header = b"blob " + str(size).encode("ascii") + b"\0"
        if _hashlib.sha1(header + raw).hexdigest() != git_blob:
            raise ValueError


def _review_targets(value: object, trusted_root: bytes, authority: object) -> None:
    _object(value, {"signatures", "signed"})
    for signature in _list(value["signatures"], 5):
        _object(signature, {"keyid", "sig"})
        if (type(signature["keyid"]) is not str
                or _fullmatch(r"[0-9a-f]{64}", signature["keyid"]) is None
                or type(signature["sig"]) is not str
                or _fullmatch(r"[0-9a-f]{140,144}", signature["sig"]) is None):
            raise ValueError
    signed = _object(value["signed"], {
        "_type", "delegations", "expires", "spec_version", "targets", "version",
        "x-tuf-on-ci-expiry-period", "x-tuf-on-ci-signing-period",
    })
    if (signed["_type"] != "targets" or signed["spec_version"] != "1.0"
            or type(signed["version"]) is not int
            or signed["version"] != authority.targets_role_version
            or signed["expires"] != authority.metadata_expiration):
        raise ValueError
    if type(signed["targets"]) is not dict:
        raise ValueError
    target = _object(signed["targets"][authority.target_name], {"length", "hashes"})
    if (type(target["length"]) is not int or target["length"] != len(trusted_root)
            or _object(target["hashes"], {"sha256"}) != {
                "sha256": _hashlib.sha256(trusted_root).hexdigest(),
            }):
        raise ValueError


def _review_bundle(raw: bytes, digest: str) -> None:
    bundle = _object(_json(raw), {"mediaType", "verificationMaterial", "messageSignature"})
    if bundle["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ValueError
    message = _object(bundle["messageSignature"], {"messageDigest", "signature"})
    message_digest = _object(message["messageDigest"], {"algorithm", "digest"})
    if (message_digest["algorithm"] != "SHA2_256"
            or _encoded(message_digest["digest"], size=32).hex() != digest):
        raise ValueError
    _encoded(message["signature"])
    # The remaining material is retained for later real cryptographic qualification.


def review_retained_sigstore_authority(
    *, trusted_root: bytes, targets_metadata: bytes, checksums: bytes,
    binary_bundle: bytes, checksums_bundle: bytes,
) -> _DevSigstoreVerificationProvenance:
    """Review exact supplied bytes without reading or selecting repository paths."""
    try:
        reviewed = _DevSigstoreVerificationProvenance()
        root, cosign = reviewed.trusted_root, reviewed.cosign
        _exact_bytes(trusted_root, root.target_size, root.target_sha256, root.target_git_blob_sha)
        _exact_bytes(targets_metadata, root.metadata_size, root.metadata_sha256, root.metadata_git_blob_sha)
        _exact_bytes(checksums, cosign.checksums_size, cosign.checksums_sha256)
        _exact_bytes(binary_bundle, cosign.bundle_size, cosign.bundle_sha256)
        _exact_bytes(checksums_bundle, cosign.checksums_bundle_size, cosign.checksums_bundle_sha256)
        _review_trusted_root(_json(trusted_root))
        _review_targets(_json(targets_metadata), trusted_root, root)
        selected = [line.split() for line in checksums.decode("ascii").splitlines()
                    if line.split() and line.split()[-1] == cosign.asset_name]
        if selected != [[cosign.asset_sha256, cosign.asset_name]]:
            raise ValueError
        _review_bundle(binary_bundle, cosign.asset_sha256)
        _review_bundle(checksums_bundle, cosign.checksums_sha256)
        return reviewed
    except _CONTROL:
        raise
    except Exception:
        raise SigstoreAuthorityReviewError(_ERROR) from None
