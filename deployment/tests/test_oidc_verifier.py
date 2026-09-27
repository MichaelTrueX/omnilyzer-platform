from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from deployment.identity import DEV_AUDIENCE, DEV_ISSUER
from deployment.jwks import OIDCVerificationError
from deployment.oidc_verifier import GitHubOIDCVerifier
from deployment.tests.test_identity import NOW, WORKFLOW_SHA, valid_claims


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def private_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def manual_token(header: bytes, claims: bytes, key: rsa.RSAPrivateKey) -> str:
    signing_input = f"{b64url(header)}.{b64url(claims)}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode("ascii") + "." + b64url(signature)


class StaticCache:
    def __init__(self, key: rsa.RSAPublicKey) -> None:
        self.key = key
        self.kids: list[str] = []

    def get_key(self, kid: str) -> rsa.RSAPublicKey:
        self.kids.append(kid)
        return self.key


class OIDCVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self) -> None:
        self.cache = StaticCache(self.key.public_key())
        self.verifier = GitHubOIDCVerifier(expected_workflow_sha=WORKFLOW_SHA, jwks_cache=self.cache)  # type: ignore[arg-type]

    def token(
        self, claims: dict[str, object] | None = None, *,
        key: rsa.RSAPrivateKey | None = None, algorithm: str = "RS256",
        headers: dict[str, object] | None = None,
    ) -> str:
        selected = key or self.key
        header = {"kid": "key-1", "typ": "JWT"}
        if headers:
            header.update(headers)
        return jwt.encode(
            claims or valid_claims(), private_pem(selected),
            algorithm=algorithm, headers=header,
        )

    def reject(self, token: object) -> None:
        with self.assertRaises(OIDCVerificationError) as captured:
            self.verifier.verify(token, received_at=NOW)  # type: ignore[arg-type]
        message = str(captured.exception)
        self.assertLessEqual(len(message), 64)
        self.assertNotIn("key-1", message)
        self.assertNotIn(DEV_ISSUER, message)

    def signed_raw(self, header: object, claims: object) -> str:
        return manual_token(
            json.dumps(header, separators=(",", ":")).encode(),
            json.dumps(claims, separators=(",", ":")).encode(),
            self.key,
        )

    def test_valid_rs256_token_returns_authorized_identity(self) -> None:
        identity = self.verifier.verify(self.token(), received_at=NOW)
        self.assertEqual(identity.issuer, DEV_ISSUER)
        self.assertEqual(identity.audience, DEV_AUDIENCE)
        self.assertEqual(identity.repository_id, 1350104356)
        self.assertEqual(self.cache.kids, ["key-1"])

    def test_reviewed_revision_is_captured_and_cannot_be_replaced(self) -> None:
        with self.assertRaises(TypeError):
            GitHubOIDCVerifier()
        class StringSubclass(str):
            pass
        for authority in (None, True, "", "0" * 40, WORKFLOW_SHA.upper(),
                          "a" * 39, "a" * 41, "g" * 40,
                          StringSubclass(WORKFLOW_SHA)):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                GitHubOIDCVerifier(expected_workflow_sha=authority)
        with self.assertRaises(AttributeError):
            self.verifier._expected_workflow_sha = "f" * 40
        with self.assertRaises(AttributeError):
            del self.verifier._expected_workflow_sha
        claims = valid_claims()
        claims["workflow_sha"] = "f" * 40
        self.assertEqual(claims["workflow_ref"], valid_claims()["workflow_ref"])
        self.reject(self.token(claims))
        self.assertEqual(self.verifier.verify(self.token(), received_at=NOW).workflow_sha,
                         WORKFLOW_SHA)

    def test_altered_payload_signature_and_different_key_fail(self) -> None:
        token = self.token()
        parts = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        payload["repository"] = "attacker/repository"
        parts[1] = b64url(json.dumps(payload, separators=(",", ":")).encode())
        self.reject(".".join(parts))
        parts = self.token().split(".")
        signature = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
        signature[-1] ^= 1
        parts[2] = b64url(bytes(signature))
        self.reject(".".join(parts))
        self.reject(self.token(key=self.other))

    def test_none_hs256_and_ps256_fail(self) -> None:
        none = self.signed_raw({"alg": "none", "kid": "key-1"}, valid_claims())
        self.reject(none)
        hs = jwt.encode(valid_claims(), b"synthetic-secret-that-is-long-enough", algorithm="HS256", headers={"kid": "key-1", "typ": "JWT"})
        self.reject(hs)
        ps = self.token(algorithm="PS256")
        self.reject(ps)

    def test_missing_duplicate_and_unsafe_header_fields_fail(self) -> None:
        claims = json.dumps(valid_claims(), separators=(",", ":")).encode()
        cases = (
            b'{"kid":"key-1"}',
            b'{"alg":"RS256","alg":"RS256","kid":"key-1"}',
            b'{"alg":"RS256"}',
            b'{"alg":"RS256","kid":"../key"}',
            b'{"alg":"RS256","kid":"key/child"}',
            b'{"alg":"RS256","kid":"key-1","unknown":true}',
            b'{"alg":"RS256","kid":"key-1","typ":"JOSE"}',
        )
        for header in cases:
            with self.subTest(header=header):
                self.reject(manual_token(header, claims, self.key))

    def test_dangerous_header_extensions_fail(self) -> None:
        for name, value in (
            ("crit", ["exp"]), ("b64", False), ("jku", "https://example.invalid"),
            ("jwk", {}), ("x5u", "https://example.invalid"), ("x5c", ["AA=="]),
        ):
            with self.subTest(name=name):
                self.reject(self.signed_raw({"alg": "RS256", "kid": "key-1", name: value}, valid_claims()))

    def test_exact_issuer_and_single_string_audience_are_required(self) -> None:
        for key, value in (
            ("iss", "https://example.invalid"),
            ("aud", "https://example.invalid"),
            ("aud", [DEV_AUDIENCE]),
        ):
            claims = valid_claims()
            claims[key] = value
            with self.subTest(key=key, value=value):
                self.reject(self.token(claims))

    def test_missing_each_required_claim_fails(self) -> None:
        for name in tuple(valid_claims()):
            claims = valid_claims()
            del claims[name]
            with self.subTest(name=name):
                self.reject(self.token(claims))

    def test_verified_claims_flow_into_existing_policy_and_policy_rejection_wins(self) -> None:
        claims = valid_claims()
        claims["repository"] = "attacker/repository"
        self.reject(self.token(claims))
        with patch("deployment.oidc_verifier.authorize_verified_github_oidc", wraps=__import__("deployment.identity", fromlist=["authorize_verified_github_oidc"]).authorize_verified_github_oidc) as authorize:
            identity = self.verifier.verify(self.token(), received_at=NOW)
        self.assertEqual(identity.actor_id, 130741173)
        authorize.assert_called_once_with(valid_claims(), received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_verified_mapping_must_equal_bounded_preparsed_mapping(self) -> None:
        changed = valid_claims()
        changed["extra"] = "injected"
        with patch("deployment.oidc_verifier.jwt.decode", return_value=changed):
            self.reject(self.token())

    def test_single_received_at_controls_temporal_authorization(self) -> None:
        claims = valid_claims()
        claims.update(iat=NOW - 61, nbf=NOW - 61, exp=NOW + 100)
        with patch("deployment.oidc_verifier.jwt.decode", wraps=jwt.decode) as decode:
            self.reject(self.token(claims))
        options = decode.call_args.kwargs["options"]
        self.assertFalse(options["verify_exp"])
        self.assertFalse(options["verify_iat"])
        self.assertFalse(options["verify_nbf"])
        self.assertTrue(options["verify_signature"])
        self.assertTrue(options["verify_iss"])
        self.assertTrue(options["verify_aud"])
        self.assertTrue(options["strict_aud"])

    def test_received_at_must_be_one_nonnegative_integer(self) -> None:
        for value in (True, -1, 1.5, "2000000000"):
            with self.subTest(value=value), self.assertRaises(OIDCVerificationError):
                self.verifier.verify(self.token(), received_at=value)  # type: ignore[arg-type]
        self.assertEqual(self.cache.kids, [])

    def test_literal_algorithm_allowlist_is_passed_to_pyjwt(self) -> None:
        with patch("deployment.oidc_verifier.jwt.decode", wraps=jwt.decode) as decode:
            self.verifier.verify(self.token(), received_at=NOW)
        self.assertEqual(decode.call_args.kwargs["algorithms"], ["RS256"])

    def test_wrong_segments_padding_invalid_base64_and_non_ascii_fail(self) -> None:
        valid = self.token()
        cases = (
            "one.two", "one.two.three.four", ".two.three",
            valid.replace(".", "=.", 1), "*.two.three", valid + "é",
        )
        for token in cases:
            with self.subTest(token=token[:20]):
                self.reject(token)

    def test_oversized_compact_header_and_claims_fail(self) -> None:
        self.reject("a" * (16 * 1024 + 1))
        oversized_header = {"alg": "RS256", "kid": "key-1", "typ": "JWT", "x": "a" * 2100}
        self.reject(self.signed_raw(oversized_header, valid_claims()))
        oversized_claims = valid_claims()
        oversized_claims["extra"] = "a" * (12 * 1024)
        self.reject(self.signed_raw({"alg": "RS256", "kid": "key-1"}, oversized_claims))

    def test_member_depth_array_string_and_node_bounds_fail(self) -> None:
        too_many_header = {"alg": "RS256", "kid": "key-1", **{f"x{i}": i for i in range(7)}}
        self.reject(self.signed_raw(too_many_header, valid_claims()))
        too_many_claims = {**valid_claims(), **{f"extra{i}": i for i in range(64)}}
        self.reject(self.signed_raw({"alg": "RS256", "kid": "key-1"}, too_many_claims))
        cases = []
        depth = valid_claims(); depth["extra"] = {"a": {"b": {"c": {"d": 1}}}}; cases.append(depth)
        array = valid_claims(); array["extra"] = list(range(33)); cases.append(array)
        string = valid_claims(); string["extra"] = "a" * 4097; cases.append(string)
        nodes = valid_claims(); nodes["extra"] = [[i for i in range(16)] for _ in range(32)]; cases.append(nodes)
        for claims in cases:
            with self.subTest(extra_type=type(claims["extra"]).__name__):
                self.reject(self.signed_raw({"alg": "RS256", "kid": "key-1"}, claims))

    def test_duplicate_nested_member_and_invalid_constants_fail(self) -> None:
        header = b'{"alg":"RS256","kid":"key-1"}'
        prefix = json.dumps(valid_claims(), separators=(",", ":"))[:-1]
        duplicate = (prefix + ',"extra":{"nested":1,"nested":2}}').encode()
        constant = (prefix + ',"extra":NaN}').encode()
        self.reject(manual_token(header, duplicate, self.key))
        self.reject(manual_token(header, constant, self.key))

    def test_exception_messages_do_not_expose_token_claim_or_signature(self) -> None:
        claims = valid_claims()
        claims["repository"] = "secret-marker-repository"
        token = self.token(claims)
        with self.assertRaises(OIDCVerificationError) as captured:
            self.verifier.verify(token, received_at=NOW)
        message = str(captured.exception)
        self.assertNotIn("secret-marker", message)
        self.assertNotIn(token, message)
        self.assertNotIn(token.split(".")[2], message)


if __name__ == "__main__":
    unittest.main()
