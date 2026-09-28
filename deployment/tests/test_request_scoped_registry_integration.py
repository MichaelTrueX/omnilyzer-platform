"""C32P inert request-context integration with only synthetic signed JWTs."""

import hashlib
import inspect
import json
from pathlib import Path
import pickle
import unittest
from unittest.mock import patch

import jwt

from deployment import broker_integration as integration
from deployment import registry_promotion_composition as composition
from deployment.broker import (
    BrokerRejectedError, BrokerUnavailableError, REJECTED_MESSAGE,
    RestrictedDeploymentBroker, UNAVAILABLE_MESSAGE,
)
from deployment.broker_service_config import (
    BrokerServiceConfigurationError, DevBrokerServiceConfiguration,
)
from deployment.execution import (
    ExecutorRequest, IngressReference, RuntimeConfigurationReference,
    parse_canonical_request,
)
from deployment.identity import authorize_verified_github_oidc
from deployment.jwks import OIDCVerificationError, OIDCVerificationUnavailable
from deployment.oidc_verifier import GitHubOIDCVerifier, MAX_COMPACT_TOKEN_BYTES
from deployment.registry_oidc_credentials import (
    GitHubRegistryCredentialVerifier, VerifiedRegistryCredentials,
)
from deployment.release_consumer import ForgejoEvidenceConsumer, ZotCandidateConsumer
from deployment.tests.test_broker import Replay, Transport, Verifier
from deployment.tests.test_broker_integration import (
    FORGEJO_TOKEN, KEY, TOKEN, ZOT_TOKEN, fixture, invoke,
)
from deployment.tests.test_broker_service_config import configuration_values
from deployment.tests.test_execution import ingress_reference, runtime_reference, valid_request
from deployment.tests.test_identity import NOW, WORKFLOW_SHA, valid_claims
from deployment.tests.test_oidc_verifier import private_pem
from deployment.tests.test_registry_oidc_credentials import StaticCache
from deployment.tests.test_release_consumer import BlobSignatures, OCISignatures, setup

ROOT = Path(__file__).resolve().parents[2]


def signed(audience: str, *, jti: str) -> str:
    return jwt.encode(valid_claims() | {"aud": audience, "jti": jti},
                      private_pem(KEY), algorithm="RS256",
                      headers={"kid": "key-1", "typ": "JWT"})


class RequestContextTests(unittest.TestCase):
    def test_broker_orders_one_deployment_verification_context_build_replay_transport(self):
        events = []
        class Context:
            def verify(self, identity, context, *, received_at):
                events.append("registry")
                self_outer.assertEqual(received_at, NOW)
                self_outer.assertEqual(identity.workflow_sha, WORKFLOW_SHA)
                return context
        class Builder:
            def build(self, promotion, identity, context, *, received_at):
                events.append("build")
                self_outer.assertIs(context, opaque)
                return ExecutorRequest.from_dict(valid_request())
        self_outer = self
        opaque = object()
        broker = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
            verifier=Verifier(events=events), replay_guard=Replay(events=events),
            transport=Transport(events=events), request_builder=Builder(),
            promotion_context_verifier=Context(),
        )
        self.assertEqual(broker.authorize_promotion_and_forward(
            compact_token=TOKEN, promotion=object(), promotion_context=opaque,
            received_at=NOW), Transport().response)
        self.assertEqual(events, ["verify", "registry", "build", "replay", "transport"])

    def test_canonical_path_has_no_context_facility_and_is_unchanged(self):
        broker = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA, verifier=Verifier(),
            replay_guard=Replay(), transport=Transport(),
        )
        self.assertEqual(tuple(inspect.signature(broker.authorize_and_forward).parameters),
                         ("compact_token", "canonical_request", "received_at"))
        with self.assertRaises(TypeError):
            broker.authorize_and_forward(
                compact_token=TOKEN,
                canonical_request=ExecutorRequest.from_dict(valid_request()).canonical_bytes(),
                received_at=NOW, promotion_context=object(),
            )
        raw = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
        self.assertEqual(broker.authorize_and_forward(
            compact_token=TOKEN, canonical_request=raw, received_at=NOW), Transport().response)

    def test_deployment_failure_prevents_registry_and_release_work(self):
        class Context:
            calls = 0
            def verify(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError
        context = Context()
        replay, transport = Replay(), Transport()
        broker = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
            verifier=Verifier(error=OIDCVerificationError("bad deployment")),
            replay_guard=replay, transport=transport,
            request_builder=object_builder(), promotion_context_verifier=context,
        )
        with self.assertRaises(BrokerRejectedError):
            broker.authorize_promotion_and_forward(
                compact_token=TOKEN, promotion=object(),
                promotion_context=object(), received_at=NOW)
        self.assertEqual(context.calls, 0)
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])

    def test_real_context_verification_precedes_every_release_authority(self):
        events = []
        original_registry = GitHubRegistryCredentialVerifier.verify
        original_zot = ZotCandidateConsumer.acquire
        original_forgejo = ForgejoEvidenceConsumer.acquire
        def registry_verify(self, *args, **kwargs):
            events.append("registry")
            return original_registry(self, *args, **kwargs)
        def zot_acquire(self, *args, **kwargs):
            events.append("zot")
            return original_zot(self, *args, **kwargs)
        def forgejo_acquire(self, *args, **kwargs):
            events.append("forgejo")
            return original_forgejo(self, *args, **kwargs)
        class OCI(OCISignatures):
            def verify(self, image_reference, now):
                events.append("oci")
                return super().verify(image_reference, now)
        with patch.object(GitHubRegistryCredentialVerifier, "verify", registry_verify):
            handler, promotion, *_ = fixture(
                verifier=Verifier(events=events), replay=Replay(events=events),
                transport=Transport(events=events))
        with patch.object(ZotCandidateConsumer, "acquire", zot_acquire), patch.object(
            ForgejoEvidenceConsumer, "acquire", forgejo_acquire,
        ):
            invoke(handler, promotion, oci_signatures=OCI())
        self.assertEqual(events, ["verify", "registry", "zot", "forgejo",
                                  "oci", "replay", "transport"])

    def test_context_error_classification_blocks_replay_and_transport(self):
        for error, expected, message in (
            (BrokerRejectedError("secret"), BrokerRejectedError, REJECTED_MESSAGE),
            (BrokerUnavailableError("secret"), BrokerUnavailableError, UNAVAILABLE_MESSAGE),
            (RuntimeError("secret"), BrokerUnavailableError, UNAVAILABLE_MESSAGE),
        ):
            class Context:
                def verify(self, *args, **kwargs):
                    raise error
            replay, transport = Replay(), Transport()
            broker = RestrictedDeploymentBroker(
                expected_workflow_sha=WORKFLOW_SHA, verifier=Verifier(),
                replay_guard=replay, transport=transport,
                request_builder=object_builder(), promotion_context_verifier=Context(),
            )
            with self.subTest(error=type(error)), self.assertRaises(expected) as caught:
                broker.authorize_promotion_and_forward(
                    compact_token=TOKEN, promotion=object(),
                    promotion_context=object(), received_at=NOW)
            self.assertEqual(str(caught.exception), message)
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.calls, [])

    def test_raw_envelope_is_private_immutable_redacted_and_unserializable(self):
        value = integration._RegistryOIDCTokens(ZOT_TOKEN, FORGEJO_TOKEN)
        self.assertFalse(hasattr(value, "__dict__"))
        self.assertNotIn(ZOT_TOKEN, repr(value))
        self.assertNotIn(FORGEJO_TOKEN, repr(value))
        for name in value.__slots__:
            with self.assertRaises(AttributeError):
                setattr(value, name, "replacement")
            with self.assertRaises(AttributeError):
                delattr(value, name)
        with self.assertRaises(TypeError):
            pickle.dumps(value)
        for name in ("to_dict", "canonical_bytes", "audit_projection", "executor_request"):
            self.assertFalse(hasattr(value, name))
        verifier = composition._RegistryContextVerifier(
            GitHubRegistryCredentialVerifier(expected_workflow_sha=WORKFLOW_SHA,
                jwks_cache=StaticCache(KEY.public_key())))
        identity = authorize_verified_github_oidc(
            valid_claims(), received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)
        for candidate in ({"zot_token": ZOT_TOKEN, "forgejo_token": FORGEJO_TOKEN},
                          object.__new__(type("Subclass", (integration._RegistryOIDCTokens,), {}))):
            with self.assertRaises(BrokerRejectedError):
                verifier.verify(identity, candidate, received_at=NOW)

    def test_handler_signature_and_all_three_token_bounds(self):
        self.assertEqual(tuple(inspect.signature(integration.InertDevPromotionHandler.handle).parameters),
                         ("self", "compact_token", "zot_token", "forgejo_token",
                          "promotion_request", "received_at"))
        handler, promotion, verifier, replay, transport, zot, forgejo = fixture()
        for name in ("compact_token", "zot_token", "forgejo_token"):
            for bad in ("", "é", "x" * (MAX_COMPACT_TOKEN_BYTES + 1),
                        b"bytes", True, None, {"token": "synthetic"}):
                values = {"compact_token": TOKEN, "zot_token": ZOT_TOKEN,
                          "forgejo_token": FORGEJO_TOKEN,
                          "promotion_request": promotion.canonical_bytes(), "received_at": NOW}
                values[name] = bad
                with self.subTest(name=name, bad=type(bad)), self.assertRaises(BrokerRejectedError):
                    handler.handle(**values)
        self.assertEqual(verifier.calls, [])
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])
        self.assertEqual(zot.calls, [])
        self.assertEqual(forgejo.calls, [])
        with self.assertRaises(BrokerRejectedError):
            invoke(handler, promotion, zot_token=json.dumps({"token": ZOT_TOKEN}))
        self.assertEqual(replay.calls, [])

    def test_registry_rejection_or_unavailability_prevents_all_consumers(self):
        for cache_error, token, expected in (
            (None, ZOT_TOKEN + "tampered", BrokerRejectedError),
            (OIDCVerificationUnavailable("private diagnostic"), ZOT_TOKEN, BrokerUnavailableError),
        ):
            cache = StaticCache(KEY.public_key())
            handler, promotion, verifier, replay, transport, zot, forgejo = fixture(
                jwks_cache=cache)
            with patch.object(composition, "CosignOCISignatureVerifier") as cosign:
                if cache_error is None:
                    with self.assertRaises(expected) as caught:
                        handler.handle(
                            compact_token=TOKEN, zot_token=token,
                            forgejo_token=FORGEJO_TOKEN,
                            promotion_request=promotion.canonical_bytes(),
                            received_at=NOW)
                else:
                    with patch.object(cache, "get_key", side_effect=cache_error):
                        with self.assertRaises(expected) as caught:
                            handler.handle(
                                compact_token=TOKEN, zot_token=token,
                                forgejo_token=FORGEJO_TOKEN,
                                promotion_request=promotion.canonical_bytes(),
                                received_at=NOW)
                cosign.assert_not_called()
            self.assertNotIn(ZOT_TOKEN, str(caught.exception))
            self.assertNotIn(FORGEJO_TOKEN, str(caught.exception))
            self.assertEqual(verifier.calls, [(TOKEN, NOW)])
            self.assertEqual(zot.calls, [])
            self.assertEqual(forgejo.calls, [])
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.calls, [])

    def test_signed_deployment_jwt_is_verified_exactly_once(self):
        class Counting:
            def __init__(self):
                self.calls = []
                self.delegate = GitHubOIDCVerifier(
                    expected_workflow_sha=WORKFLOW_SHA,
                    jwks_cache=StaticCache(KEY.public_key()))
            def verify(self, token, *, received_at):
                self.calls.append((token, received_at))
                return self.delegate.verify(token, received_at=received_at)
        verifier = Counting()
        handler, promotion, _, replay, transport, _, _ = fixture(verifier=verifier)
        deployment = signed("https://deploy-dev.omnilyzer.ai/task014-dev",
                            jti="deployment-request")
        invoke(handler, promotion, token=deployment)
        self.assertEqual(verifier.calls, [(deployment, NOW)])
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(len(transport.calls), 1)

    def test_invalid_signed_deployment_jwt_never_reaches_registry(self):
        deployment_cache = StaticCache(KEY.public_key())
        registry_cache = StaticCache(KEY.public_key())
        verifier = GitHubOIDCVerifier(
            expected_workflow_sha=WORKFLOW_SHA, jwks_cache=deployment_cache)
        handler, promotion, _, replay, transport, zot, forgejo = fixture(
            verifier=verifier, jwks_cache=registry_cache)
        wrong = signed("https://oci-dev.omnilyzer.ai", jti="wrong-deployment")
        with self.assertRaises(BrokerRejectedError):
            invoke(handler, promotion, token=wrong)
        self.assertEqual(deployment_cache.kids, ["key-1"])
        self.assertEqual(registry_cache.kids, [])
        self.assertEqual(zot.calls, [])
        self.assertEqual(forgejo.calls, [])
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])

    def test_only_exact_verified_credentials_enter_release_builder(self):
        cfg = DevBrokerServiceConfiguration(**configuration_values(
            expected_workflow_sha=WORKFLOW_SHA))
        _, _, _, _, zot_factory, forgejo_factory = setup()
        factory = composition._RequestScopedReleaseAuthority(
            cfg, zot_connection_factory=zot_factory,
            forgejo_connection_factory=forgejo_factory, oci_runner=None)
        builder = composition._ReleaseRequestBuilder(
            factory=factory, verified_context_type=VerifiedRegistryCredentials,
            blob_signatures=BlobSignatures(),
            runtime=RuntimeConfigurationReference.from_dict(runtime_reference()),
            ingress=IngressReference.from_dict(ingress_reference()),
            expected_workflow_sha=WORKFLOW_SHA)
        with self.assertRaises(ValueError):
            composition._ReleaseRequestBuilder(
                factory=factory, verified_context_type=VerifiedRegistryCredentials,
                blob_signatures=BlobSignatures(),
                runtime=RuntimeConfigurationReference.from_dict(runtime_reference()),
                ingress=IngressReference.from_dict(ingress_reference()),
                expected_workflow_sha="0" * 40)
        identity = authorize_verified_github_oidc(
            valid_claims(), received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)
        promotion = setup()[0]
        class Subclass(VerifiedRegistryCredentials):
            pass
        for candidate in ({}, object(), object.__new__(Subclass)):
            with self.subTest(candidate=type(candidate)), self.assertRaises(TypeError):
                factory.create(candidate)
            with self.assertRaises(TypeError):
                builder.build(promotion, identity, candidate, received_at=NOW)
        self.assertEqual(zot_factory.calls, [])
        self.assertEqual(forgejo_factory.calls, [])

    def test_request_scoped_provider_is_shared_only_with_its_three_consumers(self):
        handler, promotion, _, replay, transport, _, _ = fixture()
        made = []
        zot_class, forgejo_class = ZotCandidateConsumer, ForgejoEvidenceConsumer
        def zot_make(provider, factory):
            made.append(("zot", provider))
            return zot_class(provider, factory)
        def forgejo_make(provider, factory):
            made.append(("forgejo", provider))
            return forgejo_class(provider, factory)
        def oci_make(**kwargs):
            made.append(("oci", kwargs["zot_credential_provider"], kwargs))
            return OCISignatures()
        with patch.object(composition, "ZotCandidateConsumer", zot_make), patch.object(
            composition, "ForgejoEvidenceConsumer", forgejo_make,
        ), patch.object(composition, "CosignOCISignatureVerifier", oci_make):
            handler.handle(compact_token=TOKEN, zot_token=ZOT_TOKEN,
                           forgejo_token=FORGEJO_TOKEN,
                           promotion_request=promotion.canonical_bytes(), received_at=NOW)
        self.assertEqual([item[0] for item in made], ["zot", "forgejo", "oci"])
        self.assertIs(made[0][1], made[1][1])
        self.assertIs(made[0][1], made[2][1])
        self.assertIs(type(made[0][1]), VerifiedRegistryCredentials)
        self.assertEqual(made[0][1].zot_read_credential().token, ZOT_TOKEN)
        self.assertEqual(made[0][1].zot_read_credential().token, ZOT_TOKEN)
        self.assertEqual(made[0][1].forgejo_read_credential().token, FORGEJO_TOKEN)
        cfg = DevBrokerServiceConfiguration(**configuration_values(
            expected_workflow_sha=WORKFLOW_SHA))
        self.assertEqual({k: v for k, v in made[2][2].items()
                          if k in cfg.blob_verifier_kwargs()}, dict(cfg.blob_verifier_kwargs()))
        broker = handler._forward.__self__
        builder = broker._operations[3].__self__
        factory = builder._create.__self__
        for retained in (handler, broker, builder, factory):
            self.assertFalse(any(
                getattr(retained, slot) is made[0][1]
                for slot in type(retained).__slots__))
        self.assertEqual(tuple(type(handler).__slots__), ("_forward",))
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(len(transport.calls), 1)

    def test_tokens_remain_outside_promotion_executor_replay_and_transport(self):
        handler, promotion, _, replay, transport, _, _ = fixture()
        invoke(handler, promotion)
        raw = transport.calls[0]
        request = parse_canonical_request(raw)
        for token in (TOKEN, ZOT_TOKEN, FORGEJO_TOKEN):
            self.assertNotIn(token, promotion.canonical_bytes().decode())
            self.assertNotIn(token, json.dumps(promotion.to_dict()))
            self.assertNotIn(token, json.dumps(request.to_dict()))
            self.assertNotIn(token, request.canonical_bytes().decode())
            self.assertNotIn(token, raw.decode())
            self.assertNotIn(token, repr(handler))
            self.assertNotIn(token, repr(replay.calls))
        self.assertEqual(set(replay.calls[0]),
                         {"jti", "expires_at", "request_hash", "run_id", "run_attempt"})
        self.assertEqual(replay.calls[0]["request_hash"], hashlib.sha256(raw).hexdigest())
        self.assertNotEqual(replay.calls[0]["jti"], "zot-request")
        self.assertNotEqual(replay.calls[0]["jti"], "forgejo-request")
        self.assertEqual(handler.__slots__, ("_forward",))

    def test_two_interleaved_calls_keep_credential_providers_separate(self):
        handler, promotion, _, replay, transport, _, _ = fixture()
        zot_a = signed("https://oci-dev.omnilyzer.ai", jti="zot-a")
        zot_b = signed("https://oci-dev.omnilyzer.ai", jti="zot-b")
        forgejo_a = signed("u:2:316bec9a-53e4-4807-9557-7febdc979d0a", jti="forgejo-a")
        forgejo_b = signed("u:2:316bec9a-53e4-4807-9557-7febdc979d0a", jti="forgejo-b")
        providers = []
        triggered = False
        class InterleavedOCI:
            def __init__(self, provider):
                self.provider = provider
            def verify(self, image_reference, now):
                nonlocal triggered
                if not triggered:
                    triggered = True
                    handler.handle(
                        compact_token=TOKEN, zot_token=zot_b,
                        forgejo_token=forgejo_b,
                        promotion_request=promotion.canonical_bytes(),
                        received_at=NOW)
                return OCISignatures().verify(image_reference, now)
        def make_oci(**kwargs):
            provider = kwargs["zot_credential_provider"]
            providers.append(provider)
            return InterleavedOCI(provider)
        with patch.object(composition, "CosignOCISignatureVerifier", make_oci):
            handler.handle(
                compact_token=TOKEN, zot_token=zot_a,
                forgejo_token=forgejo_a,
                promotion_request=promotion.canonical_bytes(), received_at=NOW)
        self.assertEqual(len(providers), 2)
        self.assertIsNot(providers[0], providers[1])
        self.assertEqual(
            [(p.zot_read_credential().token, p.forgejo_read_credential().token)
             for p in providers], [(zot_a, forgejo_a), (zot_b, forgejo_b)])
        self.assertEqual(len(replay.calls), 2)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(handler.__slots__, ("_forward",))

    def test_config_is_revalidated_and_registry_authority_not_persisted(self):
        cfg = DevBrokerServiceConfiguration(**configuration_values(
            expected_workflow_sha=WORKFLOW_SHA))
        object.__setattr__(cfg, "_installation", object())
        kwargs = {
            "verifier": Verifier(), "replay_guard": Replay(), "transport": Transport(),
            "blob_signatures": BlobSignatures(),
            "jwks_cache": StaticCache(KEY.public_key()),
        }
        handler = composition.compose_inert_dev_promotion_handler(
            configuration=cfg, **kwargs)
        self.assertIs(type(handler), integration.InertDevPromotionHandler)
        self.assertNotIn("zot_token", cfg.to_dict())
        self.assertNotIn("forgejo_token", cfg.to_dict())
        self.assertEqual(cfg.schema_version, 2)
        bad = DevBrokerServiceConfiguration(**configuration_values(
            expected_workflow_sha=WORKFLOW_SHA))
        object.__setattr__(bad, "broker_gid", True)
        with self.assertRaises(BrokerServiceConfigurationError):
            composition.compose_inert_dev_promotion_handler(
                configuration=bad, **kwargs)

    def test_repository_remains_inert_and_historical_selection_is_closed(self):
        from deployment.application_source_set import DevApplicationSourceSet
        from deployment import application_manifest, dev_post_c31_application_update as c32d
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 41)
        self.assertIn("deployment/broker_integration.py", paths)
        self.assertIn("deployment/registry_promotion_composition.py", paths)
        self.assertEqual((len(application_manifest._predecessor_paths()),
                          len(application_manifest._paths())), (28, 31))
        self.assertEqual(c32d.PREDECESSOR,
                         "3ef02a6d61d20df3a1495b290c20807162b65b06")
        self.assertEqual(c32d.TARGET,
                         "c04e66008cff556315603a9de59dacb4679787d4")
        workflow = (ROOT / ".github/workflows/platform-promote.yml").read_text()
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("environment: task014-dev", workflow)
        self.assertFalse(json.loads((ROOT / "deployment/environments/dev.json").read_text())
                         ["activation"]["deployment_enabled"])
        for path in (ROOT / "deployment/broker_integration.py",
                     ROOT / "deployment/registry_promotion_composition.py"):
            source = path.read_text()
            for forbidden in ("socket.socket", "systemctl", "subprocess",
                              "docker login", "time.time(", "write_bytes", "write_text"):
                self.assertNotIn(forbidden, source)


def object_builder():
    class Builder:
        def build(self, *args, **kwargs):
            raise AssertionError("builder should not run")
    return Builder()


if __name__ == "__main__":
    unittest.main()
