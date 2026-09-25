"""Hostile public tests for the inert restricted deployment broker core."""

from __future__ import annotations

from dataclasses import replace
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from deployment.broker import (
    BrokerRejectedError,
    BrokerUnavailableError,
    MAX_EXECUTOR_RESPONSE_BYTES,
    REJECTED_MESSAGE,
    UNAVAILABLE_MESSAGE,
    RestrictedDeploymentBroker,
)
from deployment.execution import (
    MAX_CANONICAL_REQUEST_BYTES,
    DeploymentBroker,
    ExecutorRequest,
)
from deployment.identity import (
    AuthorizedGitHubIdentity,
    ReplayError,
    ReplayUnavailableError,
    authorize_verified_github_oidc,
)
from deployment.jwks import OIDCVerificationError, OIDCVerificationUnavailable
from deployment.replay_sqlite import SQLiteReplayGuard
from deployment.tests.test_execution import valid_request
from deployment.tests.test_identity import NOW, WORKFLOW_SHA, valid_claims


ROOT = Path(__file__).resolve().parents[2]
TOKEN = "bounded.synthetic.token"
RESPONSE = b'{"accepted":true}\n'


def identity() -> AuthorizedGitHubIdentity:
    return authorize_verified_github_oidc(valid_claims(), received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)


def request_bytes(raw: dict[str, object] | None = None) -> bytes:
    return ExecutorRequest.from_dict(raw or valid_request()).canonical_bytes()


class Verifier:
    def __init__(self, result: object | None = None, error: BaseException | None = None,
                 events: list[str] | None = None) -> None:
        self.result = identity() if result is None else result
        self.error = error
        self.events = events
        self.calls: list[tuple[object, object]] = []

    def verify(self, compact_token: str, *, received_at: int) -> object:
        self.calls.append((compact_token, received_at))
        if self.events is not None:
            self.events.append("verify")
        if self.error is not None:
            raise self.error
        return self.result


class Replay:
    def __init__(self, error: BaseException | None = None,
                 events: list[str] | None = None) -> None:
        self.error = error
        self.events = events
        self.calls: list[dict[str, object]] = []

    def consume(self, jti: str, *, expires_at: int, request_hash: str,
                run_id: int, run_attempt: int) -> None:
        self.calls.append({
            "jti": jti, "expires_at": expires_at, "request_hash": request_hash,
            "run_id": run_id, "run_attempt": run_attempt,
        })
        if self.events is not None:
            self.events.append("replay")
        if self.error is not None:
            raise self.error


class Transport:
    def __init__(self, response: object = RESPONSE, error: BaseException | None = None,
                 events: list[str] | None = None) -> None:
        self.response = response
        self.error = error
        self.events = events
        self.calls: list[bytes] = []

    def send(self, canonical_request: bytes) -> object:
        self.calls.append(canonical_request)
        if self.events is not None:
            self.events.append("transport")
        if self.error is not None:
            raise self.error
        return self.response


def broker(*, verifier: Verifier | None = None, replay: Replay | None = None,
           transport: Transport | None = None) -> tuple[
               RestrictedDeploymentBroker, Verifier, Replay, Transport,
           ]:
    selected_verifier = verifier or Verifier()
    selected_replay = replay or Replay()
    selected_transport = transport or Transport()
    return (
        RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
            verifier=selected_verifier,
            replay_guard=selected_replay,
            transport=selected_transport,
        ),
        selected_verifier,
        selected_replay,
        selected_transport,
    )


class BrokerPublicContractTests(unittest.TestCase):
    def test_exact_public_signature(self) -> None:
        signature = inspect.signature(RestrictedDeploymentBroker.authorize_and_forward)
        self.assertEqual(
            tuple(signature.parameters),
            ("self", "compact_token", "canonical_request", "received_at"),
        )
        self.assertTrue(all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for name, parameter in signature.parameters.items() if name != "self"
        ))

    def test_protocol_has_same_closed_signature(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(DeploymentBroker.authorize_and_forward).parameters),
            ("self", "compact_token", "canonical_request", "received_at"),
        )

    def test_constructor_binds_collaborators_without_calling_them(self) -> None:
        result, verifier, replay, transport = broker()
        self.assertIsInstance(result, RestrictedDeploymentBroker)
        self.assertEqual((verifier.calls, replay.calls, transport.calls), ([], [], []))

    def test_constructor_rejects_missing_or_noncallable_operations(self) -> None:
        valid = (Verifier(), Replay(), Transport())
        for index in range(3):
            dependencies: list[object] = list(valid)
            dependencies[index] = object()
            with self.subTest(index=index), self.assertRaises(TypeError):
                RestrictedDeploymentBroker(
                    expected_workflow_sha=WORKFLOW_SHA,
                    verifier=dependencies[0], replay_guard=dependencies[1],
                    transport=dependencies[2],
                )

    def test_constructor_does_not_invoke_property_descriptors(self) -> None:
        class PropertyVerifier:
            @property
            def verify(self) -> object:
                raise AssertionError("construction-side-effect")
        with self.assertRaises(TypeError):
            RestrictedDeploymentBroker(
                expected_workflow_sha=WORKFLOW_SHA,
                verifier=PropertyVerifier(), replay_guard=Replay(), transport=Transport(),
            )

    def test_captured_operations_resist_later_attribute_substitution(self) -> None:
        result, verifier, replay, transport = broker()
        verifier.verify = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError())  # type: ignore[method-assign]
        replay.consume = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError())  # type: ignore[method-assign]
        transport.send = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError())  # type: ignore[method-assign]
        self.assertEqual(
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            ),
            RESPONSE,
        )

    def test_no_per_request_collaborator_or_object_injection(self) -> None:
        result, _, _, _ = broker()
        with self.assertRaises(TypeError):
            result.authorize_and_forward(  # type: ignore[call-arg]
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                verifier=Verifier(), replay_guard=Replay(), transport=Transport(),
            )
        with self.assertRaises(BrokerRejectedError):
            result.authorize_and_forward(  # type: ignore[arg-type]
                compact_token=TOKEN, canonical_request=ExecutorRequest.from_dict(valid_request()),
                received_at=NOW,
            )

    def test_subclassed_collaborators_are_constructor_bound(self) -> None:
        class SubVerifier(Verifier):
            pass
        class SubReplay(Replay):
            pass
        class SubTransport(Transport):
            pass
        result = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
            verifier=SubVerifier(), replay_guard=SubReplay(), transport=SubTransport(),
        )
        self.assertEqual(result.authorize_and_forward(
            compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
        ), RESPONSE)


class BrokerSuccessAndOrderingTests(unittest.TestCase):
    def test_success_calls_exact_collaborators_once(self) -> None:
        result, verifier, replay, transport = broker()
        canonical = request_bytes()
        response = result.authorize_and_forward(
            compact_token=TOKEN, canonical_request=canonical, received_at=NOW,
        )
        self.assertEqual(response, RESPONSE)
        self.assertEqual(verifier.calls, [(TOKEN, NOW)])
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(len(transport.calls), 1)

    def test_replay_receives_exact_closed_binding(self) -> None:
        result, _, replay, _ = broker()
        canonical = request_bytes()
        result.authorize_and_forward(
            compact_token=TOKEN, canonical_request=canonical, received_at=NOW,
        )
        expected_identity = identity()
        self.assertEqual(replay.calls, [{
            "jti": expected_identity.jti,
            "expires_at": expected_identity.expires_at,
            "request_hash": hashlib.sha256(canonical).hexdigest(),
            "run_id": expected_identity.run_id,
            "run_attempt": expected_identity.run_attempt,
        }])

    def test_transport_receives_same_bytes_object(self) -> None:
        result, _, _, transport = broker()
        canonical = request_bytes()
        result.authorize_and_forward(
            compact_token=TOKEN, canonical_request=canonical, received_at=NOW,
        )
        self.assertIs(transport.calls[0], canonical)

    def test_operation_order_is_verify_parse_bind_replay_transport(self) -> None:
        events: list[str] = []
        result, _, _, _ = broker(
            verifier=Verifier(events=events), replay=Replay(events=events),
            transport=Transport(events=events),
        )
        import deployment.broker as module
        original_parse = module.parse_canonical_request
        original_bind = module.bind_request_to_identity
        def observed_parse(raw: bytes) -> ExecutorRequest:
            events.append("parse")
            return original_parse(raw)
        def observed_bind(request: ExecutorRequest, value: AuthorizedGitHubIdentity) -> None:
            events.append("bind")
            original_bind(request, value)
        with patch.object(module, "parse_canonical_request", observed_parse), patch.object(
            module, "bind_request_to_identity", observed_bind,
        ):
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
        self.assertEqual(events, ["verify", "parse", "bind", "replay", "transport"])

    def test_identity_is_independently_reauthorized(self) -> None:
        result, _, _, _ = broker()
        with patch(
            "deployment.broker.authorize_verified_github_oidc",
            wraps=authorize_verified_github_oidc,
        ) as authorize:
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
        authorize.assert_called_once()
        self.assertEqual(authorize.call_args.kwargs, {
            "received_at": NOW, "expected_workflow_sha": WORKFLOW_SHA,
        })

    def test_broker_rejects_verifier_identity_with_other_reviewed_revision(self) -> None:
        verifier, replay, transport = Verifier(), Replay(), Transport()
        with self.assertRaises(TypeError):
            RestrictedDeploymentBroker(
                verifier=verifier, replay_guard=replay, transport=transport,
            )
        result = RestrictedDeploymentBroker(
            expected_workflow_sha="f" * 40,
            verifier=verifier, replay_guard=replay, transport=transport,
        )
        with self.assertRaises(BrokerRejectedError):
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])
        with self.assertRaises(AttributeError):
            result._expected_workflow_sha = WORKFLOW_SHA

    def test_empty_exact_bytes_response_is_allowed(self) -> None:
        result, _, _, _ = broker(transport=Transport(b""))
        self.assertEqual(result.authorize_and_forward(
            compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
        ), b"")

    def test_collaborator_cannot_redirect_later_phase_during_request(self) -> None:
        original_transport = Transport()
        replacement_transport = Transport(b"replaced")
        holder: dict[str, RestrictedDeploymentBroker] = {}
        class MutatingReplay(Replay):
            def consume(inner_self, *args: object, **kwargs: object) -> None:
                super().consume(*args, **kwargs)  # type: ignore[arg-type]
                object.__setattr__(
                    holder["broker"], "_operations",
                    (Verifier().verify, inner_self.consume, replacement_transport.send),
                )
        replay = MutatingReplay()
        holder["broker"] = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
            verifier=Verifier(), replay_guard=replay, transport=original_transport,
        )
        self.assertEqual(holder["broker"].authorize_and_forward(
            compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
        ), RESPONSE)
        self.assertEqual(len(original_transport.calls), 1)
        self.assertEqual(replacement_transport.calls, [])

    def test_ordinary_collaborator_reassignment_is_rejected(self) -> None:
        result, _, _, _ = broker()
        with self.assertRaises(AttributeError):
            result._operations = ()  # type: ignore[assignment]


class BrokerInputRejectionTests(unittest.TestCase):
    def assert_rejected_without_calls(self, **changes: object) -> None:
        result, verifier, replay, transport = broker()
        arguments: dict[str, object] = {
            "compact_token": TOKEN,
            "canonical_request": request_bytes(),
            "received_at": NOW,
        }
        arguments.update(changes)
        with self.assertRaisesRegex(BrokerRejectedError, f"^{REJECTED_MESSAGE}$"):
            result.authorize_and_forward(**arguments)  # type: ignore[arg-type]
        self.assertEqual((verifier.calls, replay.calls, transport.calls), ([], [], []))

    def test_token_exact_type_required(self) -> None:
        class TokenSubclass(str):
            pass
        for invalid in (TokenSubclass(TOKEN), b"token", None, {}, 1):
            with self.subTest(invalid=type(invalid).__name__):
                self.assert_rejected_without_calls(compact_token=invalid)

    def test_request_exact_type_required(self) -> None:
        class BytesSubclass(bytes):
            pass
        canonical = request_bytes()
        for invalid in (
            BytesSubclass(canonical), bytearray(canonical), memoryview(canonical),
            "request", {}, ExecutorRequest.from_dict(valid_request()), None,
        ):
            with self.subTest(invalid=type(invalid).__name__):
                self.assert_rejected_without_calls(canonical_request=invalid)

    def test_request_empty_and_oversized_rejected(self) -> None:
        for invalid in (b"", b"x" * (MAX_CANONICAL_REQUEST_BYTES + 1)):
            with self.subTest(size=len(invalid)):
                self.assert_rejected_without_calls(canonical_request=invalid)

    def test_malformed_request_at_exact_maximum_rejects_after_verification(self) -> None:
        result, verifier, replay, transport = broker()
        invalid = b"x" * MAX_CANONICAL_REQUEST_BYTES
        with self.assertRaises(BrokerRejectedError):
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=invalid, received_at=NOW,
            )
        self.assertEqual(len(verifier.calls), 1)
        self.assertEqual((replay.calls, transport.calls), ([], []))

    def test_received_at_exact_type_and_range_required(self) -> None:
        class IntSubclass(int):
            pass
        for invalid in (True, 1.0, -1, "1", IntSubclass(NOW), None):
            with self.subTest(invalid=invalid):
                self.assert_rejected_without_calls(received_at=invalid)

    def test_malformed_duplicate_nonascii_and_noncanonical_requests_rejected(self) -> None:
        canonical = request_bytes()
        duplicate = canonical.replace(
            b'{"exact_image_reference"',
            b'{"stage":"dev","exact_image_reference"', 1,
        )
        reordered = json.dumps(valid_request(), separators=(",", ":")).encode() + b"\n"
        for invalid in (
            b"not-json\n", duplicate, b'\xff\n', b" " + canonical,
            canonical.rstrip(b"\n"), reordered,
        ):
            with self.subTest(invalid=invalid[:30]):
                result, verifier, replay, transport = broker()
                with self.assertRaises(BrokerRejectedError):
                    result.authorize_and_forward(
                        compact_token=TOKEN, canonical_request=invalid, received_at=NOW,
                    )
                self.assertEqual(len(verifier.calls), 1)
                self.assertEqual((replay.calls, transport.calls), ([], []))

    def test_each_closed_request_boundary_rejects_before_replay(self) -> None:
        mutations = (
            ("operation", "shell"), ("stage", "prod"),
            ("oci_origin", "https://registry.invalid"),
            ("oci_repository", "other/repository"),
            ("manifest_digest", "sha256:bad"),
            ("exact_image_reference", "other/image:latest"),
        )
        for field, invalid in mutations:
            raw = valid_request(); raw[field] = invalid
            with self.subTest(field=field):
                self._reject_canonical_value(raw)

    def test_each_nested_request_boundary_rejects_before_replay(self) -> None:
        cases = []
        for name, field, invalid in (
            ("runtime_configuration_reference", "path", "/etc/passwd"),
            ("secrets_reference", "required", ["TOKEN"]),
            ("ingress_reference", "public_origin", "https://evil.invalid"),
        ):
            raw = valid_request()
            raw[name][field] = invalid  # type: ignore[index]
            cases.append((name, raw))
        for name, raw in cases:
            with self.subTest(name=name):
                self._reject_canonical_value(raw)

    def _reject_canonical_value(self, raw: dict[str, object]) -> None:
        canonical = (json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n").encode()
        result, verifier, replay, transport = broker()
        with self.assertRaises(BrokerRejectedError):
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=canonical, received_at=NOW,
            )
        self.assertEqual(len(verifier.calls), 1)
        self.assertEqual((replay.calls, transport.calls), ([], []))


class BrokerIdentityBoundaryTests(unittest.TestCase):
    def assert_identity_rejected(self, value: object) -> None:
        result, verifier, replay, transport = broker(verifier=Verifier(value))
        with self.assertRaisesRegex(BrokerRejectedError, f"^{REJECTED_MESSAGE}$"):
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
        self.assertEqual(len(verifier.calls), 1)
        self.assertEqual((replay.calls, transport.calls), ([], []))

    def test_identity_subclass_mapping_and_request_object_rejected(self) -> None:
        class IdentitySubclass(AuthorizedGitHubIdentity):
            pass
        base = identity()
        for invalid in (IdentitySubclass(**vars(base)), valid_claims(), ExecutorRequest.from_dict(valid_request())):
            with self.subTest(invalid=type(invalid).__name__):
                self.assert_identity_rejected(invalid)

    def test_direct_invalid_base_identity_is_revalidated(self) -> None:
        self.assert_identity_rejected(replace(identity(), repository="attacker/repository"))

    def test_exact_base_identity_with_missing_field_is_rejected(self) -> None:
        invalid = identity()
        object.__delattr__(invalid, "jti")
        self.assert_identity_rejected(invalid)

    def test_hostile_int_and_str_fields_are_rejected(self) -> None:
        class HostileInt(int):
            def __eq__(self, other: object) -> bool:
                return True
        class HostileStr(str):
            def __eq__(self, other: object) -> bool:
                return True
            def __hash__(self) -> int:
                return str.__hash__(self)
        for invalid in (
            replace(identity(), run_id=HostileInt(-1)),
            replace(identity(), jti=HostileStr("different-safe-jti")),
        ):
            with self.subTest(field=type(invalid.run_id).__name__):
                self.assert_identity_rejected(invalid)

    def test_shadowed_methods_and_deepcopy_cannot_bypass_identity(self) -> None:
        invalid = replace(identity(), actor_id=True)
        object.__setattr__(invalid, "__deepcopy__", lambda memo: identity())
        object.__setattr__(invalid, "to_dict", lambda: vars(identity()))
        self.assert_identity_rejected(invalid)

    def test_identity_is_normalized_from_one_coherent_snapshot(self) -> None:
        initial = replace(identity(), actor_id=identity().actor_id + 1)
        replacement = replace(identity(), run_id=identity().run_id + 1)
        original = dict(vars(initial))
        replacement_fields = dict(vars(replacement))
        class SwappingDict(dict):
            pass
        # A non-base mapping cannot become the authorization snapshot.
        object.__setattr__(initial, "__dict__", SwappingDict(original))
        self.assert_identity_rejected(initial)
        # Replacing the complete base dictionary yields one coherent (invalid) state,
        # never a field-by-field hybrid of the two identities.
        object.__setattr__(initial, "__dict__", replacement_fields)
        self.assert_identity_rejected(initial)

    def test_hostile_identity_dictionary_key_is_rejected_without_hashing(self) -> None:
        class HostileKey(str):
            armed = False
            invoked = False

            def __hash__(self) -> int:
                if self.armed:
                    type(self).invoked = True
                    raise AssertionError("hostile-key-hash")
                return str.__hash__(self)

        invalid = identity()
        fields = object.__getattribute__(invalid, "__dict__")
        run_id = fields.pop("run_id")
        hostile = HostileKey("run_id")
        fields[hostile] = run_id
        HostileKey.armed = True
        self.assert_identity_rejected(invalid)
        self.assertFalse(HostileKey.invoked)

    def test_each_identity_mismatch_rejects_before_replay(self) -> None:
        base = identity()
        alternatives = (
            replace(base, actor_id=base.actor_id + 1),
            replace(base, workflow_sha="a" * 40),
            replace(base, run_id=base.run_id + 1),
            replace(base, run_attempt=base.run_attempt + 1),
            replace(base, jti="different-safe-jti"),
            replace(base, issued_at=base.issued_at + 1),
            replace(base, expires_at=base.expires_at - 1),
        )
        for alternative in alternatives:
            with self.subTest(alternative=alternative):
                self.assert_identity_rejected(alternative)

    def test_fixed_identity_allowlist_mismatches_are_rejected(self) -> None:
        base = identity()
        for invalid in (
            replace(base, repository_id=base.repository_id + 1),
            replace(base, repository_owner_id=base.repository_owner_id + 1),
            replace(base, repository="other/repository"),
            replace(base, workflow_ref=base.workflow_ref + "/other"),
        ):
            with self.subTest(invalid=invalid):
                self.assert_identity_rejected(invalid)


class BrokerFailureAndResponseTests(unittest.TestCase):
    def test_request_hash_provider_failure_is_generic_and_stops_before_replay(self) -> None:
        result, _, replay, transport = broker()
        with patch("deployment.broker.hashlib.sha256", side_effect=RuntimeError("hash-marker")):
            with self.assertRaisesRegex(
                BrokerUnavailableError, f"^{UNAVAILABLE_MESSAGE}$",
            ) as captured:
                result.authorize_and_forward(
                    compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                )
        self.assertNotIn("marker", str(captured.exception))
        self.assertEqual((replay.calls, transport.calls), ([], []))

    def test_malformed_request_hash_result_is_unavailable_before_replay(self) -> None:
        class HashResult:
            def hexdigest(self) -> str:
                return "HASH-MARKER"
        result, _, replay, transport = broker()
        with patch("deployment.broker.hashlib.sha256", return_value=HashResult()):
            with self.assertRaisesRegex(BrokerUnavailableError, f"^{UNAVAILABLE_MESSAGE}$"):
                result.authorize_and_forward(
                    compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                )
        self.assertEqual((replay.calls, transport.calls), ([], []))

    def test_verifier_rejection_and_unavailable_classification(self) -> None:
        for error, expected in (
            (OIDCVerificationError("token-marker"), BrokerRejectedError),
            (OIDCVerificationUnavailable("metadata-marker"), BrokerUnavailableError),
            (RuntimeError("dependency-marker"), BrokerUnavailableError),
        ):
            result, verifier, replay, transport = broker(verifier=Verifier(error=error))
            with self.subTest(error=type(error).__name__), self.assertRaises(expected) as captured:
                result.authorize_and_forward(
                    compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                )
            self.assertEqual(len(verifier.calls), 1)
            self.assertEqual((replay.calls, transport.calls), ([], []))
            self.assertNotIn("marker", str(captured.exception))

    def test_replay_duplicate_and_unavailable_classification(self) -> None:
        for error, expected in (
            (ReplayError("jti-marker"), BrokerRejectedError),
            (ReplayUnavailableError("sql-path-marker"), BrokerUnavailableError),
            (RuntimeError("dependency-marker"), BrokerUnavailableError),
        ):
            result, _, replay, transport = broker(replay=Replay(error=error))
            with self.subTest(error=type(error).__name__), self.assertRaises(expected) as captured:
                result.authorize_and_forward(
                    compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                )
            self.assertEqual(len(replay.calls), 1)
            self.assertEqual(transport.calls, [])
            self.assertNotIn("marker", str(captured.exception))

    def test_replay_raise_after_recording_never_transports_or_resets(self) -> None:
        replay = Replay(error=ReplayUnavailableError("after-recording-marker"))
        result, _, _, transport = broker(replay=replay)
        with self.assertRaises(BrokerUnavailableError):
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(transport.calls, [])
        self.assertFalse(hasattr(replay, "reset"))

    def test_transport_failure_leaves_replay_consumed_without_retry(self) -> None:
        result, _, replay, transport = broker(
            transport=Transport(error=RuntimeError("response-token-path-marker")),
        )
        with self.assertRaisesRegex(BrokerUnavailableError, f"^{UNAVAILABLE_MESSAGE}$") as captured:
            result.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(len(transport.calls), 1)
        self.assertNotIn("marker", str(captured.exception))

    def test_reentrant_transport_cannot_replay_or_transport_twice(self) -> None:
        replay = Replay()
        sends = 0
        holder: dict[str, RestrictedDeploymentBroker] = {}
        class ReentrantTransport:
            def send(inner_self, canonical_request: bytes) -> bytes:
                nonlocal sends
                sends += 1
                holder["broker"].authorize_and_forward(
                    compact_token=TOKEN, canonical_request=canonical_request,
                    received_at=NOW,
                )
                return RESPONSE
        class DefiniteReplay(Replay):
            def consume(inner_self, *args: object, **kwargs: object) -> None:
                super().consume(*args, **kwargs)  # type: ignore[arg-type]
                if len(inner_self.calls) > 1:
                    raise ReplayError("duplicate")
        replay = DefiniteReplay()
        holder["broker"] = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
            verifier=Verifier(), replay_guard=replay, transport=ReentrantTransport(),
        )
        with self.assertRaises(BrokerUnavailableError):
            holder["broker"].authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
        self.assertEqual(sends, 1)
        self.assertEqual(len(replay.calls), 2)

    def test_response_exact_bytes_type_and_bound(self) -> None:
        class BytesSubclass(bytes):
            pass
        class Misleading:
            def __len__(self) -> int:
                raise AssertionError("must-not-coerce")
            def __bytes__(self) -> bytes:
                return b"forged"
        for invalid in (
            "response", bytearray(b"response"), memoryview(b"response"),
            BytesSubclass(b"response"), Misleading(), object(),
            b"x" * (MAX_EXECUTOR_RESPONSE_BYTES + 1),
        ):
            result, _, replay, transport = broker(transport=Transport(invalid))
            with self.subTest(invalid=type(invalid).__name__), self.assertRaises(BrokerUnavailableError):
                result.authorize_and_forward(
                    compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                )
            self.assertEqual((len(replay.calls), len(transport.calls)), (1, 1))

    def test_maximum_response_bytes_pass(self) -> None:
        response = b"x" * MAX_EXECUTOR_RESPONSE_BYTES
        result, _, _, _ = broker(transport=Transport(response))
        self.assertIs(result.authorize_and_forward(
            compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
        ), response)

    def test_sensitive_values_never_appear_in_failures(self) -> None:
        markers = (
            TOKEN, identity().jti, str(identity().run_id),
            hashlib.sha256(request_bytes()).hexdigest(), "/var/lib/secret",
            "token=secret", "claims-marker", "sql-marker", "host.invalid",
        )
        for failure in (
            BrokerRejectedError(REJECTED_MESSAGE), BrokerUnavailableError(UNAVAILABLE_MESSAGE),
        ):
            for marker in markers:
                self.assertNotIn(marker, str(failure))

    def test_control_flow_exceptions_are_not_normalized(self) -> None:
        for error in (KeyboardInterrupt(), SystemExit(), GeneratorExit()):
            result, _, _, _ = broker(verifier=Verifier(error=error))
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                result.authorize_and_forward(
                    compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                )


class BrokerSQLiteIntegrationTests(unittest.TestCase):
    def make_guard(self, directory: str) -> SQLiteReplayGuard:
        return SQLiteReplayGuard(
            Path(directory) / "replay.sqlite3",
            expected_directory_uid=os.getuid(), expected_directory_gid=os.getgid(),
            current_time=lambda: NOW,
        )

    def test_real_sqlite_replay_persists_across_guard_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o2770)
            guard = self.make_guard(directory)
            guard.initialize()
            first = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
                verifier=Verifier(), replay_guard=guard, transport=Transport(),
            )
            first.authorize_and_forward(
                compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
            )
            second_transport = Transport()
            second = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
                verifier=Verifier(), replay_guard=self.make_guard(directory),
                transport=second_transport,
            )
            with self.assertRaises(BrokerRejectedError):
                second.authorize_and_forward(
                    compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                )
            self.assertEqual(second_transport.calls, [])

    def test_concurrent_identical_requests_have_one_transport_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o2770)
            guard = self.make_guard(directory)
            guard.initialize()
            lock = threading.Lock()
            transports = 0
            barrier = threading.Barrier(8)
            class CountingTransport:
                def send(inner_self, canonical_request: bytes) -> bytes:
                    nonlocal transports
                    with lock:
                        transports += 1
                    return RESPONSE
            result = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
                verifier=Verifier(), replay_guard=guard, transport=CountingTransport(),
            )
            outcomes: list[str] = []
            def contender() -> None:
                barrier.wait()
                try:
                    result.authorize_and_forward(
                        compact_token=TOKEN, canonical_request=request_bytes(), received_at=NOW,
                    )
                except BrokerRejectedError:
                    outcome = "rejected"
                else:
                    outcome = "success"
                with lock:
                    outcomes.append(outcome)
            threads = [threading.Thread(target=contender) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(outcomes.count("success"), 1)
            self.assertEqual(outcomes.count("rejected"), 7)
            self.assertEqual(transports, 1)


class BrokerStaticAuthorityTests(unittest.TestCase):
    def test_broker_imports_no_network_process_or_runtime_modules(self) -> None:
        path = ROOT / "deployment/broker.py"
        tree = ast.parse(path.read_text())
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertFalse(imports & {
            "docker", "http", "socket", "subprocess", "ssl", "urllib", "requests",
        })

    def test_broker_exposes_no_listener_command_path_or_persistence_api(self) -> None:
        public = {
            name for name, value in vars(RestrictedDeploymentBroker).items()
            if not name.startswith("_") and callable(value)
        }
        self.assertEqual(public, {"authorize_and_forward", "authorize_promotion_and_forward"})

    def test_source_has_no_mutable_global_collections(self) -> None:
        tree = ast.parse((ROOT / "deployment/broker.py").read_text())
        mutable = (ast.List, ast.Dict, ast.Set)
        assignments = [
            node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
        ]
        self.assertFalse(any(isinstance(getattr(node, "value", None), mutable) for node in assignments))


if __name__ == "__main__":
    unittest.main()
