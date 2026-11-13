"""File: deployment/tests/test_analytics_unix_boundary.py

Purpose: Isolated real Linux Task014-style Analytics private Unix transport,
         SO_PEERCRED connected receiver, sealed SCM_RIGHTS credential, exact
         release/request revalidation, preflight and original executor replay.
Related: deployment/analytics_unix_boundary.py,
         deployment/analytics_executor.py,
         deployment/analytics_promotion_broker.py,
         deployment/private_registry_fd.py, deployment/executor_server.py,
         deployment/unix_transport.py,
         deployment/tests/test_private_registry_end_to_end.py.

Sections: original callback fixtures, exact first-install receiver, adversarial
          private credential and request tests, real one-shot Unix socket flow,
          cross-product and incorrect peer denial; independent signed
          three-audience successor JWT verification with no deployment.

The synthetic operation and preflight are NOT a real Docker, PostgreSQL,
rootless executor or signed registry verification. No installed process,
external network, credentials or production path are used.
"""
from __future__ import annotations

import hashlib
from io import StringIO
import os
from contextlib import contextmanager, ExitStack
import subprocess
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from deployment.analytics_executor import AnalyticsPrivilegedExecutor
import deployment.analytics_unix_boundary as analytics_boundary
from deployment.analytics_unix_boundary import (
    AnalyticsUnixExecutorConnectionHandler,
    AnalyticsUnixExecutorTransport, AnalyticsUnixExecutorListener,
)
from deployment.analytics_signed_release_consumer import PINNED_IMAGE, PINNED_DIGEST
from deployment.analytics_active_state_review import AnalyticsActiveState
from deployment.executor import (
    ExecutorRejectedError, ExecutorUnavailableError,
    parse_canonical_response,
)
from deployment.executor_server import ExecutorConnectionUnavailableError
from deployment.private_registry_fd import (
    PrivateRegistryTransferError, create_sealed_credential,
    read_sealed_credential,
)
from deployment.private_registry_pull import current_private_zot_request
from deployment.unix_transport import (
    ExecutorTransportUnavailableError, UnixExecutorTransport,
)
from deployment.tests.test_analytics_execution import EXPECTED, fixture
from deployment.tests.test_executor import Replay
from deployment.tests.test_identity import NOW
from deployment.policy import canonical_bytes

REQUEST = canonical_bytes(fixture())
TOKEN = "synthetic-test-only-zot-auth-token"
CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


@contextmanager
def signed_owner_fixture(selected):
    """Generate a disposable *real* SSH Ed25519 owner approval fixture.

    The root-controlled public signer is mocked ONLY in this synthetic test.
    The original load_and_verify_owner_signed_source uses real OpenSSH,
    canonical signed bytes and actual O_NOFOLLOW filesystem reads. No owner
    private key or real /etc/omnilyzer anchor is created or contacted.
    """
    from release import analytics_owner_source_selection as owner
    from deployment import analytics_executor as executor_module

    with tempfile.TemporaryDirectory(prefix="task14b-owner-ed25519-") as dirname:
        root = Path(dirname)
        private = root / "fixture-owner-key"
        subprocess.run([
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private),
        ], check=True, capture_output=True, timeout=10)
        pub = private.with_suffix(".pub").read_text().strip()
        trust = (
            f'{owner.OWNER_SIGNER_IDENTITY} '
            f'namespaces="{owner.OWNER_APPROVAL_NAMESPACE}" {pub}\n'
        ).encode("ascii")
        approval = root / "signed-source.json"
        approval.write_bytes(owner.expected_owner_approval_bytes(selected))
        subprocess.run([
            "ssh-keygen", "-Y", "sign", "-f", str(private),
            "-n", owner.OWNER_APPROVAL_NAMESPACE, str(approval),
        ], check=True, capture_output=True, timeout=10)
        signature = root / "signed-source.json.sig"
        with (
            patch.object(owner, "_root_controlled_signers", return_value=trust),
            patch.object(executor_module, "_OWNER_APPROVAL_FILE", approval),
            patch.object(executor_module, "_OWNER_SIGNATURE_FILE", signature),
        ):
            yield approval, signature, trust


class SyntheticPreflight:
    """Test-only callback that checks the original Linux sealed descriptor."""

    def __init__(self, events: list[str], *, error: bool = False,
                 token: str = TOKEN):
        self.events, self.error, self.token = events, error, token

    def preflight_analytics(self, canonical_request, credential_fd):
        """Do no runtime action; assert broker request and sealed image scope."""
        self.events.append("private_manifest")
        assert canonical_request == REQUEST
        authority = read_sealed_credential(
            credential_fd, canonical_request=canonical_request,
            image=PINNED_IMAGE, now=NOW, product_id="analytics",
        )
        assert authority.token == self.token
        if self.error:
            raise OSError("synthetic image preflight failed")

    def preflight_analytics_successor(self, canonical_request, credential_fd):
        """Simulate the actual successor Zot manifest PROBE, never a pull."""
        from deployment.private_registry_fd import _successor_request_image
        self.events.append("successor_manifest_probe")
        image = _successor_request_image(canonical_request)
        authority = read_sealed_credential(
            credential_fd, canonical_request=canonical_request,
            image=image, now=NOW, product_id="analytics-successor",
        )
        assert authority.token == self.token
        if self.error:
            raise OSError("synthetic manifest probe failed")


class SyntheticFirstInstall:
    """Test-only marker that does NOT install a product or change any DB."""

    def __init__(self, events: list[str], *, error: bool = False,
                 token: str = TOKEN):
        self.events, self.error, self.token = events, error, token

    def deploy_analytics(self, request):
        """Record the exact reviewed request and simulate success/failure."""
        self.events.append("deploy_analytics")
        assert request.exact_image_reference == PINNED_IMAGE
        assert request.ingress_reference["public_origin"] is None
        assert request.rollback_reference["previous_digest"] is None
        assert request.rollback_reference["preserve_database_writes"] is True
        scoped = current_private_zot_request()
        assert scoped is not None
        fd, original = scoped
        assert original == REQUEST
        assert read_sealed_credential(
            fd, canonical_request=original, image=PINNED_IMAGE,
            now=NOW, product_id="analytics",
        ).token == self.token
        if self.error:
            raise OSError("synthetic private install failed")

    def rollback_first_analytics(self, request):
        """Synthetic no-op rollback for original executor failure paths."""
        self.events.append("rollback_first_analytics")
        return None


def receiver(*, events=None, fail_preflight=False, fail_deploy=False,
             token=TOKEN):
    """Assemble actual original replay and product-specific executor callbacks."""
    history = [] if events is None else events
    replay = Replay(history)
    executor = AnalyticsPrivilegedExecutor(
        replay_guard=replay,
        private_registry_preflight=SyntheticPreflight(
            history, error=fail_preflight, token=token,
        ),
        operation=SyntheticFirstInstall(history, error=fail_deploy, token=token),
        reviewed_installed_source=EXPECTED,
    )
    return executor, replay, history


def credential(*, image=PINNED_IMAGE, request=REQUEST, expires_at=NOW + 270,
               product_id="analytics"):
    """Create one real sealed synthetic capability with the original kernel API."""
    return create_sealed_credential(
        TOKEN, expires_at=expires_at, image=image,
        canonical_request=request, product_id=product_id, now=NOW,
    )


class AnalyticsExecutorPrivateTests(unittest.TestCase):
    """Receiver revalidates all fields without trusting broker-derived objects."""

    def setUp(self):
        self.clocks = [
            patch("deployment.analytics_executor.time.time", return_value=NOW),
            patch("deployment.private_registry_fd.time.time", return_value=NOW),
        ]
        for p in self.clocks:
            p.start()
            self.addCleanup(p.stop)

    def test_exact_first_install_replay_order_and_original_response(self):
        """Real sealed FD, double credential check then begin/deploy/finish."""
        executor, replay, events = receiver()
        fd = credential()
        try:
            reply = executor.execute_private(REQUEST, credential_fd=fd)
            result = parse_canonical_response(reply)
            self.assertEqual(
                result.executor_request_sha256, hashlib.sha256(REQUEST).hexdigest(),
            )
            self.assertEqual(
                events,
                ["private_manifest", "begin_execution", "deploy_analytics",
                 "finish_execution"],
            )
            self.assertEqual(len(replay.begin_calls), 1)
            self.assertEqual(len(replay.finish_calls), 1)
        finally:
            os.close(fd)

    def test_wrong_request_schema_or_fd_rejects_before_replay(self):
        """No canary, tampered request, absent FD or unreviewed root hashes."""
        executor, replay, events = receiver()
        fd = credential()
        try:
            for raw, credential_fd in (
                (b"{}", fd), (REQUEST + b" ", fd),
                (canonical_bytes({**fixture(), "stage": "prod"}), fd),
                (REQUEST, -1),
            ):
                with self.subTest(length=len(raw)), self.assertRaises(
                    (ExecutorRejectedError, ExecutorUnavailableError)
                ):
                    executor.execute_private(raw, credential_fd=credential_fd)
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(events, [])
        finally:
            os.close(fd)

    def test_unsealed_canary_or_wrong_digest_fd_never_works(self):
        """A synthetically accepted broker cannot bypass executor FD policy."""
        executor, replay, events = receiver()
        canary = (
            "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
            + "b" * 64
        )
        fd = credential(image=canary, product_id="canary")
        try:
            with self.assertRaises(ExecutorUnavailableError):
                executor.execute_private(REQUEST, credential_fd=fd)
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(events, [])
        finally:
            os.close(fd)

    def test_short_token_preflight_fail_and_deploy_fail_hold_replay(self):
        """Do not begin replay for invalid TTL or failed registry preflight."""
        for expires, preflight_failure in (
            (NOW + 224, False), (NOW + 270, True),
        ):
            executor, replay, events = receiver(fail_preflight=preflight_failure)
            fd = credential(expires_at=expires)
            try:
                with self.assertRaises(ExecutorUnavailableError):
                    executor.execute_private(REQUEST, credential_fd=fd)
                self.assertEqual(replay.begin_calls, [])
                self.assertNotIn("deploy_analytics", events)
            finally:
                os.close(fd)
        executor, replay, events = receiver(fail_deploy=True)
        fd = credential()
        try:
            with self.assertRaises(ExecutorUnavailableError):
                executor.execute_private(REQUEST, credential_fd=fd)
            self.assertEqual(len(replay.begin_calls), 1)
            self.assertEqual(replay.finish_calls, [])
        finally:
            os.close(fd)

    def test_constructor_strictly_requires_product_named_callbacks(self):
        """An original canary deploy() callback is not an Analytics installer."""
        class CanaryOnly:
            def deploy(self, request):
                return None

        with self.assertRaises(TypeError):
            AnalyticsPrivilegedExecutor(
                replay_guard=Replay([]),
                private_registry_preflight=SyntheticPreflight([]),
                operation=CanaryOnly(), reviewed_installed_source=EXPECTED,
            )
        with self.assertRaises(TypeError):
            AnalyticsPrivilegedExecutor(
                replay_guard=Replay([]),
                private_registry_preflight=SyntheticPreflight([]),
                operation=SyntheticFirstInstall([]),
                reviewed_installed_source={
                    **EXPECTED, "reviewed_compose_sha256": "invalid",
                },
            )

    def test_original_canary_handler_transport_still_refuses_analytics(self):
        """No automatic schema-v2 support is added to ordinary canary socket."""
        from deployment.executor_server import UnixExecutorConnectionHandler
        with self.assertRaises(TypeError):
            UnixExecutorConnectionHandler(
                executor=object(), expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), private_registry_transfer=True,
            )
        transport = UnixExecutorTransport(
            expected_executor_uid=os.getuid(),
            expected_executor_gid=os.getgid(),
            expected_socket_group_gid=os.getgid(),
        )
        self.assertFalse(hasattr(transport, "_send_analytics_private"))


class AnalyticsActualUnixSocketTests(unittest.TestCase):
    """Actual AF_UNIX and SO_PEERCRED with no host root or network."""

    def setUp(self):
        self.clock1 = patch(
            "deployment.analytics_executor.time.time", return_value=NOW,
        )
        self.clock2 = patch(
            "deployment.private_registry_fd.time.time", return_value=NOW,
        )
        self.clock1.start()
        self.clock2.start()
        self.addCleanup(self.clock1.stop)
        self.addCleanup(self.clock2.stop)

    def test_first_successor_preflight_observes_real_slot_shape_without_deploy(self):
        """Sealed successor FD + independent active/candidate + Zot PROBE only."""
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        from dataclasses import replace

        raw_model, source = AnalyticsSuccessorRequestTests().candidate()
        self.enterContext(signed_owner_fixture(source["selected"]))
        raw = canonical_bytes(raw_model)
        image = raw_model["exact_image_reference"]
        state = AnalyticsActiveState(
            schema_version=1, active_slot="blue", active_digest=PINNED_DIGEST,
            active_image=PINNED_IMAGE, active_container_id="a" * 64,
            active_child_ip="172.20.0.3", active_network_id="f" * 64,
            private_ingress_port=3141, candidate_slot="green",
            candidate_port=3142, candidate_probe_present=True,
            candidate_digest=raw_model["manifest_digest"],
            candidate_container_id="b" * 64,
        )
        executor, replay, events = receiver()
        fd = credential(request=raw, image=image, product_id="analytics-successor")
        try:
            with (
                patch("deployment.analytics_executor.os.geteuid", return_value=991),
                patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                      return_value=state) as inspector,
            ):
                self.assertIsNone(executor.preflight_first_successor_without_deployment(
                    raw, credential_fd=fd,
                ))
            self.assertEqual(inspector.call_count, 2)
            self.assertEqual(events, ["successor_manifest_probe"])
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(replay.finish_calls, [])

            # Runtime changes during the manifest network probe fail closed.
            with (
                patch("deployment.analytics_executor.os.geteuid", return_value=991),
                patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                      side_effect=(state, replace(state, active_container_id="c" * 64))),
                self.assertRaises(ExecutorUnavailableError),
            ):
                executor.preflight_first_successor_without_deployment(
                    raw, credential_fd=fd,
                )
            self.assertEqual(events, ["successor_manifest_probe"] * 2)
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(replay.finish_calls, [])
        finally:
            os.close(fd)

    # Section: generation3-only closed, redacted local preflight diagnostics.
    def test_private_preflight_trace_distinguishes_six_fail_closed_gates(self):
        """One static UID991 phase per subgate, no JTI, JWT or inner exception."""
        from dataclasses import replace
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.tests.test_analytics_private_registry import (
            first_successor_empty_active_state,
        )

        candidate, context = AnalyticsSuccessorRequestTests().candidate()
        self.enterContext(signed_owner_fixture(context["selected"]))
        raw = canonical_bytes(candidate)
        state = first_successor_empty_active_state()
        fd = credential(
            request=raw, image=candidate["exact_image_reference"],
            product_id="analytics-successor",
        )
        self.addCleanup(os.close, fd)

        # All test-only recipients and JWTs are synthetic local fixtures.
        cases = (
            "private_owner", "private_active", "private_slot",
            "private_credential", "private_manifest", "private_stability",
        )
        for failure in cases:
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(patch(
                    "deployment.analytics_executor.os.getuid", return_value=991,
                ))
                stack.enter_context(patch(
                    "deployment.analytics_executor.os.geteuid", return_value=991,
                ))
                stack.enter_context(patch(
                    "deployment.analytics_executor.os.getgid", return_value=991,
                ))
                stack.enter_context(patch(
                    "deployment.analytics_executor.os.getegid", return_value=991,
                ))
                inspector = stack.enter_context(patch(
                    "deployment.analytics_active_state_review."
                    "inspect_analytics_active_state",
                    return_value=state,
                ))
                slot = stack.enter_context(patch(
                    "deployment.analytics_active_state_review."
                    "verify_empty_analytics_successor_slot",
                    return_value=None,
                ))
                executor, replay, events = receiver(
                    fail_preflight=failure == "private_manifest",
                )
                if failure == "private_owner":
                    stack.enter_context(patch(
                        "deployment.analytics_executor._verify_executor_owner_source",
                        side_effect=ValueError("synthetic-secret-do-not-log"),
                    ))
                elif failure == "private_active":
                    inspector.return_value = replace(state, active_slot="green")
                elif failure == "private_slot":
                    slot.side_effect = ValueError(
                        "synthetic-secret-do-not-log",
                    )
                elif failure == "private_credential":
                    stack.enter_context(patch(
                        "deployment.analytics_executor.read_sealed_credential",
                        side_effect=ValueError("synthetic-secret-do-not-log"),
                    ))
                elif failure == "private_stability":
                    inspector.side_effect = (
                        state, replace(state, active_container_id="f" * 64),
                    )
                with patch(
                    "deployment.analytics_executor.sys.stderr",
                    new=StringIO(),
                ) as stderr:
                    with self.assertRaises(ExecutorUnavailableError):
                        executor.preflight_first_successor_without_deployment(
                            raw, credential_fd=fd, candidate_ready=False,
                            trace_generation3=True,
                        )
                self.assertEqual(
                    stderr.getvalue(),
                    "TASK014_ANALYTICS_UID991_HOLD phase=" + failure + "\n",
                )
                self.assertEqual(replay.begin_calls, [])
                self.assertEqual(replay.finish_calls, [])
                self.assertNotIn("synthetic-secret", stderr.getvalue())

    def test_private_preflight_default_silent_and_trace_type_fail_closed(self):
        """Legacy/default calls do not disclose a UID991 stage or bypass DENY."""
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.tests.test_analytics_private_registry import (
            first_successor_empty_active_state,
        )

        data, context = AnalyticsSuccessorRequestTests().candidate()
        self.enterContext(signed_owner_fixture(context["selected"]))
        raw = canonical_bytes(data)
        fd = credential(
            request=raw, image=data["exact_image_reference"],
            product_id="analytics-successor",
        )
        self.addCleanup(os.close, fd)
        executor, replay, events = receiver(fail_preflight=True)
        with (
            patch("deployment.analytics_executor.os.getuid", return_value=991),
            patch("deployment.analytics_executor.os.geteuid", return_value=991),
            patch("deployment.analytics_executor.os.getgid", return_value=991),
            patch("deployment.analytics_executor.os.getegid", return_value=991),
            patch(
                "deployment.analytics_active_state_review."
                "inspect_analytics_active_state",
                return_value=first_successor_empty_active_state(),
            ),
            patch(
                "deployment.analytics_active_state_review."
                "verify_empty_analytics_successor_slot", return_value=None,
            ),
            patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr,
        ):
            with self.assertRaises(ExecutorUnavailableError):
                executor.preflight_first_successor_without_deployment(
                    raw, credential_fd=fd, candidate_ready=False,
                )
            self.assertEqual(stderr.getvalue(), "")
            for invalid in (None, 1, "true", [], {}):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ExecutorRejectedError):
                        executor.preflight_first_successor_without_deployment(
                            raw, credential_fd=fd, candidate_ready=False,
                            trace_generation3=invalid,
                        )
            self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(replay.begin_calls, [])
        self.assertEqual(replay.finish_calls, [])

    def test_first_successor_pre_pull_and_post_pull_gates_are_disjoint(self):
        """Avoid a first-release startup deadlock without relaxing final GO.

        The new, internally selected pre-pull phase requires a healthy signed
        blue 0.15.0 with *no* candidate route. The existing default continues
        to require independently probed, healthy green before any cutover.
        Both paths perform real owner Ed25519 fixture verification, sealed-FD
        scope and the same successor manifest probe, but never deploy.
        """
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        from dataclasses import replace

        data, context = AnalyticsSuccessorRequestTests().candidate()
        self.enterContext(signed_owner_fixture(context["selected"]))
        raw = canonical_bytes(data)
        staged = AnalyticsActiveState(
            schema_version=1, active_slot="blue", active_digest=PINNED_DIGEST,
            active_image=PINNED_IMAGE, active_container_id="a" * 64,
            active_child_ip="172.20.0.3", active_network_id="f" * 64,
            private_ingress_port=3141, candidate_slot="green",
            candidate_port=3142, candidate_probe_present=True,
            candidate_digest=data["manifest_digest"],
            candidate_container_id="b" * 64,
        )
        empty = replace(
            staged, candidate_probe_present=False,
            candidate_digest=None, candidate_container_id=None,
        )
        executor, replay, events = receiver()
        fd = credential(
            request=raw, image=data["exact_image_reference"],
            product_id="analytics-successor",
        )
        try:
            with (
                patch("deployment.analytics_executor.os.geteuid", return_value=991),
                patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                      return_value=empty) as inspection,
                patch("deployment.analytics_active_state_review.verify_empty_analytics_successor_slot",
                      return_value=None) as absent_inventory,
            ):
                self.assertIsNone(
                    executor.preflight_first_successor_without_deployment(
                        raw, credential_fd=fd, candidate_ready=False,
                    )
                )
            self.assertEqual(inspection.call_count, 2)
            self.assertEqual(absent_inventory.call_count, 2)
            self.assertEqual(events, ["successor_manifest_probe"])
            for candidate_state, required in (
                (empty, True), (staged, False),
                (replace(empty, candidate_digest=data["manifest_digest"]), False),
                (replace(empty, candidate_probe_present=True), False),
            ):
                with (
                    self.subTest(ready=required, observed=candidate_state),
                    patch("deployment.analytics_executor.os.geteuid", return_value=991),
                    patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                          return_value=candidate_state),
                    self.assertRaises(ExecutorUnavailableError),
                ):
                    executor.preflight_first_successor_without_deployment(
                        raw, credential_fd=fd, candidate_ready=required,
                    )
            # Even a verified 3141 route is insufficient when an orphaned
            # candidate or an uncertain Docker inventory blocks cold pull.
            with (
                patch("deployment.analytics_executor.os.geteuid", return_value=991),
                patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                      return_value=empty),
                patch("deployment.analytics_active_state_review.verify_empty_analytics_successor_slot",
                      side_effect=RuntimeError("existing green container")),
                self.assertRaises(ExecutorUnavailableError),
            ):
                executor.preflight_first_successor_without_deployment(
                    raw, credential_fd=fd, candidate_ready=False,
                )
            for value in (None, 1, "false", [], {}):
                with self.subTest(candidate_ready=value), self.assertRaises(
                        ExecutorRejectedError):
                    executor.preflight_first_successor_without_deployment(
                        raw, credential_fd=fd, candidate_ready=value,
                    )
            self.assertEqual(events, ["successor_manifest_probe"])
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(replay.finish_calls, [])
        finally:
            os.close(fd)

    def test_first_successor_preflight_denies_wrong_live_state_and_fd(self):
        """No credential, forged state, wrong UID or callback invokes replay."""
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        from dataclasses import replace

        raw_model, source = AnalyticsSuccessorRequestTests().candidate()
        self.enterContext(signed_owner_fixture(source["selected"]))
        raw = canonical_bytes(raw_model)
        image = raw_model["exact_image_reference"]
        state = AnalyticsActiveState(
            schema_version=1, active_slot="blue", active_digest=PINNED_DIGEST,
            active_image=PINNED_IMAGE, active_container_id="a" * 64,
            active_child_ip="172.20.0.3", active_network_id="f" * 64,
            private_ingress_port=3141, candidate_slot="green",
            candidate_port=3142, candidate_probe_present=True,
            candidate_digest=raw_model["manifest_digest"],
            candidate_container_id="b" * 64,
        )
        executor, replay, events = receiver()
        fd = credential(request=raw, image=image, product_id="analytics-successor")
        old_fd = credential()
        try:
            variants = (
                (raw, fd, state, 1005),
                (raw, old_fd, state, 991),
                (raw, fd, replace(state, active_digest="sha256:" + "a" * 64), 991),
                (raw, fd, replace(state, active_slot="green"), 991),
                (raw, fd, replace(state, candidate_probe_present=False), 991),
                (raw, fd, replace(state, candidate_digest="sha256:" + "c" * 64), 991),
                (canonical_bytes({**raw_model, "rollback_reference": {
                    **raw_model["rollback_reference"], "previous_slot": "green",
                }}), fd, state, 991),
            )
            for request, token_fd, observed, uid in variants:
                with (
                    self.subTest(uid=uid, digest=observed.candidate_digest,
                                 old_fd=token_fd is old_fd),
                    patch("deployment.analytics_executor.os.geteuid", return_value=uid),
                    patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                          return_value=observed),
                    self.assertRaises(ExecutorUnavailableError),
                ):
                    executor.preflight_first_successor_without_deployment(
                        request, credential_fd=token_fd,
                    )
            self.assertEqual(events, [])
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(replay.finish_calls, [])
            with self.assertRaises(ExecutorRejectedError):
                executor.preflight_first_successor_without_deployment(raw, credential_fd=-1)
        finally:
            os.close(fd)
            os.close(old_fd)

    def test_successor_executor_rechecks_actual_owner_ed25519_before_host_io(self):
        """Verify owner source independently, reject tamper/different approval."""
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        from deployment import analytics_executor as executor_module
        from release import analytics_owner_source_selection as owner

        candidate, context = AnalyticsSuccessorRequestTests().candidate()
        selected = context["selected"]
        with signed_owner_fixture(selected) as (approval, signature, trust):
            self.assertIsNone(executor_module._verify_executor_owner_source(candidate))
            for key, bad in (
                ("owner_approval_sha256", "f" * 64),
                ("source_sha", "a" * 40),
                ("product_source_sha", "b" * 40),
                ("release_version", "9.9.9"),
            ):
                with self.subTest(field=key), self.assertRaises(ValueError):
                    executor_module._verify_executor_owner_source({**candidate, key: bad})
            prior = signature.read_bytes()
            signature.write_bytes(prior[:-4] + b"AAAA")
            with self.assertRaises(owner.AnalyticsOwnerSourceSelectionDenied):
                executor_module._verify_executor_owner_source(candidate)
            signature.write_bytes(prior)
            with patch.object(owner, "_root_controlled_signers", side_effect=(
                owner.AnalyticsOwnerSourceSelectionDenied("missing root anchor")
            )), self.assertRaises(owner.AnalyticsOwnerSourceSelectionDenied):
                executor_module._verify_executor_owner_source(candidate)
            approval.unlink()
            with self.assertRaises(owner.AnalyticsOwnerSourceSelectionDenied):
                executor_module._verify_executor_owner_source(candidate)

    def test_first_successor_owner_anchor_missing_denies_before_registry_or_docker(self):
        """Missing real root trust stops before any host read or replay."""
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        from release import analytics_owner_source_selection as owner

        candidate, _ = AnalyticsSuccessorRequestTests().candidate()
        raw = canonical_bytes(candidate)
        executor, replay, events = receiver()
        fd = credential(
            request=raw, image=candidate["exact_image_reference"],
            product_id="analytics-successor",
        )
        try:
            with (
                patch("deployment.analytics_executor.os.geteuid", return_value=991),
                patch.object(owner, "_root_controlled_signers", side_effect=(
                    owner.AnalyticsOwnerSourceSelectionDenied("no real root key")
                )),
                patch("deployment.analytics_active_state_review.inspect_analytics_active_state") as observed,
                self.assertRaises(ExecutorUnavailableError),
            ):
                executor.preflight_first_successor_without_deployment(
                    raw, credential_fd=fd,
                )
            observed.assert_not_called()
            self.assertEqual(events, [])
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(replay.finish_calls, [])
        finally:
            os.close(fd)

    def test_systemd_analytics_listener_transfers_descriptor_after_exact_peer_check(self):
        """Join the real Analytics sender to the real shared PID1 decision."""
        from deployment import unix_transport as wire
        from deployment.tests.test_unix_transport import FakeSocket, metadata, Clock, RESPONSE, PEER
        fd = credential()
        try:
            for pid, uid, gid in ((1,0,0),(2,0,0),(1,1,0),(1,0,1)):
                fake = FakeSocket(peer=PEER.pack(pid,uid,gid))
                with patch.object(wire.os, 'lstat', side_effect=[metadata(uid=991,gid=993),metadata(uid=991,gid=993)]), patch.object(wire.socket, 'socket', return_value=fake), patch.object(wire.time, 'monotonic', Clock()), patch.object(wire, 'send_sealed_header') as send:
                    transport = AnalyticsUnixExecutorTransport(expected_executor_uid=991,expected_executor_gid=991,expected_socket_group_gid=993,reviewed_installed_source=EXPECTED)
                    if (pid,uid,gid)==(1,0,0):
                        self.assertEqual(transport._send_analytics_private(REQUEST,credential_fd=fd), RESPONSE)
                        send.assert_called_once_with(fake,len(REQUEST).to_bytes(4,'big'),fd)
                    else:
                        with self.assertRaises(ExecutorTransportUnavailableError):transport._send_analytics_private(REQUEST,credential_fd=fd)
                        send.assert_not_called()
                self.assertTrue(fake.closed)
        finally:os.close(fd)

    def test_systemd_peer_does_not_approve_foreign_paths_or_replaced_inodes(self):
        from deployment import unix_transport as wire
        from deployment.tests.test_unix_transport import FakeSocket, metadata, Clock, PEER
        fd = credential()
        try:
            for path, after in (('/tmp/unreviewed-analytics.sock', metadata(uid=991,gid=993)), (analytics_boundary.ANALYTICS_EXECUTOR_SOCKET_PATH, metadata(uid=991,gid=993,inode=999))):
                fake = FakeSocket(peer=PEER.pack(1,0,0))
                with patch.object(analytics_boundary,'ANALYTICS_EXECUTOR_SOCKET_PATH',path), patch.object(wire.os,'lstat',side_effect=[metadata(uid=991,gid=993),after]), patch.object(wire.socket,'socket',return_value=fake), patch.object(wire.time,'monotonic',Clock()), patch.object(wire,'send_sealed_header') as send:
                    transport=AnalyticsUnixExecutorTransport(expected_executor_uid=991,expected_executor_gid=991,expected_socket_group_gid=993,reviewed_installed_source=EXPECTED)
                    with self.assertRaises(ExecutorTransportUnavailableError):transport._send_analytics_private(REQUEST,credential_fd=fd)
                    send.assert_not_called()
                self.assertTrue(fake.closed)
        finally:os.close(fd)

    def test_schema3_scoped_fd_uses_original_peer_checked_analytics_socket(self):
        """Real sealed successor FD crosses original transport, no deployment.

        Original schema-2 receiver is NOT broadened and still denies a
        successor. This test only covers the reused socket/credential
        transport, not source-signature or release authority.
        """
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.tests.test_unix_transport import (
            FakeSocket, metadata, Clock, RESPONSE, PEER,
        )
        from deployment import unix_transport as wire

        request, _ = AnalyticsSuccessorRequestTests().candidate()
        raw = canonical_bytes(request)
        image = request["exact_image_reference"]
        successor_fd = credential(
            image=image, request=raw, product_id="analytics-successor",
        )
        old_fd = credential()
        try:
            self.assertFalse(
                hasattr(UnixExecutorTransport, "_send_analytics_successor_private")
            )
            for payload, source_fd in (
                (raw, successor_fd),
                (raw + b" ", successor_fd),
                (raw, old_fd),
                (canonical_bytes({**request, "stage": "prod"}), successor_fd),
                (canonical_bytes({
                    **request, "exact_image_reference": PINNED_IMAGE,
                }), successor_fd),
            ):
                fake = FakeSocket(peer=PEER.pack(1, 0, 0))
                with (
                    self.subTest(
                        valid=payload == raw and source_fd == successor_fd,
                    ),
                    patch.object(
                        wire.os, "lstat",
                        side_effect=[
                            metadata(uid=991, gid=993),
                            metadata(uid=991, gid=993),
                        ],
                    ),
                    patch.object(wire.socket, "socket", return_value=fake),
                    patch.object(wire.time, "monotonic", Clock()),
                    patch.object(wire, "send_sealed_header") as sent,
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=991, expected_executor_gid=991,
                        expected_socket_group_gid=993,
                        reviewed_installed_source=EXPECTED,
                    )
                    if payload == raw and source_fd == successor_fd:
                        self.assertEqual(
                            transport._send_analytics_successor_private(
                                payload, credential_fd=source_fd,
                            ), RESPONSE,
                        )
                        sent.assert_called_once_with(
                            fake, len(raw).to_bytes(4, "big"), successor_fd,
                        )
                    else:
                        with self.assertRaises(ExecutorTransportUnavailableError):
                            transport._send_analytics_successor_private(
                                payload, credential_fd=source_fd,
                            )
                        sent.assert_not_called()
                if payload == raw and source_fd == successor_fd:
                    self.assertTrue(fake.closed)
            # Sending from any previous v2 helper remains impossible.
            with self.assertRaises(ExecutorTransportUnavailableError):
                transport._send_analytics_private(raw, credential_fd=successor_fd)
        finally:
            os.close(successor_fd)
            os.close(old_fd)

    def test_successor_real_unix_fd_reaches_original_executor_and_stops_before_replay(self):
        """Prove schema3 can cross the kernel boundary, NOT deploy through v2.

        Real AF_UNIX, kernel SO_PEERCRED, sealed FD + SCM_RIGHTS and framing
        execute in an isolated temporary socket. Original executor continues
        to reject the successor prior to preflight, replay and Docker.
        """
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )

        candidate, _context = AnalyticsSuccessorRequestTests().candidate()
        raw = canonical_bytes(candidate)
        image = candidate["exact_image_reference"]
        executor, replay, events = receiver()
        with tempfile.TemporaryDirectory(prefix="task14b-successor-socket-") as root:
            path = str(Path(root) / "analytics.sock")
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=executor,
                expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(),
                reviewed_installed_source=EXPECTED,
                structural_successor_receive_only=True,
            )
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o660)
            listener.listen(1)
            listener.settimeout(3)
            failures = []

            def serve():
                """Accept only one local successor request, never start Docker."""
                try:
                    child, _ = listener.accept()
                    handler.handle(child)
                except ExecutorConnectionUnavailableError:
                    failures.append("schema2-executor-denied")
                except BaseException as unexpected:
                    failures.append(type(unexpected).__name__)

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            fd = credential(
                request=raw, image=image, product_id="analytics-successor",
            )
            try:
                with (
                    patch.object(
                        analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", path,
                    ),
                    patch.object(
                        analytics_boundary, "read_sealed_credential",
                        wraps=read_sealed_credential,
                    ) as credential_reader,
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                    with self.assertRaises(ExecutorTransportUnavailableError):
                        transport._send_analytics_successor_private(
                            raw, credential_fd=fd,
                        )
                # Both sender and receiver inspect the exact sealed
                # capability before the original v2 executor rejects it.
                self.assertGreaterEqual(credential_reader.call_count, 2)
            finally:
                os.close(fd)
                server.join(5)
                listener.close()
            self.assertFalse(server.is_alive())
            self.assertEqual(failures, ["schema2-executor-denied"])
            self.assertEqual(events, [])
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(replay.finish_calls, [])

    def test_successor_read_only_probe_real_unix_fd_never_reports_deploy(self):
        """Real SO_PEERCRED + SCM_RIGHTS enters UID991 proof, then DENIES.

        This is a disposable socket with a SYNTHETIC observed host snapshot
        and credential, not a live release or a signed deployment acceptance.
        """
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests

        candidate, source = AnalyticsSuccessorRequestTests().candidate()
        self.enterContext(signed_owner_fixture(source["selected"]))
        raw = canonical_bytes(candidate)
        state = AnalyticsActiveState(
            schema_version=1, active_slot="blue", active_digest=PINNED_DIGEST,
            active_image=PINNED_IMAGE, active_container_id="a" * 64,
            active_child_ip="172.20.0.3", active_network_id="f" * 64,
            private_ingress_port=3141, candidate_slot="green",
            candidate_port=3142, candidate_probe_present=True,
            candidate_digest=candidate["manifest_digest"],
            candidate_container_id="b" * 64,
        )
        executor, replay, events = receiver()
        with tempfile.TemporaryDirectory(prefix="task14b-schema3-review-") as tmp:
            path = str(Path(tmp) / "socket")
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(),
                reviewed_installed_source=EXPECTED,
                verified_successor_preflight_only=True,
            )
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o660)
            listener.listen(1)
            listener.settimeout(3)
            failures: list[str] = []

            def serve():
                """Serve one protected local request and refuse all promotion."""
                try:
                    accepted, _ = listener.accept()
                    handler.handle(accepted)
                except ExecutorConnectionUnavailableError:
                    failures.append("read-only-probe-denied")
                except BaseException as problem:
                    failures.append(type(problem).__name__)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            fd = credential(
                request=raw, image=candidate["exact_image_reference"],
                product_id="analytics-successor",
            )
            try:
                with (
                    patch.object(analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", path),
                    patch("deployment.analytics_executor.os.geteuid", return_value=991),
                    patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                          return_value=state) as inspected,
                    patch.object(analytics_boundary, "read_sealed_credential",
                                 wraps=read_sealed_credential) as read_fd,
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                    with self.assertRaises(ExecutorTransportUnavailableError):
                        transport._send_analytics_successor_private(
                            raw, credential_fd=fd,
                        )
                self.assertEqual(inspected.call_count, 2)
                self.assertGreaterEqual(read_fd.call_count, 2)
            finally:
                os.close(fd)
                worker.join(5)
                listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, ["read-only-probe-denied"])
        self.assertEqual(events, ["successor_manifest_probe"])
        self.assertEqual(replay.begin_calls, [])
        self.assertEqual(replay.finish_calls, [])

    def test_successor_probe_receiver_never_combines_with_structural_mode(self):
        """No mixed dispatch mode or accidental default schema-3 allowance."""
        executor, replay, events = receiver()
        with self.assertRaises(TypeError):
            AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
                structural_successor_receive_only=True,
                verified_successor_preflight_only=True,
            )
        with self.assertRaises(TypeError):
            AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
                verified_successor_preflight_only=1,
            )
        self.assertEqual(events, [])
        self.assertEqual(replay.begin_calls, [])

    def test_broker_review_to_uid991_read_only_socket_denies_promotion(self):
        """Join reviewed OIDC/source, real signed owner, kernel FD and UID991.

        Registry release receipts and OCI observations are synthetic. This
        proves rejection across one real local socket, never a live release.
        """
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        from deployment.tests.test_analytics_promotion_broker import (
            make_broker, evidence, AnalyticsFirstSuccessorBrokerReviewTests,
        )
        from deployment.broker import BrokerUnavailableError

        request, context = AnalyticsSuccessorRequestTests().candidate()
        payload = canonical_bytes(request)
        observed = AnalyticsActiveState(
            schema_version=1, active_slot="blue", active_digest=PINNED_DIGEST,
            active_image=PINNED_IMAGE, active_container_id="a" * 64,
            active_child_ip="172.20.0.3", active_network_id="f" * 64,
            private_ingress_port=3141, candidate_slot="green",
            candidate_port=3142, candidate_probe_present=True,
            candidate_digest=request["manifest_digest"],
            candidate_container_id="b" * 64,
        )
        executor, replay, events = receiver(
            token=AnalyticsFirstSuccessorBrokerReviewTests.kwargs(payload)["zot_token"],
        )
        with tempfile.TemporaryDirectory(prefix="task14b-full-review-") as folder, (
            signed_owner_fixture(context["selected"])
        ) as (approval, signature, _signers):
            location = str(Path(folder) / "executor.sock")
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
                verified_successor_preflight_only=True,
            )
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(location)
            os.chmod(location, 0o660)
            listener.listen(1)
            listener.settimeout(4)
            failures = []

            def serve():
                """Process one genuine kernel-framed request; reject promotion."""
                try:
                    connected, _ = listener.accept()
                    handler.handle(connected)
                except ExecutorConnectionUnavailableError:
                    failures.append("denied")
                except BaseException as err:
                    failures.append(type(err).__name__)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                with (
                    patch.object(analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", location),
                    patch("deployment.analytics_executor.os.geteuid", return_value=991),
                    patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                          return_value=observed) as inspection,
                    patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                          return_value=evidence()) as old,
                    patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                          return_value=context["signed_release"]) as next_release,
                    patch("deployment.analytics_promotion_broker.time.time", return_value=NOW),
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                    broker, broker_replay, _ = make_broker(
                        owner_files=(approval, signature), transport=transport,
                    )
                    before = set(os.listdir("/proc/self/fd"))
                    with self.assertRaises(BrokerUnavailableError):
                        broker.forward_verified_first_successor_probe_without_deployment(
                            **AnalyticsFirstSuccessorBrokerReviewTests.kwargs(payload)
                        )
                    # A response can precede receiver socket close by one
                    # scheduling quantum. Join before assessing actual FD leaks.
                    worker.join(5)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(before, set(os.listdir("/proc/self/fd")))
                    self.assertEqual(broker_replay.calls, [])
                    old.assert_called_once()
                    next_release.assert_called_once()
                    self.assertEqual(inspection.call_count, 2)
            finally:
                worker.join(5)
                listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, ["denied"])
        self.assertEqual(events, ["successor_manifest_probe"])
        self.assertEqual(replay.begin_calls, [])
        self.assertEqual(replay.finish_calls, [])

    def test_broker_invalid_detached_owner_signature_does_not_send_successor(self):
        """Reject tampered real OpenSSH signature before any sealed-FD send.

        Original OIDC and signed-review mocks are isolated test fixtures;
        actual owner Ed25519 verification is NOT mocked on this path.
        """
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        from deployment.tests.test_analytics_promotion_broker import (
            make_broker, evidence, ReadOnlySuccessorProbeTransport,
            AnalyticsFirstSuccessorBrokerReviewTests,
        )
        from deployment.broker import BrokerUnavailableError
        request, context = AnalyticsSuccessorRequestTests().candidate()
        raw = canonical_bytes(request)
        with signed_owner_fixture(context["selected"]) as (approval, signature, _):
            signed = signature.read_bytes()
            signature.write_bytes(signed[:-5] + b"AAAAA")
            candidate = ReadOnlySuccessorProbeTransport()
            broker, replay, _ = make_broker(
                owner_files=(approval, signature), transport=candidate,
            )
            with (
                patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                      return_value=evidence()) as original,
                patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release") as successor,
                patch("deployment.analytics_promotion_broker.create_sealed_credential") as seal,
                self.assertRaises(BrokerUnavailableError),
            ):
                broker.forward_verified_first_successor_probe_without_deployment(
                    **AnalyticsFirstSuccessorBrokerReviewTests.kwargs(raw)
                )
            original.assert_called_once()
            successor.assert_not_called()
            seal.assert_not_called()
            self.assertEqual(candidate.checked, [])
            self.assertEqual(replay.calls, [])

    def test_real_analytics_unix_socket_and_sealed_fd_roundtrip(self):
        """Reuse original metadata, peer, expiry, framing and response checks."""
        with tempfile.TemporaryDirectory(prefix="m05-14-analytics-unix-") as root:
            path = str(Path(root) / "executor.sock")
            executor, replay, events = receiver()
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(),
                reviewed_installed_source=EXPECTED,
            )
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o660)
            listener.listen(1)
            listener.settimeout(3)
            errors = []

            def serve():
                """Provide only a local, disposable one-shot socket service."""
                try:
                    client, _ = listener.accept()
                    handler.handle(client)
                except BaseException as exc:
                    errors.append(exc)

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            try:
                with patch.object(
                    analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", path
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                fd = credential()
                try:
                    before = set(os.listdir("/proc/self/fd"))
                    reply = transport._send_analytics_private(
                        REQUEST, credential_fd=fd,
                    )
                    # Wait for the receiver's finally/socket close. The
                    # client receiving a reply does not imply the other
                    # thread has already closed its accepted descriptor.
                    server.join(5)
                    self.assertFalse(server.is_alive())
                    after = set(os.listdir("/proc/self/fd"))
                    self.assertEqual(before, after)
                    self.assertEqual(
                        parse_canonical_response(reply).executor_request_sha256,
                        hashlib.sha256(REQUEST).hexdigest(),
                    )
                finally:
                    os.close(fd)
            finally:
                server.join(5)
                listener.close()
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(
                events,
                ["private_manifest", "begin_execution",
                 "deploy_analytics", "finish_execution"],
            )
            self.assertEqual(len(replay.begin_calls), 1)
            self.assertEqual(len(replay.finish_calls), 1)

    def test_full_broker_jwt_to_real_unix_credential_and_durable_sqlite(self):
        """Real local socket+memfd+SQLite; synthetic external signature result.

        This is end-to-end Task014 CONTROL FLOW, not live signed registry,
        Docker image, PostgreSQL, or an approved installation.
        """
        from deployment.replay_sqlite import SQLiteReplayGuard
        from deployment.analytics_promotion_broker import AnalyticsPrivatePromotionBroker
        from deployment.tests.test_analytics_promotion_broker import evidence
        from deployment.tests.test_analytics_review_composition import handler as review_handler
        from deployment.tests.test_broker import Verifier
        from deployment.tests.test_broker_integration import (
            TOKEN as DEPLOYMENT_TOKEN, ZOT_TOKEN, FORGEJO_TOKEN, KEY,
        )
        from deployment.tests.test_identity import WORKFLOW_SHA
        from deployment.tests.test_registry_oidc_credentials import StaticCache

        with tempfile.TemporaryDirectory(prefix="m05-14-full-chain-") as root:
            base = Path(root)
            # The ORIGINAL SQLite replay guard rejects unrelated directory
            # entries, including an executor socket. Keep the protected
            # replay directory separate from the AF_UNIX socket parent.
            replay_dir = base / "replay"
            replay_dir.mkdir(mode=0o2770)
            replay_dir.chmod(0o2770)
            replay = SQLiteReplayGuard(
                replay_dir / "replay.sqlite3", expected_directory_uid=os.getuid(),
                expected_directory_gid=os.getgid(), current_time=lambda: NOW,
            )
            replay.initialize()
            socket_path = str(base / "analytics-executor.sock")
            server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server_socket.bind(socket_path)
            os.chmod(socket_path, 0o660)
            server_socket.listen(1)
            server_socket.settimeout(3)
            events = []
            privileged = AnalyticsPrivilegedExecutor(
                replay_guard=replay,
                private_registry_preflight=SyntheticPreflight(
                    events, token=ZOT_TOKEN,
                ),
                operation=SyntheticFirstInstall(events, token=ZOT_TOKEN),
                reviewed_installed_source=EXPECTED,
            )
            receiver = AnalyticsUnixExecutorConnectionHandler(
                executor=privileged, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
            )
            errors = []

            def serve():
                """Accept exactly one private, local, synthetic product attempt."""
                try:
                    connection, _ = server_socket.accept()
                    receiver.handle(connection)
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                with patch.object(
                    analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", socket_path,
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                broker = AnalyticsPrivatePromotionBroker(
                    expected_workflow_sha=WORKFLOW_SHA, verifier=Verifier(),
                    signed_review_handler=review_handler(),
                    replay_guard=replay, analytics_transport=transport,
                    reviewed_installed_source=EXPECTED,
                    jwks_cache=StaticCache(KEY.public_key()),
                )
                with patch(
                    "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                    return_value=evidence(),
                ) as signed_mock, patch(
                    "deployment.analytics_promotion_broker.time.time", return_value=NOW,
                ):
                    result = broker.authorize_and_forward(
                        compact_token=DEPLOYMENT_TOKEN, zot_token=ZOT_TOKEN,
                        forgejo_token=FORGEJO_TOKEN, canonical_request=REQUEST,
                        received_at=NOW,
                    )
                    self.assertEqual(
                        parse_canonical_response(result).executor_request_sha256,
                        hashlib.sha256(REQUEST).hexdigest(),
                    )
                    # A second legitimate original OIDC call with same JTI/run
                    # must be denied by the EXISTING on-disk replay state.
                    with self.assertRaises(Exception):
                        broker.authorize_and_forward(
                            compact_token=DEPLOYMENT_TOKEN, zot_token=ZOT_TOKEN,
                            forgejo_token=FORGEJO_TOKEN,
                            canonical_request=REQUEST, received_at=NOW,
                        )
                    self.assertEqual(signed_mock.call_count, 2)
            finally:
                worker.join(5)
                server_socket.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(events, [
                "private_manifest", "deploy_analytics",
            ])

    def test_original_single_accept_listener_validates_exact_analytics_socket(self):
        """Original Task014 listener independently binds socket inode and path.

        This is a real disposable Linux AF_UNIX accept/SCM_RIGHTS flow. It
        neither installs nor activates a systemd service.
        """
        with tempfile.TemporaryDirectory(prefix="m05-14-listener-") as folder:
            path = str(Path(folder) / "analytics-executor.sock")
            privileged, replay, events = receiver()
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=privileged, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
            )
            original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            original.bind(path)
            original.set_inheritable(False)
            os.chmod(path, 0o660)
            original.listen(1)
            errors = []
            try:
                with patch.object(
                    analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", path,
                ):
                    executor_listener = AnalyticsUnixExecutorListener(
                        listener=original, handler=handler,
                        expected_socket_owner_uid=os.getuid(),
                        expected_socket_group_gid=os.getgid(),
                    )
                    # Relocate only the original ancestor tuple for a local
                    # disposable socket; original installed /run hierarchy
                    # remains fixed in the production Analytics class.
                    settings = list(object.__getattribute__(
                        executor_listener, "_configuration",
                    ))
                    settings[27] = ("/", "/tmp", folder)
                    object.__setattr__(
                        executor_listener, "_configuration", tuple(settings),
                    )
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )

                def serve_once():
                    """Run the *original* listener identity and socket checks."""
                    try:
                        executor_listener.serve_once()
                    except BaseException as exc:
                        errors.append(exc)

                server = threading.Thread(target=serve_once, daemon=True)
                server.start()
                fd = credential()
                try:
                    result = transport._send_analytics_private(
                        REQUEST, credential_fd=fd,
                    )
                    self.assertEqual(
                        parse_canonical_response(result).executor_request_sha256,
                        hashlib.sha256(REQUEST).hexdigest(),
                    )
                finally:
                    os.close(fd)
                server.join(5)
                self.assertFalse(server.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(
                    events, ["private_manifest", "begin_execution",
                             "deploy_analytics", "finish_execution"],
                )
            finally:
                original.close()

    def test_original_canary_listener_never_accepts_analytics_handler_as_route(self):
        """Analytics listener does not use ordinary canary executor path."""
        from deployment.executor_listener import UnixExecutorListener
        privileged, replay, events = receiver()
        handler = AnalyticsUnixExecutorConnectionHandler(
            executor=privileged, expected_broker_uid=os.getuid(),
            expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with self.assertRaises(TypeError):
                AnalyticsUnixExecutorListener(
                    listener=listener, handler=object(),
                    expected_socket_owner_uid=os.getuid(),
                    expected_socket_group_gid=os.getgid(),
                )
            original = UnixExecutorListener(
                listener=listener, handler=handler,
                expected_socket_owner_uid=os.getuid(),
                expected_socket_group_gid=os.getgid(),
            )
            original_settings = object.__getattribute__(
                original, "_configuration",
            )
            self.assertEqual(
                original_settings[26], "/run/omnilyzer/deployment/executor.sock",
            )
            with patch.object(
                analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH",
                "/run/omnilyzer/deployment/executor.sock",
            ), self.assertRaises(TypeError):
                AnalyticsUnixExecutorListener(
                    listener=listener, handler=handler,
                    expected_socket_owner_uid=os.getuid(),
                    expected_socket_group_gid=os.getgid(),
                )
        finally:
            listener.close()

    def test_explicit_analytics_transport_denies_canonical_canary_fallback(self):
        """No generic send() or original canary _send_private() on Analytics."""
        with patch.object(
            analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH",
            "/tmp/m05-14-analytics-denied.sock",
        ):
            transport = AnalyticsUnixExecutorTransport(
                expected_executor_uid=os.getuid(),
                expected_executor_gid=os.getgid(),
                expected_socket_group_gid=os.getgid(),
                reviewed_installed_source=EXPECTED,
            )
        for op in (lambda: transport.send(REQUEST),
                   lambda: transport._send_private(REQUEST, credential_fd=3)):
            with self.assertRaises(ExecutorTransportUnavailableError):
                op()

    def test_mismatched_authenticated_broker_peer_is_denied(self):
        """Real Linux SO_PEERCRED must reject an unexpected broker UID."""
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        executor, replay, events = receiver()
        handler = AnalyticsUnixExecutorConnectionHandler(
            executor=executor, expected_broker_uid=os.getuid() + 1,
            expected_broker_gid=os.getgid(),
            reviewed_installed_source=EXPECTED,
        )
        try:
            with self.assertRaises(ExecutorConnectionUnavailableError):
                handler.handle(right)
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(events, [])
        finally:
            left.close()
            right.close()


# Section: independently signed deployment and distinct registry audiences
# are now transported in the original FD. Verify the real cryptographic gates
# without using a broker-created receipt or activating UID991/Docker services.
class AnalyticsSuccessorIndependentJWTTests(unittest.TestCase):
    """Real RSA/JWT and kernel FD acceptance at the *future* executor boundary."""

    @staticmethod
    def candidate():
        """Return an exact synthetic schema-3 request with signed run identity."""
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        return AnalyticsSuccessorRequestTests().candidate()[0]

    @staticmethod
    def proof(raw, *, deployment=None, zot=None, forgejo=None, expires=None):
        """Seal raw cryptographic evidence, not an already accepted claim."""
        import jwt
        from deployment.private_registry_fd import (
            create_sealed_successor_review_credentials,
        )
        from deployment.tests.test_broker_integration import (
            KEY, ZOT_TOKEN, FORGEJO_TOKEN,
        )
        from deployment.tests.test_identity import valid_claims
        from deployment.tests.test_oidc_verifier import private_pem
        from deployment.private_registry_fd import _successor_request_image

        token = jwt.encode(
            valid_claims(), private_pem(KEY), algorithm="RS256",
            headers={"kid": "key-1", "typ": "JWT"},
        ) if deployment is None else deployment
        return create_sealed_successor_review_credentials(
            zot_token=ZOT_TOKEN if zot is None else zot,
            forgejo_token=FORGEJO_TOKEN if forgejo is None else forgejo,
            github_oidc_token=token, expires_at=NOW + 290 if expires is None else expires,
            image=_successor_request_image(raw), canonical_request=raw, now=NOW,
        )

    def verify(self, raw, fd, *, workflow=None, at=NOW, cache=None):
        """Use the existing independent verifier with a synthetic trusted key."""
        from deployment.analytics_executor import _verify_executor_successor_identity
        from deployment.tests.test_broker_integration import KEY
        from deployment.tests.test_identity import WORKFLOW_SHA
        from deployment.tests.test_registry_oidc_credentials import StaticCache
        return _verify_executor_successor_identity(
            raw, fd, expected_workflow_sha=(
                WORKFLOW_SHA if workflow is None else workflow
            ), received_at=at, jwks_cache=(
                StaticCache(KEY.public_key()) if cache is None else cache
            ),
        )

    def test_three_real_jwt_signatures_bound_to_exact_request_and_fd(self):
        """Three verified audiences are necessary but not deployment consent."""
        raw = canonical_bytes(self.candidate())
        before = set(os.listdir("/proc/self/fd"))
        fd = self.proof(raw)
        try:
            self.assertIsNone(self.verify(raw, fd))
            self.assertIsNone(self.verify(raw, fd))
            # Even three valid signed JWTs create no replay, Docker route,
            # source signature or container operation from this helper.
            with (
                patch("deployment.analytics_executor._verify_executor_owner_source") as owner,
                patch("deployment.analytics_active_state_review.inspect_analytics_active_state") as live,
                patch("deployment.analytics_executor._ENTER_EXECUTION") as replay,
            ):
                self.assertIsNone(self.verify(raw, fd))
            owner.assert_not_called()
            live.assert_not_called()
            replay.assert_not_called()
        finally:
            os.close(fd)
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))

    def test_verified_registry_context_can_be_reused_only_in_memory(self):
        """Executor obtains original issuer-verified credentials for a future signed review."""
        from deployment.analytics_executor import (
            _verified_executor_successor_identity_and_credentials,
        )
        from deployment.identity import AuthorizedGitHubIdentity
        from deployment.registry_oidc_credentials import VerifiedRegistryCredentials
        from deployment.tests.test_identity import WORKFLOW_SHA
        from deployment.tests.test_broker_integration import KEY
        from deployment.tests.test_registry_oidc_credentials import StaticCache

        raw = canonical_bytes(self.candidate())
        fd = self.proof(raw)
        try:
            identity, registry = _verified_executor_successor_identity_and_credentials(
                raw, fd, expected_workflow_sha=WORKFLOW_SHA,
                jwks_cache=StaticCache(KEY.public_key()), received_at=NOW,
            )
            self.assertIs(type(identity), AuthorizedGitHubIdentity)
            self.assertIs(type(registry), VerifiedRegistryCredentials)
            self.assertEqual(identity.run_id, self.candidate()["github_run_id"])
            self.assertEqual(registry.zot_read_credential().expires_at, NOW + 290)
            # The installed read-only route retains the historical None
            # contract and cannot promote using these in-memory credentials.
            self.assertIsNone(self.verify(raw, fd))
        finally:
            os.close(fd)

    def test_wrong_workflow_and_exact_request_identity_never_become_authority(self):
        """Neither request-selected workflow nor altered actor/run/JTI works."""
        raw = canonical_bytes(self.candidate())
        fd = self.proof(raw)
        try:
            from deployment.tests.test_identity import WORKFLOW_SHA
            with self.assertRaises(ExecutorUnavailableError):
                self.verify(raw, fd, workflow="a" * 40)
            with self.assertRaises(ExecutorUnavailableError):
                self.verify(raw, fd, workflow="0" * 40)
            with self.assertRaises(ExecutorUnavailableError):
                self.verify(raw + b" ", fd)
            for field, value in (
                ("github_run_id", 99),
                ("github_run_attempt", 2),
                ("requested_by_actor_id", 1),
                ("oidc_jti", "different-jti"),
                ("oidc_issued_at", NOW - 90),
                ("oidc_expires_at", NOW + 100),
            ):
                modified = canonical_bytes({**self.candidate(), field: value})
                other = self.proof(modified)
                try:
                    with self.subTest(field=field), self.assertRaises(
                        ExecutorUnavailableError
                    ):
                        self.verify(modified, other)
                finally:
                    os.close(other)
        finally:
            os.close(fd)

    def test_wrong_signed_audiences_or_signer_or_expiration_fail_closed(self):
        """A real signed wrong audience is not acceptable; nor forged JWT."""
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from deployment.tests.test_broker_integration import KEY
        from deployment.tests.test_identity import valid_claims
        from deployment.tests.test_oidc_verifier import private_pem
        from deployment.tests.test_broker_integration import (
            ZOT_TOKEN, FORGEJO_TOKEN,
        )
        raw = canonical_bytes(self.candidate())
        def signed(claims, *, key=KEY):
            return jwt.encode(
                claims, private_pem(key), algorithm="RS256",
                headers={"kid": "key-1", "typ": "JWT"},
            )
        wrong = rsa.generate_private_key(
            public_exponent=65537, key_size=2048,
        )
        cases = (
            {"deployment": signed(valid_claims(), key=wrong)},
            {"deployment": signed(valid_claims() | {"aud": "wrong"})},
            {"zot": FORGEJO_TOKEN},
            {"forgejo": ZOT_TOKEN},
            {"forgejo": signed(valid_claims() | {
                "aud": "u:3:d4f50b90-f001-4b9f-ad1e-487080ec44fb",
                "run_id": "34150000001",
            })},
        )
        for index, mutation in enumerate(cases):
            with self.subTest(index=index):
                fd = self.proof(raw, **mutation)
                try:
                    with self.assertRaises(ExecutorUnavailableError):
                        self.verify(raw, fd)
                finally:
                    os.close(fd)
        fd = self.proof(raw)
        try:
            with self.assertRaises(ExecutorUnavailableError):
                self.verify(raw, fd, at=NOW + 301)
        finally:
            os.close(fd)

    def test_root_pinned_v2_unix_receiver_checks_three_signatures_but_denies(self):
        """V2 pin is consumed inside real deny-only handler before OCI check.

        Synthetic RSA/JWKS is substituted ONLY for cryptographic test keys.
        A real signed owner Ed25519 fixture and actual sealed memfd validate
        the path without connecting Docker, Zot or a protected service.
        """
        import time
        from deployment.tests.test_broker_integration import KEY
        from deployment.tests.test_identity import WORKFLOW_SHA
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        candidate, context = AnalyticsSuccessorRequestTests().candidate()
        self.enterContext(signed_owner_fixture(context["selected"]))
        raw = canonical_bytes(candidate)
        fd = self.proof(raw)
        from deployment.tests.test_broker_integration import ZOT_TOKEN
        executor, replay, events = receiver(token=ZOT_TOKEN)
        handler = AnalyticsUnixExecutorConnectionHandler(
            executor=executor, expected_broker_uid=os.getuid(),
            expected_broker_gid=os.getgid(),
            reviewed_installed_source=EXPECTED,
            verified_successor_preflight_only=True,
            expected_workflow_sha=WORKFLOW_SHA,
        )
        verified = object.__getattribute__(handler, "_configuration")[0]
        state = AnalyticsActiveState(
            schema_version=1, active_slot="blue", active_digest=PINNED_DIGEST,
            active_image=PINNED_IMAGE, active_container_id="a" * 64,
            active_child_ip="172.20.0.3", active_network_id="f" * 64,
            private_ingress_port=3141, candidate_slot="green",
            candidate_port=3142, candidate_probe_present=True,
            candidate_digest=candidate["manifest_digest"],
            candidate_container_id="b" * 64,
        )
        try:
            with (
                patch("deployment.jwks.GitHubJWKSCache.get_key",
                      return_value=KEY.public_key()) as trusted,
                patch("deployment.private_registry_fd.time.time",
                      return_value=NOW),
                patch("deployment.analytics_executor.time.time",
                      return_value=NOW),
                patch("deployment.analytics_executor.os.geteuid",
                      return_value=991),
                patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                      return_value=state) as live,
                self.assertRaises(ExecutorRejectedError),
            ):
                verified(raw, credential_fd=fd)
            self.assertEqual(trusted.call_count, 3)
            self.assertEqual(live.call_count, 2)
            self.assertEqual(events, ["successor_manifest_probe"])
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(replay.finish_calls, [])
        finally:
            os.close(fd)

    def test_v2_unix_workflow_input_can_never_enable_original_v1_mode(self):
        """An untrusted or empty workflow pin cannot activate a receiver."""
        from deployment.tests.test_identity import WORKFLOW_SHA
        executor, replay, events = receiver()
        for wrong in ("0" * 40, "a" * 39, None, {}, True):
            if wrong is None:
                continue
            with self.subTest(wrong=wrong), self.assertRaises(TypeError):
                AnalyticsUnixExecutorConnectionHandler(
                    executor=executor, expected_broker_uid=os.getuid(),
                    expected_broker_gid=os.getgid(),
                    reviewed_installed_source=EXPECTED,
                    verified_successor_preflight_only=True,
                    expected_workflow_sha=wrong,
                )
        with self.assertRaises(TypeError):
            AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(),
                reviewed_installed_source=EXPECTED,
                verified_successor_preflight_only=False,
                expected_workflow_sha=WORKFLOW_SHA,
            )
        self.assertEqual(events, [])
        self.assertEqual(replay.begin_calls, [])

    def test_original_schema_one_successor_readonly_probe_is_not_validated_jwt(self):
        """Legacy one-Zot-only FD can never acquire three-signature status."""
        from deployment.private_registry_fd import create_sealed_credential
        from deployment.private_registry_fd import _successor_request_image
        raw = canonical_bytes(self.candidate())
        fd = create_sealed_credential(
            TOKEN, expires_at=NOW + 270,
            image=_successor_request_image(raw),
            canonical_request=raw, now=NOW, product_id="analytics-successor",
        )
        try:
            with self.assertRaises(ExecutorUnavailableError):
                self.verify(raw, fd)
        finally:
            os.close(fd)


# Section: root-reviewed V2 full-signature receiver integration.
# Use genuine Linux peer credentials, SOCK_STREAM and sealed original
# three-JWT transfer. The signed-release result below is an explicit mocked
# seam, NOT a real installed UID991 Cosign/Forgejo approval or deployment.
class AnalyticsSuccessorFullSignedUnixReceiverTests(unittest.TestCase):
    """Prove exact V2 delegation is read-only even when full review succeeds."""

    def setUp(self):
        """Bind the original schema3 and real kernel-sealed three-JWT FD."""
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.tests.test_identity import WORKFLOW_SHA
        self.workflow = WORKFLOW_SHA
        self.raw = canonical_bytes(AnalyticsSuccessorRequestTests().candidate()[0])
        self.fd = AnalyticsSuccessorIndependentJWTTests.proof(self.raw)
        self.addCleanup(os.close, self.fd)
        self.executor, self.replay, self.events = receiver()

    def handler(self, **overrides):
        """Bind the reviewed workflow and complete signed-review-only mode."""
        defaults = dict(
            executor=self.executor,
            expected_broker_uid=os.getuid(), expected_broker_gid=os.getgid(),
            reviewed_installed_source=EXPECTED,
            full_signed_successor_review_only=True,
            expected_workflow_sha=self.workflow,
        )
        defaults.update(overrides)
        return AnalyticsUnixExecutorConnectionHandler(**defaults)

    def test_valid_signed_review_is_still_hard_denied(self):
        """No positive response, replay or Docker callback after full review."""
        handler = self.handler()
        callback = object.__getattribute__(handler, "_configuration")[0]
        with (
            patch(
                "deployment.analytics_executor._review_executor_successor_signed_release",
                return_value=object(),
            ) as reviewed,
            self.assertRaises(ExecutorRejectedError),
        ):
            callback(self.raw, credential_fd=self.fd)
        reviewed.assert_called_once_with(
            self.raw, self.fd,
            expected_workflow_sha=self.workflow,
            reviewed_installed_source=EXPECTED,
        )
        self.assertEqual(self.replay.begin_calls, [])
        self.assertEqual(self.replay.finish_calls, [])
        self.assertEqual(self.events, [])

    def test_signature_or_owner_failure_is_hard_denied_no_fallback(self):
        """No legacy single-JWT path or Docker attempt on signed-review error."""
        callback = object.__getattribute__(
            self.handler(), "_configuration",
        )[0]
        with (
            patch(
                "deployment.analytics_executor._review_executor_successor_signed_release",
                side_effect=ExecutorUnavailableError("signed review unavailable"),
            ) as reviewed,
            self.assertRaises(ExecutorUnavailableError),
        ):
            callback(self.raw, credential_fd=self.fd)
        reviewed.assert_called_once()
        self.assertEqual(self.events, [])
        self.assertEqual(self.replay.begin_calls, [])

    def test_only_one_read_only_mode_can_be_selected(self):
        """No untrusted workflow, mixed modes or V1->V2 upgrade shortcut."""
        with self.assertRaises(TypeError):
            self.handler(verified_successor_preflight_only=True)
        with self.assertRaises(TypeError):
            self.handler(structural_successor_receive_only=True)
        with self.assertRaises(TypeError):
            self.handler(full_signed_successor_review_only=1)
        with self.assertRaises(TypeError):
            self.handler(expected_workflow_sha=None)
        with self.assertRaises(TypeError):
            self.handler(expected_workflow_sha="a" * 39)
        with self.assertRaises(TypeError):
            self.handler(
                full_signed_successor_review_only=False,
                expected_workflow_sha=self.workflow,
            )
        self.assertEqual(self.events, [])
        self.assertEqual(self.replay.begin_calls, [])

    def test_separately_selected_root3_positive_mode_uses_same_real_sealed_fd(self):
        """Real AF_UNIX SO_PEERCRED/SCM_RIGHTS, source-only callback boundary.

        This is NOT a real UID991 service, Docker or original signature
        acceptance. A synthetic callback stands in for the independently
        tested signed coordinator. V2 is still DENY-only and original V1 is
        neither imported into this route nor changed.
        """
        from deployment.tests.test_analytics_successor_candidate_operation import (
            SyntheticGreenRunner,
        )
        from deployment.analytics_first_install import (
            AnalyticsSuccessorCandidateOperation,
        )
        from deployment.analytics_private_registry import (
            AnalyticsPrivateZotPullAdapter,
        )
        from deployment.analytics_route_journal import AnalyticsRouteJournal
        from deployment.executor import _build_success_response
        import hashlib

        expected = _build_success_response(hashlib.sha256(self.raw).hexdigest())
        with tempfile.TemporaryDirectory(
            prefix="task14b-source-positive-unix-",
        ) as directory:
            runner = SyntheticGreenRunner(
                analytics_boundary._successor_request_image(self.raw),
            )
            registry = AnalyticsPrivateZotPullAdapter(
                runner, reviewed_installed_source=EXPECTED,
            )
            candidate = AnalyticsSuccessorCandidateOperation(
                runner=runner, private_registry=registry,
                reviewed_installed_source=EXPECTED,
            )
            journal = AnalyticsRouteJournal(
                directory, expected_uid=os.getuid(), expected_gid=os.getgid(),
            )
            handler = self.handler(
                full_signed_successor_review_only=False,
                owner_authorized_first_successor=True,
                candidate_operation=candidate,
                route_journal=journal,
            )
            socket_path = str(Path(directory) / "one-shot.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(socket_path)
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            listener.settimeout(3)
            failures = []

            def accept_once():
                """Prove the real kernel FD and peer one-connection framing."""
                try:
                    accepted, _ = listener.accept()
                    handler.handle(accepted)
                except BaseException as exc:
                    failures.append(type(exc).__name__)

            worker = threading.Thread(target=accept_once, daemon=True)
            worker.start()
            try:
                with (
                    patch.object(
                        analytics_boundary,
                        "ANALYTICS_EXECUTOR_SOCKET_PATH", socket_path,
                    ),
                    patch(
                        "deployment.analytics_executor."
                        "_execute_reviewed_first_successor_transaction",
                        return_value=expected,
                    ) as signed,
                    patch("deployment.private_registry_fd.time.time",
                          return_value=NOW),
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                    response = transport._send_analytics_successor_private(
                        self.raw, credential_fd=self.fd,
                    )
                worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(response, expected)
                signed.assert_called_once_with(
                    self.raw, credential_fd=unittest.mock.ANY,
                    expected_workflow_sha=self.workflow,
                    executor=self.executor, candidate_operation=candidate,
                    journal=journal,
                )
            finally:
                worker.join(5)
                listener.close()
            self.assertEqual(failures, [])
            self.assertEqual(self.replay.begin_calls, [])
            self.assertEqual(self.replay.finish_calls, [])
            self.assertEqual(self.events, [])

    def test_exact_real_unix_signed_receive_rejects_without_replay(self):
        """Actual SO_PEERCRED + SCM_RIGHTS sealed three JWTs, then hard DENY."""
        with tempfile.TemporaryDirectory(prefix="task14b-fullsigned-unix-") as tmp:
            path = str(Path(tmp) / "socket")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o660)
            listener.listen(1)
            listener.settimeout(3)
            handler = self.handler()
            failures = []

            def serve():
                """Accept exactly one signed but NON-deploying local request."""
                try:
                    accepted, _ = listener.accept()
                    handler.handle(accepted)
                except ExecutorConnectionUnavailableError:
                    failures.append("signed-review-denied")
                except BaseException as unexpected:
                    failures.append(type(unexpected).__name__)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                with (
                    patch.object(
                        analytics_boundary,
                        "ANALYTICS_EXECUTOR_SOCKET_PATH", path,
                    ),
                    patch(
                        "deployment.analytics_executor._review_executor_successor_signed_release",
                        return_value=object(),
                    ) as signed,
                    # The real sealed FD and original receiver use their
                    # shared fixed synthetic JWT clock. No future token is
                    # constructed and the actual JWT proof remains sealed.
                    patch("deployment.private_registry_fd.time.time",
                          return_value=NOW),
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                    with self.assertRaises(ExecutorTransportUnavailableError):
                        transport._send_analytics_successor_private(
                            self.raw, credential_fd=self.fd,
                        )
                worker.join(5)
                self.assertFalse(worker.is_alive())
                signed.assert_called_once()
            finally:
                worker.join(5)
                listener.close()
            self.assertEqual(failures, ["signed-review-denied"])
            self.assertEqual(self.replay.begin_calls, [])
            self.assertEqual(self.replay.finish_calls, [])
            self.assertEqual(self.events, [])


# Section: explicit UNINSTALLED UID991 full Task013 review. All registry,
# signer/owner and live-host responses below are synthetic. This verifies the
# real release consumer composition and fail-closed binding, not actual release
# signature acceptance or a privileged/signed DEV deployment.
class AnalyticsSuccessorIndependentSignedReleaseReviewTests(unittest.TestCase):
    """Exercise the future full evidence reader without positive Unix routing."""

    def setUp(self):
        """Use a genuine signed RSA/JWT sealed FD but only synthetic release data."""
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.tests.test_analytics_private_registry import (
            first_successor_empty_active_state,
        )
        self.data, self.context = AnalyticsSuccessorRequestTests().candidate()
        self.raw = canonical_bytes(self.data)
        self.proof = AnalyticsSuccessorIndependentJWTTests()
        self.fd = self.proof.proof(self.raw)
        self.addCleanup(os.close, self.fd)
        self.live = first_successor_empty_active_state()

    @contextmanager
    def synthetic_host(self, *, state=None, signed=None, owner=True):
        """Mock only unavailable root/registry assets, never JWT verification."""
        from contextlib import ExitStack
        from deployment.tests.test_broker_integration import KEY
        from deployment.tests.test_registry_oidc_credentials import StaticCache
        from deployment.tests.test_identity import WORKFLOW_SHA
        from deployment.analytics_executor import (
            _review_executor_successor_signed_release,
        )
        with ExitStack() as mocks:
            for name in ("getuid", "geteuid", "getgid", "getegid"):
                mocks.enter_context(patch(
                    "deployment.analytics_executor.os." + name, return_value=991,
                ))
            owner_signature = mocks.enter_context(patch(
                "deployment.analytics_executor._verify_executor_owner_source",
                side_effect=None if owner else ValueError("forged owner proof"),
            ))
            active = mocks.enter_context(patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
                return_value=self.live if state is None else state,
            ))
            forgejo = mocks.enter_context(patch(
                "deployment.analytics_signed_release_consumer.acquire_and_review_owner_approved_analytics_release",
                return_value=self.context["signed_release"] if signed is None else signed,
            ))
            signature = mocks.enter_context(patch(
                "release.analytics_owner_source_selection.load_and_verify_owner_signed_source",
                return_value=(
                    self.context["selected"], self.context["owner_approval"],
                ),
            ))
            def review(raw=self.raw, fd=self.fd, *, trace_generation3=False):
                """Use the same exact reviewed source and original RSA JWKS."""
                return _review_executor_successor_signed_release(
                    raw, fd, expected_workflow_sha=WORKFLOW_SHA,
                    reviewed_installed_source=EXPECTED, received_at=NOW,
                    jwks_cache=StaticCache(KEY.public_key()),
                    trace_generation3=trace_generation3,
                )
            yield review, owner_signature, active, forgejo, signature

    # Section: all four real signed-review helper stage codes stay local.
    def test_generation3_redacted_signed_review_phase_owner_blue(self):
        """Wrong owner fails before JWT/registry and exposes no details."""
        with self.synthetic_host(owner=False) as (review, owner, state, forgejo, _):
            with patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr:
                with self.assertRaises(ExecutorUnavailableError):
                    review(trace_generation3=True)
            self.assertEqual(
                stderr.getvalue(),
                "TASK014_ANALYTICS_UID991_HOLD phase=owner_blue\n",
            )
            owner.assert_called_once()
            state.assert_not_called()
            forgejo.assert_not_called()

    def test_generation3_redacted_signed_review_phase_signed_identity(self):
        """An independently denied signed JWT leaks no claimed identity."""
        with self.synthetic_host() as (review, _, state, forgejo, _):
            with (
                patch(
                    "deployment.analytics_executor."
                    "_verified_executor_successor_identity_and_credentials",
                    side_effect=ValueError("synthetic-secret-value"),
                ),
                patch("deployment.analytics_executor.sys.stderr", new=StringIO())
                    as stderr,
            ):
                with self.assertRaises(ExecutorUnavailableError):
                    review(trace_generation3=True)
            self.assertEqual(
                stderr.getvalue(),
                "TASK014_ANALYTICS_UID991_HOLD phase=signed_identity\n",
            )
            self.assertNotIn("synthetic-secret-value", stderr.getvalue())
            self.assertEqual(state.call_count, 1)
            forgejo.assert_not_called()

    def test_generation3_redacted_signed_review_phase_sigstore_evidence(self):
        """A failed signed evidence verification does not start deployment."""
        with self.synthetic_host() as (review, _, state, forgejo, _):
            forgejo.side_effect = ValueError("synthetic-credential-hidden")
            with patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr:
                with self.assertRaises(ExecutorUnavailableError):
                    review(trace_generation3=True)
            self.assertEqual(
                stderr.getvalue(),
                "TASK014_ANALYTICS_UID991_HOLD phase=sigstore_evidence\n",
            )
            self.assertNotIn("synthetic-credential-hidden", stderr.getvalue())
            self.assertEqual(state.call_count, 1)
            forgejo.assert_called_once()

    def test_generation3_redacted_signed_review_phase_binding(self):
        """An unacceptable signed subject never becomes request authority."""
        from dataclasses import replace
        bad = replace(self.context["signed_release"], manifest_sha256="f" * 64)
        with self.synthetic_host(signed=bad) as (review, _, state, forgejo, _):
            with patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr:
                with self.assertRaises(ExecutorUnavailableError):
                    review(trace_generation3=True)
            self.assertEqual(
                stderr.getvalue(),
                "TASK014_ANALYTICS_UID991_HOLD phase=signed_release_binding\n",
            )
            self.assertEqual(state.call_count, 1)
            forgejo.assert_called_once()

    def test_generation2_review_denial_stays_silent_and_success_has_no_phase(self):
        """Original read-only denial and completed review have zero trace."""
        with self.synthetic_host(owner=False) as (review, _, _, _, _):
            with patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr:
                with self.assertRaises(ExecutorUnavailableError):
                    review()
            self.assertEqual(stderr.getvalue(), "")
        with self.synthetic_host() as (review, _, _, _, _):
            with patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr:
                valid = review(trace_generation3=True)
            self.assertEqual(valid.canonical_bytes(), self.raw)
            self.assertEqual(stderr.getvalue(), "")

    def test_existing_real_uid_cannot_enter_signed_review(self):
        """A restricted test user cannot impersonate the future UID991."""
        from deployment.analytics_executor import (
            _review_executor_successor_signed_release,
        )
        from deployment.tests.test_identity import WORKFLOW_SHA
        with self.assertRaises(ExecutorUnavailableError):
            _review_executor_successor_signed_release(
                self.raw, self.fd, expected_workflow_sha=WORKFLOW_SHA,
                reviewed_installed_source=EXPECTED, received_at=NOW,
            )

    def test_full_signed_review_binds_same_original_policy_and_exact_request(self):
        """Verified 3-JWT identity feeds original independent signer consumers."""
        from deployment.analytics_execution import AnalyticsSuccessorRequest
        from deployment.blob_verifier import (
            CosignReleaseBlobVerifier, COSIGN_PATH,
        )
        from deployment.analytics_executor import _OWNER_APPROVAL_FILE
        from deployment.oci_verifier import CosignOCISignatureVerifier
        with self.synthetic_host() as (review, owner, state, forgejo, signature):
            result = review()
            self.assertIs(type(result), AnalyticsSuccessorRequest)
            self.assertEqual(result.canonical_bytes(), self.raw)
            owner.assert_called_once()
            self.assertEqual(state.call_count, 2)
            self.assertEqual(signature.call_count, 1)
            forgejo.assert_called_once()
            args, kwargs = forgejo.call_args
            self.assertIs(type(args[2]), CosignReleaseBlobVerifier)
            self.assertIs(type(args[3]), CosignOCISignatureVerifier)
            self.assertEqual(
                object.__getattribute__(args[2], "_authority")[0],
                COSIGN_PATH,
            )
            self.assertEqual(
                object.__getattribute__(args[2], "_broker"), (991, 991),
            )
            self.assertEqual(
                object.__getattribute__(args[3], "_broker"), (991, 991),
            )
            self.assertEqual(kwargs["approval_file"], _OWNER_APPROVAL_FILE)

    def test_owner_rejection_happens_before_remote_release_fetch(self):
        """An invalid owner signature cannot trigger Sigstore/Zot I/O."""
        with self.synthetic_host(owner=False) as (review, owner, state, forgejo, _):
            with self.assertRaises(ExecutorUnavailableError):
                review()
            owner.assert_called_once()
            state.assert_not_called()
            forgejo.assert_not_called()

    def test_forged_signed_subject_or_host_drift_never_returns_request(self):
        """Even synthetic upstream success cannot bypass equality and route checks."""
        from dataclasses import replace
        wrong = replace(self.context["signed_release"], manifest_sha256="f" * 64)
        with self.synthetic_host(signed=wrong) as (review, _, state, forgejo, _):
            with self.assertRaises(ExecutorUnavailableError):
                review()
            forgejo.assert_called_once()
        # Actual state must still match the original blue writer on SECOND read.
        with self.synthetic_host() as (review, _, state, forgejo, _):
            state.side_effect = [
                self.live, replace(self.live, active_digest="sha256:" + "e" * 64),
            ]
            with self.assertRaises(ExecutorUnavailableError):
                review()
            forgejo.assert_called_once()

    def test_invalid_runtime_and_unbound_source_reject_before_registry(self):
        """No broker receipt or unreviewed local source may become authority."""
        with self.synthetic_host() as (review, _, state, forgejo, _):
            from deployment.analytics_executor import (
                _review_executor_successor_signed_release,
            )
            from deployment.tests.test_identity import WORKFLOW_SHA
            with self.assertRaises(ExecutorUnavailableError):
                _review_executor_successor_signed_release(
                    self.raw, self.fd, expected_workflow_sha=WORKFLOW_SHA,
                    reviewed_installed_source={"source": "untrusted"},
                    received_at=NOW,
                )
            state.assert_not_called()
            forgejo.assert_not_called()


if __name__ == "__main__":
    unittest.main()
