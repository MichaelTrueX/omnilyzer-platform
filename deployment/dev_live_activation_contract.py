"""deployment/dev_live_activation_contract.py - C33W DEV activation lifecycle.

Purpose:
- define the exact reviewed transition from an installed inactive DEV control
  plane to a privately reachable broker;
- preserve systemd socket activation for the privileged executor;
- provide immutable values for the later root-controlled activation wrapper
  without embedding host mutation in repository code.

Links:
- controller.py authorizes only the exact C33W DEV environment.
- broker_edge_contract.py owns the private Tailscale/Nginx/broker path.
- host_service_layout.py owns systemd unit and executor socket identities.
- systemd_socket_activation.py owns the inherited executor descriptor contract.

This module is declarative only. It does not execute systemctl, open listeners,
change files, activate deployment, or retry a failed transition.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields

from .broker_edge_contract import DevBrokerEdgeContract
from .host_service_layout import DevHostServiceLayout


__all__ = ("DevLiveActivationContract",)

_ERROR = "DEV live activation contract is invalid"


@dataclass(frozen=True, slots=True)
class DevLiveActivationContract:
    """Immutable C33W service-order and private-ingress activation authority."""

    stage: str = field(init=False, default="dev")
    executor_socket_unit: str = field(
        init=False,
        default="omnilyzer-deployment-executor.socket",
    )
    executor_service_unit: str = field(
        init=False,
        default="omnilyzer-deployment-executor.service",
    )
    broker_service_unit: str = field(
        init=False,
        default="omnilyzer-deployment-broker.service",
    )
    executor_socket_path: str = field(
        init=False,
        default="/run/omnilyzer/deployment/executor.sock",
    )
    broker_listen_host: str = field(init=False, default="127.0.0.1")
    broker_listen_port: int = field(init=False, default=3031)
    nginx_listen_host: str = field(init=False, default="127.0.0.1")
    nginx_listen_port: int = field(init=False, default=3032)
    private_https_endpoint: str = field(
        init=False,
        default=(
            "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote"
        ),
    )
    activation_sequence: tuple[str, ...] = field(
        init=False,
        default=(
            "start-executor-socket",
            "qualify-executor-socket",
            "start-broker-service",
            "qualify-private-ingress",
        ),
    )
    direct_start_forbidden: tuple[str, ...] = field(
        init=False,
        default=("omnilyzer-deployment-executor.service",),
    )
    automatic_retry_allowed: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        """Cross-check every literal against existing reviewed service contracts."""

        for item in fields(self):
            expected = item.default
            actual = getattr(self, item.name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError(_ERROR)

        layout = DevHostServiceLayout()
        edge = DevBrokerEdgeContract()
        if (
            self.executor_socket_unit != layout.executor_socket_unit_name
            or self.executor_service_unit != layout.executor_service_unit_name
            or self.executor_socket_path != layout.executor_socket_path
            or self.broker_listen_host != edge.upstream_host
            or self.broker_listen_port != edge.upstream_port
            or self.nginx_listen_host != edge.nginx_listen_host
            or self.nginx_listen_port != edge.nginx_listen_port
            or self.private_https_endpoint != edge.transport_endpoint
            or self.executor_service_unit not in self.direct_start_forbidden
            or self.automatic_retry_allowed is not False
        ):
            raise ValueError(_ERROR)
