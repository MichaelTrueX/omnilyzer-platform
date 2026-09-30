"""Inert C32ZF host authority for one executor-owned rootless DEV Docker engine.

No host I/O, caller inputs, package installation, or service activation occurs.
The frozen C32W application is not changed or enabled by this authority.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PackageAuthority:
    name: str
    apt_version: str
    origin: str
    deb_sha256: str
    required_executables: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SystemdTemplateDropInAuthority:
    path: str
    package: str
    apt_version: str
    architecture: str
    sha256: str
    uid: int
    gid: int
    mode: int


DOCKER_ORIGIN = "https://download.docker.com/linux/ubuntu noble/stable amd64"
UBUNTU_MAIN = "Ubuntu signed noble-updates/main amd64"
UBUNTU_UNIVERSE = "Ubuntu signed noble/universe amd64"


@dataclass(frozen=True, slots=True)
class RootlessDockerAuthority:
    executor_uid: int = field(init=False, default=991)
    executor_gid: int = field(init=False, default=991)
    executor_user: str = field(init=False, default="omnilyzer-executor")
    subuid_start: int = field(init=False, default=493216)
    subgid_start: int = field(init=False, default=493216)
    subordinate_count: int = field(init=False, default=65536)
    canary_host_uid: int = field(init=False, default=503216)
    canary_host_gid: int = field(init=False, default=503216)
    nginx_host_uid: int = field(init=False, default=558747)
    nginx_host_gid: int = field(init=False, default=558747)
    engine_version: str = field(init=False, default="29.8.1")
    compose_version: str = field(init=False, default="5.5.1")
    packages: tuple[PackageAuthority, ...] = field(init=False, default=(
        PackageAuthority("docker-ce", "5:29.8.1-1~ubuntu.24.04~noble", DOCKER_ORIGIN,
                         "607bcf63bf85c5a245b73229c2797fda5c5a430343c02ebf80f32f6db7513eb9",
                         ("/usr/bin/dockerd",)),
        PackageAuthority("docker-ce-cli", "5:29.8.1-1~ubuntu.24.04~noble", DOCKER_ORIGIN,
                         "e26e6770fab41256cf16c09c24a0b75e70bf72465ef2688f85d1f7d3fdb9b99c",
                         ("/usr/bin/docker",)),
        PackageAuthority("docker-ce-rootless-extras", "5:29.8.1-1~ubuntu.24.04~noble",
                         DOCKER_ORIGIN,
                         "02897501837b7ff4fec8248decdd5828b7d40d7f591021a91f29673e02d0f982",
                         ("/usr/bin/dockerd-rootless.sh", "/usr/bin/rootlesskit")),
        PackageAuthority("docker-compose-plugin", "5.5.1-1~ubuntu.24.04~noble",
                         DOCKER_ORIGIN,
                         "82ff966149ca2c62e1a4e1fdebdf65fda8c3a8bea80b32deda6903b40afc2347",
                         ("/usr/libexec/docker/cli-plugins/docker-compose",)),
        PackageAuthority("containerd.io", "2.3.6-1~ubuntu.24.04~noble", DOCKER_ORIGIN,
                         "2eb8c6e244fe6886f2fa2eee9ec418c4b9bb44eb44fca748504f57c23341aed2",
                         ("/usr/bin/containerd",)),
        PackageAuthority("uidmap", "1:4.13+dfsg1-4ubuntu3.2", UBUNTU_MAIN,
                         "a80cb7f72dd18c73cbb0b07b7fbe855504f26bfafae072a9b3d125c89d499b9e",
                         ("/usr/bin/newuidmap", "/usr/bin/newgidmap")),
        PackageAuthority("slirp4netns", "1.2.1-1build2", UBUNTU_UNIVERSE,
                         "3fc72a72a376a3ad3b439434bc87d89d245f9d54a1d540e8a06b74d4e2385e0a",
                         ("/usr/bin/slirp4netns",)),
    ))
    vendor_rootless_script: str = field(init=False, default="/usr/bin/dockerd-rootless.sh")
    vendor_rootless_script_sha256: str = field(
        init=False, default="200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488")
    docker_cli: str = field(init=False, default="/usr/bin/docker")
    compose_plugin: str = field(init=False, default="/usr/libexec/docker/cli-plugins/docker-compose")
    rootlesskit: str = field(init=False, default="/usr/bin/rootlesskit")
    rootlesskit_flags: str = field(
        init=False, default="--subid-source=static --slirp4netns-binary=/usr/bin/slirp4netns")
    subid_source: str = field(init=False, default="static")
    slirp4netns_binary: str = field(init=False, default="/usr/bin/slirp4netns")
    dockerd: str = field(init=False, default="/usr/bin/dockerd")
    runtime_directory: str = field(init=False, default="/run/user/991")
    daemon_socket: str = field(init=False, default="/run/user/991/docker.sock")
    socket_directory: str = field(init=False, default="/run/omnilyzer/deployment/rootless-docker")
    socket: str = field(init=False, default="/run/omnilyzer/deployment/rootless-docker/docker.sock")
    socket_host: str = field(init=False, default="unix:///run/omnilyzer/deployment/rootless-docker/docker.sock")
    data_root: str = field(init=False, default="/var/lib/omnilyzer/deployment/rootless-docker-data")
    exec_root: str = field(init=False, default="/run/user/991/docker-exec")
    rootlesskit_state: str = field(init=False, default="/run/user/991/dockerd-rootless")
    containerd_rootless_state: str = field(init=False, default="/run/user/991/containerd-rootless")
    pid_file: str = field(init=False, default="/run/user/991/docker.pid")
    home: str = field(init=False, default="/var/lib/omnilyzer/deployment/rootless-home")
    daemon_config: str = field(init=False, default="/etc/omnilyzer/deployment/rootless-docker/daemon.json")
    client_config: str = field(init=False, default="/etc/omnilyzer/deployment/docker-client/config.json")
    launcher: str = field(init=False, default="/opt/omnilyzer/deployment/rootless-docker/launch.py")
    user_unit: str = field(init=False, default="/etc/systemd/user/omnilyzer-task014-rootless-docker.service")
    cgroup_dropin: str = field(init=False, default="/etc/systemd/system/user@991.service.d/omnilyzer-task014-cgroup-delegation.conf")
    executor_socket_dropin: str = field(init=False, default="/etc/systemd/system/omnilyzer-deployment-executor.service.d/rootless-docker-socket.conf")
    user_manager_template_dropins: tuple[SystemdTemplateDropInAuthority, ...] = field(
        init=False,
        default=(
            SystemdTemplateDropInAuthority(
                "/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf",
                "systemd",
                "255.4-1ubuntu8.17",
                "amd64",
                "1c1452839b609b0609cccaba3c648d780372df6f244deb487da6da5ee002a993",
                0, 0, 0o644,
            ),
            SystemdTemplateDropInAuthority(
                "/usr/lib/systemd/system/user@.service.d/10-oomd-user-service-defaults.conf",
                "systemd-oomd",
                "255.4-1ubuntu8.17",
                "amd64",
                "ddf0f174373b79ea32997999cf2139e595c3fe9ccaf6ff66b2230d493fc664ef",
                0, 0, 0o644,
            ),
            SystemdTemplateDropInAuthority(
                "/usr/lib/systemd/system/user@.service.d/timeout.conf",
                "systemd",
                "255.4-1ubuntu8.17",
                "amd64",
                "597eac16d8d7a289bb16aeeb01be0191d0c90beca4c6e0dba0f0c2d7c4e0ea81",
                0, 0, 0o644,
            ),
        ),
    )
    canary_runtime: str = field(init=False, default="/var/lib/omnilyzer/deployment/dev/canary-runtime")
    nginx_runtime: str = field(init=False, default="/var/lib/omnilyzer/deployment/dev/nginx-runtime")
    detach_netns: bool = field(init=False, default=True)
    rootless_environment: tuple[tuple[str, str], ...] = field(init=False, default=(
        ("DOCKERD", "/usr/bin/dockerd"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR", "/run/user/991/dockerd-rootless"),
        ("CONTAINERD_ROOTLESS_ROOTLESSKIT_STATE_DIR", "/run/user/991/containerd-rootless"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_NET", "slirp4netns"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_MTU", "65520"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER", "builtin"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX", "auto"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP", "auto"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK", "true"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS", "true"),
        ("DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS",
         "--subid-source=static --slirp4netns-binary=/usr/bin/slirp4netns"),
    ))
    provisioned_directories: tuple[tuple[str, int, int, int], ...] = field(init=False, default=(
        ("/var/lib/omnilyzer/deployment/rootless-home", 991, 991, 0o700),
        ("/var/lib/omnilyzer/deployment/rootless-docker-data", 991, 991, 0o700),
        ("/var/lib/omnilyzer/deployment/dev/canary-runtime", 991, 503216, 0o770),
        ("/var/lib/omnilyzer/deployment/dev/nginx-runtime", 991, 991, 0o755),
        ("/etc/omnilyzer/deployment/rootless-docker", 0, 0, 0o755),
        ("/etc/omnilyzer/deployment/docker-client", 0, 0, 0o755),
        ("/opt/omnilyzer/deployment/rootless-docker", 0, 0, 0o755),
        ("/etc/systemd/system/user@991.service.d", 0, 0, 0o755),
        ("/etc/systemd/system/omnilyzer-deployment-executor.service.d", 0, 0, 0o755),
    ))
    external_runtime_prerequisites: tuple[tuple[str, int, int, int], ...] = field(init=False, default=(
        ("/run/user/991", 991, 991, 0o700),
        ("/run/omnilyzer", 0, 0, 0o755),
        ("/run/omnilyzer/deployment", 0, 0, 0o755),
    ))
    installed_assets: tuple[tuple[str, str, str, int, int, int], ...] = field(init=False, default=(
        (
            "deployment/systemd/rootless/omnilyzer-task014-rootless-docker.service",
            "/etc/systemd/user/omnilyzer-task014-rootless-docker.service",
            "eebc1e030365bced1df3d97afaa8215dee2fc3e02afa8ce88c24f5a9441bbd12",
            0, 0, 0o644,
        ),
        (
            "deployment/systemd/rootless/omnilyzer-task014-cgroup-delegation.conf",
            "/etc/systemd/system/user@991.service.d/omnilyzer-task014-cgroup-delegation.conf",
            "aba4044ef5937f7f310b4312750082649ab45a7d6ad848870c288f72b7943df3",
            0, 0, 0o644,
        ),
        (
            "deployment/systemd/rootless/rootless-docker-executor-socket.conf",
            "/etc/systemd/system/omnilyzer-deployment-executor.service.d/rootless-docker-socket.conf",
            "afef78b7ed57beedc2a8496b602c3f7d6dad7981dd88258f6b7e8c35a7fbed2d",
            0, 0, 0o644,
        ),
        (
            "deployment/systemd/rootless/rootless-docker-launcher.py",
            "/opt/omnilyzer/deployment/rootless-docker/launch.py",
            "34d5557a068e030c75e063cf6b6106ef118ec7ff87de1d953d900dfbd1eaefff",
            0, 0, 0o644,
        ),
        (
            "deployment/systemd/rootless/rootless-docker-daemon.json",
            "/etc/omnilyzer/deployment/rootless-docker/daemon.json",
            "d2103ea82f8df0c68a1bf534626b26540f3766462a9da6262cf2540f6dd7f09f",
            0, 0, 0o644,
        ),
        (
            "deployment/systemd/rootless/rootless-docker-client-config.json",
            "/etc/omnilyzer/deployment/docker-client/config.json",
            "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
            0, 0, 0o644,
        ),
    ))
    qualification: tuple[str, ...] = field(init=False, default=(
        "preinstall-rootful-docker-containerd-units-masked-and-start-blocked-before-apt-maintainer-scripts",
        "postinstall-rootful-docker-and-containerd-units-masked-inactive-no-rootful-process-or-socket",
        "all-seven-packages-exact-version-signed-origin-deb-digest-and-critical-binary-owner",
        "no-buildx-or-higher-priority-compose-plugin-or-replacement-binary",
        "vendor-rootless-bootstrap-exact-package-owned-script-hash-and-behavior",
        "rootlesskit-slirp4netns-uidmap-and-ubuntu-apparmor-prerequisites",
        "executor-exact-identity-and-no-docker-or-sudo-membership",
        "exclusive-nonoverlapping-65536-subuid-and-subgid-range",
        "static-subid-source-exact-etc-subuid-and-subgid-entry-no-extra-or-overlap",
        "slirp4netns-exact-absolute-package-owned-binary-no-path-shadow",
        "logind-linger-user-manager-and-ephemeral-XDG-runtime-exact-for-uid-991",
        "instance-specific-cpu-memory-pids-cgroup-v2-delegation",
        "root-controlled-exact-launcher-unit-dropin-and-json-assets",
        "rootless-data-home-runtime-socket-and-exec-path-ownership-modes",
        "vendor-containerd-conflict-copyup-cleanup-and-ipv4-ipv6-forwarding-behavior",
        "safe-rootlesskit-state-owned-0700-vendor-lock-and-crash-recovery",
        "existing-docker-socket-exact-identity-live-probe-refused-defers-to-vendor-lock-no-launcher-unlink",
        "executor-protecthome-preserved-with-one-readonly-private-socket-bind",
        "daemon-rootless-overlay2-systemd-cgroup-and-exact-version",
        "daemon-private-unix-socket-only-no-tcp-or-rootful-fallback",
        "daemon-inventory-only-task014-dev-project-and-approved-images",
        "exact-zot-image-pull-and-digest-without-persistent-docker-credentials",
        "canary-bind-mount-mapped-uid-gid-read-write-migration-and-read-only-service",
        "nginx-bind-mount-readable-by-mapped-65532-and-writable-by-executor",
        "internal-compose-network-and-exact-loopback-3020-publication",
        "cpu-memory-pids-limits-enforced-not-ignored-by-rootless-engine",
        "read-only-cap-drop-no-new-privileges-and-restart-after-reboot",
        "executor-fails-closed-when-rootless-daemon-stops-or-socket-changes",
        "broker-has-no-docker-access-and-executor-socket-remains-reviewed",
        "successor-rootless-application-generation-reviewed-installed-before-activation",
        "broker-and-executor-inactive-until-separate-activation-review",
    ))


AUTHORITY = RootlessDockerAuthority()


__all__ = ("PackageAuthority", "SystemdTemplateDropInAuthority", "RootlessDockerAuthority", "AUTHORITY")
