"""Read the fixed broker config for privileged migration without broker identity.

The live broker loader is intentionally broker-UID-bound. This root-only
adapter reuses its frozen descriptor traversal, canonical parser and
revalidation primitives, then binds only the protected directory/file GID to
the parsed broker configuration.

Related: broker_service_config_loader.py, root_executor_configuration_reader.py.
"""

from __future__ import annotations

import os

from . import broker_service_config as config
from . import broker_service_config_loader as loader


__all__ = (
    "RootBrokerConfigurationUnavailableError",
    "read_root_dev_broker_configuration",
)

_ERROR = "DEV broker configuration is unavailable to privileged migration"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class RootBrokerConfigurationUnavailableError(Exception):
    """One fixed external failure for the root-only broker read boundary."""


def _root_identity() -> tuple[int, int, int, int]:
    """Require an unchanged real/effective root process identity."""

    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if any(type(value) is not int or value != 0 for value in identity):
        raise OSError
    return identity

def read_root_dev_broker_configuration() -> config.DevBrokerServiceConfiguration:
    """Return canonical fixed-path broker authority under root process binding."""

    owned: list[int] = []
    failure = False
    control = None
    result = None
    try:
        first_identity = _root_identity()
        if (
            loader._CONFIG_PATH != config.PRODUCTION_BROKER_SERVICE_CONFIG_PATH
            or loader._DIRECTORY_COMPONENTS
            != ("etc", "omnilyzer", "deployment", "broker")
            or loader._FILE_NAME != "dev.json"
            or loader._CONFIG_PATH
            != "/" + "/".join((*loader._DIRECTORY_COMPONENTS, loader._FILE_NAME))
        ):
            raise OSError
        directory_flags, file_flags = loader._required_flags()
        directories, final_directory = loader._open_directories(
            owned, directory_flags,
        )
        descriptor, file_status = loader._open_configuration_file(
            final_directory, file_flags, owned,
        )
        raw = loader._bounded_read(descriptor, file_status[6])
        configuration = loader._parse_configuration(raw)
        if type(configuration) is not config.DevBrokerServiceConfiguration:
            raise OSError
        loader._revalidate_file(descriptor, final_directory, file_status)
        directory_status = loader._revalidate_directories(directories)
        if (
            directory_status[5] != configuration.broker_gid
            or file_status[5] != configuration.broker_gid
            or _root_identity() != first_identity
        ):
            raise OSError
        result = configuration
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        try:
            cleanup_failed, cleanup_control = loader._close_owned(owned)
            failure = failure or cleanup_failed
            control = control or cleanup_control
        except _CONTROL as error:
            control = control or error
        except Exception:
            failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise RootBrokerConfigurationUnavailableError(_ERROR) from None
    return result
