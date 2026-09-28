"""Read the fixed C17 config for privileged provisioning without executor identity.

The live executor loader is intentionally executor-UID-bound. This root-only
adapter reuses its frozen descriptor, parser and revalidation primitives, then
binds the parsed executor GID to the protected directory and file metadata.
"""

from __future__ import annotations

import os

from . import executor_service_config as c17
from . import executor_service_config_loader as loader

__all__ = ("RootExecutorConfigurationUnavailableError",
           "read_root_dev_executor_configuration")

_ERROR = "DEV executor configuration is unavailable to privileged provisioning"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class RootExecutorConfigurationUnavailableError(Exception):
    """One fixed external failure for the root-only read boundary."""


def _root_identity() -> tuple[int, int, int, int]:
    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if any(type(value) is not int or value != 0 for value in identity):
        raise OSError
    return identity


def read_root_dev_executor_configuration() -> c17.DevExecutorServiceConfiguration:
    """Return the canonical fixed-path C17 config with root process binding."""
    owned: list[int] = []
    failure = False
    control = None
    result = None
    try:
        first_identity = _root_identity()
        if (loader._CONFIG_PATH != c17.PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH
                or loader._DIRECTORY_COMPONENTS != ("etc", "omnilyzer", "deployment", "dev")
                or loader._FILE_NAME != "executor.json"
                or loader._CONFIG_PATH != "/" + "/".join((*loader._DIRECTORY_COMPONENTS,
                                                          loader._FILE_NAME))):
            raise OSError
        directory_flags, file_flags = loader._required_flags()
        directories, final_directory = loader._open_directories(owned, directory_flags)
        descriptor, file_status = loader._open_configuration_file(
            final_directory, file_flags, owned)
        raw = loader._bounded_read(descriptor, file_status[6])
        configuration = loader._parse_configuration(raw)
        if type(configuration) is not c17.DevExecutorServiceConfiguration:
            raise OSError
        loader._revalidate_file(descriptor, final_directory, file_status)
        directory_status = loader._revalidate_directories(directories)
        if (directory_status[5] != configuration.executor_gid
                or file_status[5] != configuration.executor_gid
                or _root_identity() != first_identity):
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
        raise RootExecutorConfigurationUnavailableError(_ERROR) from None
    return result
