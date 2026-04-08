"""Client-side helpers for connecting to a clibroker server."""

from __future__ import annotations

from .backend_http import ClientBackendError, HttpBackend
from .config import (
    BrokerClientConfig,
    HTTPBackendConfig,
    load_client_config,
    resolve_client_config_path,
)


def build_backend(
    config: BrokerClientConfig,
    backend_name: str | None = None,
    *,
    transport: object | None = None,
) -> HttpBackend:
    """Build the configured client backend.

    Today the only supported backend type is direct HTTP to the broker server.
    """

    backend_cfg = config.get_backend(backend_name)
    if backend_cfg.type == "http":
        return HttpBackend(backend_cfg, transport=transport)
    raise ValueError(f"Unsupported backend type: {backend_cfg.type}")


__all__ = [
    "BrokerClientConfig",
    "ClientBackendError",
    "HTTPBackendConfig",
    "HttpBackend",
    "build_backend",
    "load_client_config",
    "resolve_client_config_path",
]
