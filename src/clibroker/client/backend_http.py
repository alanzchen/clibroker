"""Direct HTTP backend for the broker client."""

from __future__ import annotations

from typing import Any

from .config import HTTPBackendConfig
from ..models import ClientConfigResponse, ExecuteResponse


class ClientBackendError(RuntimeError):
    """Raised when the client cannot talk to the broker server."""


def _require_httpx():
    try:
        import httpx
    except ModuleNotFoundError as exc:
        raise ClientBackendError(
            "Client support requires the optional dependency 'httpx'. "
            "Install it with `pip install clibroker[client]`."
        ) from exc
    return httpx


class HttpBackend:
    """HTTP backend that talks directly to a clibroker server."""

    def __init__(
        self,
        config: HTTPBackendConfig,
        *,
        transport: Any | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    @property
    def config(self) -> HTTPBackendConfig:
        """Expose the resolved backend config wrapper."""

        return self._config

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._config.resolve_token()}"}

    async def fetch_config(self) -> ClientConfigResponse:
        """Fetch the token-scoped discovery document from the broker."""

        httpx = _require_httpx()

        try:
            async with httpx.AsyncClient(
                base_url=self._config.base_url,
                headers=self._headers(),
                timeout=self._config.timeout_s,
                verify=self._config.verify_tls,
                transport=self._transport,
            ) as client:
                response = await client.get("/client-config")
        except Exception as exc:  # pragma: no cover - transport library specific
            raise ClientBackendError(f"Failed to fetch client config: {exc}") from exc

        if response.status_code != 200:
            raise ClientBackendError(
                _format_http_error("fetch client config", response)
            )

        return ClientConfigResponse.model_validate(response.json())

    async def execute(self, tool: str, argv: list[str]) -> ExecuteResponse:
        """Forward an execute request to the broker server."""

        httpx = _require_httpx()

        try:
            async with httpx.AsyncClient(
                base_url=self._config.base_url,
                headers=self._headers(),
                timeout=self._config.timeout_s,
                verify=self._config.verify_tls,
                transport=self._transport,
            ) as client:
                response = await client.post(
                    "/execute",
                    json={"tool": tool, "argv": argv},
                )
        except Exception as exc:  # pragma: no cover - transport library specific
            raise ClientBackendError(f"Failed to execute command: {exc}") from exc

        if response.status_code != 200:
            raise ClientBackendError(_format_http_error("execute command", response))

        return ExecuteResponse.model_validate(response.json())


def _format_http_error(action: str, response: Any) -> str:
    """Format a useful error message from an HTTP error response."""

    detail = None
    try:
        payload = response.json()
        if isinstance(payload, dict):
            detail = payload.get("detail")
    except Exception:  # pragma: no cover - defensive only
        detail = None

    if detail:
        return f"Failed to {action}: HTTP {response.status_code}: {detail}"
    return f"Failed to {action}: HTTP {response.status_code}"
