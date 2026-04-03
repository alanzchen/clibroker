"""Client-side configuration models and YAML loading."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, field_validator, model_validator


class HTTPBackendConfig(BaseModel):
    """Config for the direct HTTP client backend."""

    type: Literal["http"] = "http"
    base_url: str
    token: str
    timeout_s: float = 30.0
    verify_tls: bool = True

    @field_validator("base_url")
    @classmethod
    def _normalize_base_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("base_url must not be empty")
        return value.rstrip("/")

    def resolve_token(self) -> str:
        """Return the concrete token value, resolving env indirection."""

        if self.token.startswith("env:"):
            var = self.token[4:]
            resolved = os.environ.get(var)
            if resolved is None:
                raise RuntimeError(
                    f"Backend token references env var '{var}' which is not set"
                )
            return resolved
        return self.token

    def redacted_dict(self) -> dict[str, object]:
        """Return a safe dict for display without exposing literal secrets."""

        token_display = self.token if self.token.startswith("env:") else "<redacted>"
        return {
            "type": self.type,
            "base_url": self.base_url,
            "token": token_display,
            "timeout_s": self.timeout_s,
            "verify_tls": self.verify_tls,
        }


class BrokerClientConfig(BaseModel):
    """Root config for the broker client CLI."""

    default_backend: str
    backends: dict[str, HTTPBackendConfig]

    @model_validator(mode="after")
    def _validate_default_backend(self) -> "BrokerClientConfig":
        if self.default_backend not in self.backends:
            raise ValueError(
                f"default_backend '{self.default_backend}' does not exist in backends"
            )
        return self

    def get_backend(self, name: str | None = None) -> HTTPBackendConfig:
        """Return the selected backend config."""

        backend_name = name or self.default_backend
        try:
            return self.backends[backend_name]
        except KeyError as exc:
            raise KeyError(f"Unknown backend '{backend_name}'") from exc


def load_client_config(path: str | Path) -> BrokerClientConfig:
    """Load and validate a broker client config file."""

    with open(path) as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError(
            f"Client config file must be a YAML mapping, got {type(raw).__name__}"
        )
    return BrokerClientConfig.model_validate(raw)
