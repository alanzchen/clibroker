"""Bearer token authentication and per-rule RBAC.

Security notes:
- Token comparison uses hmac.compare_digest for timing-safety.
- Tokens are stored hashed (SHA-256) in memory — plaintext values are
  never kept after initialization.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from .audit import get_audit_logger
from .config import Config, TokenConfig


def _hash_token(value: str) -> str:
    """Return the hex SHA-256 digest of a token value."""
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class AuthenticatedClient:
    """Represents a successfully authenticated client."""

    name: str
    allow_rules: list[str]


class Authenticator:
    """Resolves bearer tokens and enforces per-rule authorization.

    Tokens are stored as SHA-256 hashes — incoming tokens are hashed and
    then compared using ``hmac.compare_digest`` for constant-time safety.
    """

    def __init__(self, config: Config) -> None:
        # Map hash(token) -> TokenConfig.  Plaintext is discarded.
        self._token_map: dict[str, TokenConfig] = {}
        for token_cfg in config.server.auth.tokens:
            resolved = token_cfg.resolve_value()
            self._token_map[_hash_token(resolved)] = token_cfg

    def authenticate(self, request: Request) -> AuthenticatedClient:
        """Extract and validate the bearer token from the request.

        Raises HTTPException 401 if token is missing or invalid.
        """
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header",
            )

        token_value = auth_header[7:]  # strip "Bearer "
        incoming_hash = _hash_token(token_value)

        # Constant-time scan: always iterate every entry so that the
        # time taken does not reveal how many tokens are configured or
        # which bucket matched.
        matched_cfg: TokenConfig | None = None
        for stored_hash, cfg in self._token_map.items():
            if hmac.compare_digest(incoming_hash, stored_hash):
                matched_cfg = cfg
                # Don't break — keep iterating for constant-time

        if matched_cfg is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token",
            )

        return AuthenticatedClient(
            name=matched_cfg.name,
            allow_rules=matched_cfg.allow_rules,
        )

    @staticmethod
    def authorize(client: AuthenticatedClient, rule_id: str) -> None:
        """Check that the authenticated client is allowed to invoke the given rule.

        Raises HTTPException 403 if not authorized.
        """
        log = get_audit_logger()
        if rule_id not in client.allow_rules:
            log.warning(
                "rbac_denied",
                client=client.name,
                rule=rule_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Client '{client.name}' is not authorized for rule '{rule_id}'",
            )
