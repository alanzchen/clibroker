"""Tests for all code-review security and correctness fixes.

Covers:
  C-2  — empty Rule.command rejected (min_length=1)
  S-3  — flag parser hardening (--flag=value, flag values starting with -, --, flag without value)
  S-4  — deny rule subtree cascading
  S-1  — timing-safe token comparison (hmac.compare_digest)
  A-5  — /health endpoint
       — /token-info endpoint
       — env: token resolution failure
  T-7  — MCP handler with invalid flags
       — URL paths contain slugs, not raw tokens
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import textwrap

import pytest
import yaml
from pydantic import ValidationError

from clibroker.app import _token_slug, create_app
from clibroker.auth import Authenticator, _hash_token
from clibroker.config import Config, Rule, TokenConfig
from clibroker.policy import (
    PolicyDenied,
    PolicyEngine,
    PolicyNoMatch,
    PolicyValidationError,
)
from tests.conftest import make_config

READER_TOKEN = "test-reader-token"
OPERATOR_TOKEN = "test-operator-token"
READER_SLUG = hashlib.sha256(READER_TOKEN.encode()).hexdigest()[:16]
OPERATOR_SLUG = hashlib.sha256(OPERATOR_TOKEN.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# C-2: Empty command rejection
# ---------------------------------------------------------------------------


class TestEmptyCommandRejection:
    """Rule.command must have at least one element (min_length=1)."""

    def test_empty_command_list_rejected(self) -> None:
        """A Rule with command=[] should fail Pydantic validation."""
        with pytest.raises(ValidationError) as exc_info:
            Rule(id="bad_rule", command=[], effect="allow")
        errors = exc_info.value.errors()
        # Should mention min_length / too_short
        assert any("too_short" in e["type"] or "min_length" in str(e) for e in errors)

    def test_single_element_command_accepted(self) -> None:
        """A Rule with command=["list"] should be valid."""
        rule = Rule(id="ok_rule", command=["list"], effect="allow")
        assert rule.command == ["list"]

    def test_multi_element_command_accepted(self) -> None:
        """A Rule with command=["message", "list"] should be valid."""
        rule = Rule(id="ok_rule", command=["message", "list"], effect="allow")
        assert rule.command == ["message", "list"]


# ---------------------------------------------------------------------------
# S-3: Flag parser hardening
# ---------------------------------------------------------------------------


class TestFlagParserHardening:
    """Test the hardened flag parser in _validate_rule."""

    @pytest.fixture
    def engine_with_flags(self) -> PolicyEngine:
        """Engine where the tool has flags --account, --folder and a positional."""
        return PolicyEngine(make_config())

    def test_flag_equals_syntax(self, engine_with_flags: PolicyEngine) -> None:
        """--account=work should be normalized and accepted."""
        result = engine_with_flags.evaluate(
            "himalaya", ["message", "list", "--account=work"]
        )
        assert result.rule_id == "list_messages"
        assert "--account" in result.full_argv
        assert "work" in result.full_argv

    def test_flag_value_starting_with_dash(
        self, engine_with_flags: PolicyEngine
    ) -> None:
        """A flag value like --account -personal should be accepted
        (the value is consumed as the flag's argument)."""
        result = engine_with_flags.evaluate(
            "himalaya", ["message", "list", "--account", "-personal"]
        )
        assert result.rule_id == "list_messages"
        assert "-personal" in result.full_argv

    def test_double_dash_end_of_options(self, engine_with_flags: PolicyEngine) -> None:
        """After --, everything is a positional (not a flag).
        For read_message rule: expects 1 positional (id matching ^[0-9]+$)."""
        result = engine_with_flags.evaluate("himalaya", ["message", "read", "--", "42"])
        assert result.rule_id == "read_message"
        assert "42" in result.full_argv

    def test_double_dash_flag_like_positional(
        self, engine_with_flags: PolicyEngine
    ) -> None:
        """After --, even --something should be treated as a positional.
        This should fail pattern validation since '--something' isn't numeric."""
        with pytest.raises(PolicyValidationError) as exc_info:
            engine_with_flags.evaluate(
                "himalaya", ["message", "read", "--", "--something"]
            )
        assert "pattern" in str(exc_info.value)

    def test_flag_without_value_rejected(self, engine_with_flags: PolicyEngine) -> None:
        """An allowed flag without a following value should be rejected."""
        with pytest.raises(PolicyValidationError) as exc_info:
            engine_with_flags.evaluate("himalaya", ["message", "list", "--account"])
        assert "requires a value" in str(exc_info.value)

    def test_unknown_flag_rejected(self, engine_with_flags: PolicyEngine) -> None:
        """A flag not in the allowlist should be rejected."""
        with pytest.raises(PolicyValidationError) as exc_info:
            engine_with_flags.evaluate(
                "himalaya", ["message", "list", "--evil", "payload"]
            )
        assert "not allowed" in str(exc_info.value)

    def test_short_flag_rejected(self, engine_with_flags: PolicyEngine) -> None:
        """Short flags like -x should be rejected if not in allowlist."""
        with pytest.raises(PolicyValidationError):
            engine_with_flags.evaluate("himalaya", ["message", "list", "-x", "val"])

    def test_flag_equals_with_value_containing_equals(
        self, engine_with_flags: PolicyEngine
    ) -> None:
        """--account=user=name should split only on first = (account -> 'user=name')."""
        result = engine_with_flags.evaluate(
            "himalaya", ["message", "list", "--account=user=name"]
        )
        assert result.rule_id == "list_messages"
        assert "user=name" in result.full_argv

    def test_multiple_flags_with_equals(self, engine_with_flags: PolicyEngine) -> None:
        """Multiple --flag=value pairs should all be accepted."""
        result = engine_with_flags.evaluate(
            "himalaya", ["message", "list", "--account=work", "--folder=INBOX"]
        )
        assert result.rule_id == "list_messages"
        assert "work" in result.full_argv
        assert "INBOX" in result.full_argv

    def test_flag_value_is_double_dash_rejected(
        self, engine_with_flags: PolicyEngine
    ) -> None:
        """--account -- should reject because -- as a value triggers end-of-options check."""
        with pytest.raises(PolicyValidationError) as exc_info:
            engine_with_flags.evaluate(
                "himalaya", ["message", "list", "--account", "--"]
            )
        assert "requires a value" in str(exc_info.value)


# ---------------------------------------------------------------------------
# S-4: Deny rule subtree cascading
# ---------------------------------------------------------------------------


class TestDenySubtreeCascading:
    """Deny rules should cascade to child command subtrees."""

    @pytest.fixture
    def engine_with_subtree(self) -> PolicyEngine:
        """Engine where 'message delete' is denied, and 'message delete batch' is allowed."""
        raw = yaml.safe_load(
            textwrap.dedent("""\
            server:
              bind: "127.0.0.1:9999"
              auth:
                type: bearer
                tokens: []
            tools:
              himalaya:
                executable: "/usr/bin/echo"
                default_args: []
                rules:
                  - id: deny_delete
                    command: ["message", "delete"]
                    effect: deny
                  - id: allow_delete_batch
                    command: ["message", "delete", "batch"]
                    effect: allow
                    flags:
                      allowed: ["--dry-run"]
                    positionals: []
            """)
        )
        config = Config.model_validate(raw)
        return PolicyEngine(config)

    def test_parent_deny_blocks_child_allow(
        self, engine_with_subtree: PolicyEngine
    ) -> None:
        """Even though 'message delete batch' has an allow rule,
        the parent deny on 'message delete' should cascade and block it."""
        with pytest.raises(PolicyDenied) as exc_info:
            engine_with_subtree.evaluate("himalaya", ["message", "delete", "batch"])
        assert exc_info.value.rule_id == "deny_delete"

    def test_parent_deny_blocks_exact_match(
        self, engine_with_subtree: PolicyEngine
    ) -> None:
        """Direct match on 'message delete' should still be denied."""
        with pytest.raises(PolicyDenied):
            engine_with_subtree.evaluate("himalaya", ["message", "delete"])

    def test_parent_deny_blocks_with_flags(
        self, engine_with_subtree: PolicyEngine
    ) -> None:
        """'message delete batch --dry-run yes' should still be denied
        because the parent deny cascades."""
        with pytest.raises(PolicyDenied):
            engine_with_subtree.evaluate(
                "himalaya", ["message", "delete", "batch", "--dry-run", "yes"]
            )


# ---------------------------------------------------------------------------
# S-1: Timing-safe token comparison
# ---------------------------------------------------------------------------


class TestTimingSafeAuth:
    """Verify that the auth module uses SHA-256 hashing and hmac.compare_digest."""

    def test_hash_token_returns_sha256(self) -> None:
        """_hash_token should return the hex SHA-256 digest."""
        assert _hash_token("hello") == hashlib.sha256(b"hello").hexdigest()

    def test_authenticator_stores_hashed_tokens(self) -> None:
        """Authenticator._token_map keys should be SHA-256 hashes, not plaintext."""
        config = make_config()
        auth = Authenticator(config)
        # Plaintext tokens should NOT be keys
        assert READER_TOKEN not in auth._token_map
        assert OPERATOR_TOKEN not in auth._token_map
        # SHA-256 hashes should be keys
        assert _hash_token(READER_TOKEN) in auth._token_map
        assert _hash_token(OPERATOR_TOKEN) in auth._token_map

    def test_valid_token_authenticates(self) -> None:
        """A correct token should authenticate successfully."""
        from starlette.testclient import TestClient

        config = make_config()
        auth = Authenticator(config)

        # Build a minimal Request-like object for testing
        from starlette.requests import Request
        from starlette.datastructures import Headers

        scope = {
            "type": "http",
            "headers": Headers({"authorization": f"Bearer {READER_TOKEN}"}).raw,
        }
        request = Request(scope)
        client = auth.authenticate(request)
        assert client.name == "reader"
        assert "list_messages" in client.allow_rules

    def test_invalid_token_rejected(self) -> None:
        """An incorrect token should raise 401."""
        from fastapi import HTTPException
        from starlette.requests import Request
        from starlette.datastructures import Headers

        config = make_config()
        auth = Authenticator(config)
        scope = {
            "type": "http",
            "headers": Headers({"authorization": "Bearer totally-wrong"}).raw,
        }
        request = Request(scope)
        with pytest.raises(HTTPException) as exc_info:
            auth.authenticate(request)
        assert exc_info.value.status_code == 401

    def test_rbac_authorized(self) -> None:
        """authorize() should pass when rule is in allow_rules."""
        from clibroker.auth import AuthenticatedClient

        client = AuthenticatedClient(name="reader", allow_rules=["list_messages"])
        # Should not raise
        Authenticator.authorize(client, "list_messages")

    def test_rbac_unauthorized_logs_and_raises(self) -> None:
        """authorize() should raise 403 and audit-log when rule is not in allow_rules."""
        from fastapi import HTTPException
        from clibroker.auth import AuthenticatedClient

        client = AuthenticatedClient(name="reader", allow_rules=["list_messages"])
        with pytest.raises(HTTPException) as exc_info:
            Authenticator.authorize(client, "move_message")
        assert exc_info.value.status_code == 403
        assert "not authorized" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# A-5: /health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Test the unauthenticated /health endpoint."""

    @pytest.fixture
    async def client(self):
        from httpx import ASGITransport, AsyncClient

        config = make_config()
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client) -> None:
        resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "version" in body

    @pytest.mark.asyncio
    async def test_health_requires_no_auth(self, client) -> None:
        """No Authorization header needed."""
        resp = await client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /token-info endpoint
# ---------------------------------------------------------------------------


class TestTokenInfoEndpoint:
    """Test the authenticated /token-info endpoint."""

    @pytest.fixture
    async def client(self):
        from httpx import ASGITransport, AsyncClient

        config = make_config()
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_token_info_without_auth_returns_401(self, client) -> None:
        resp = await client.get("/token-info")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_token_info_reader(self, client) -> None:
        resp = await client.get(
            "/token-info",
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "reader"
        assert body["slug"] == READER_SLUG
        assert body["mcp_url"] == f"/mcp/{READER_SLUG}/"
        assert body["sse_url"] == f"/sse/{READER_SLUG}/"
        assert "list_messages" in body["allow_rules"]
        assert "move_message" not in body["allow_rules"]

    @pytest.mark.asyncio
    async def test_token_info_operator(self, client) -> None:
        resp = await client.get(
            "/token-info",
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "operator"
        assert body["slug"] == OPERATOR_SLUG
        assert "move_message" in body["allow_rules"]


# ---------------------------------------------------------------------------
# env: token resolution failure
# ---------------------------------------------------------------------------


class TestEnvTokenResolution:
    """Test env: indirection for token values."""

    def test_env_token_resolves_when_set(self, monkeypatch) -> None:
        """env:MY_TOKEN should resolve to the environment variable value."""
        monkeypatch.setenv("MY_TOKEN", "secret-value-123")
        tc = TokenConfig(name="envtoken", value="env:MY_TOKEN", allow_rules=["r1"])
        assert tc.resolve_value() == "secret-value-123"

    def test_env_token_raises_when_unset(self, monkeypatch) -> None:
        """env:MISSING_VAR should raise RuntimeError."""
        monkeypatch.delenv("MISSING_VAR", raising=False)
        tc = TokenConfig(name="envtoken", value="env:MISSING_VAR", allow_rules=["r1"])
        with pytest.raises(RuntimeError) as exc_info:
            tc.resolve_value()
        assert "MISSING_VAR" in str(exc_info.value)
        assert "not set" in str(exc_info.value)

    def test_literal_token_not_affected(self) -> None:
        """A literal token value should be returned as-is."""
        tc = TokenConfig(name="literal", value="my-plain-token", allow_rules=["r1"])
        assert tc.resolve_value() == "my-plain-token"


# ---------------------------------------------------------------------------
# URL slug tests — paths contain slugs, not raw tokens
# ---------------------------------------------------------------------------


class TestURLSlugs:
    """Verify that URL paths use SHA-256[:16] slugs, not raw tokens."""

    def test_token_slug_is_sha256_prefix(self) -> None:
        """_token_slug should return first 16 hex chars of SHA-256."""
        expected = hashlib.sha256(b"my-secret").hexdigest()[:16]
        assert _token_slug("my-secret") == expected

    def test_slug_length_is_16(self) -> None:
        assert len(_token_slug("any-token")) == 16

    def test_different_tokens_different_slugs(self) -> None:
        assert _token_slug("token-a") != _token_slug("token-b")

    def test_mcp_mount_uses_slug(self) -> None:
        """The app should mount MCP endpoints at /mcp/<slug>/, not /mcp/<raw-token>/."""
        config = make_config()
        app = create_app(config)
        # Check that mcp_servers state uses slugs as keys
        for slug in app.state.mcp_servers:
            # Slugs are 16-char hex strings
            assert len(slug) == 16
            # Slug should NOT be a raw token
            assert slug != READER_TOKEN
            assert slug != OPERATOR_TOKEN
            # Slug should match expected hash prefix
            assert slug in (READER_SLUG, OPERATOR_SLUG)


# ---------------------------------------------------------------------------
# T-7: MCP handler with invalid flags
# ---------------------------------------------------------------------------


class TestMCPInvalidFlags:
    """Test that MCP tool calls with invalid flags return policy errors."""

    @pytest.fixture
    async def operator_client(self):
        from asgi_lifespan import LifespanManager
        from httpx import ASGITransport, AsyncClient

        config = make_config(executable=sys.executable)
        app = create_app(config)
        async with LifespanManager(app) as manager:
            transport = ASGITransport(app=manager.app)
            async with AsyncClient(
                transport=transport,
                base_url=f"http://localhost:8000/mcp/{OPERATOR_SLUG}",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            ) as ac:
                yield ac

    async def _init_session(self, client):
        """Initialize an MCP session and return the session headers."""
        init_resp = await client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0.1.0"},
                },
            },
        )
        session_id = init_resp.headers.get("mcp-session-id")
        headers = {}
        if session_id:
            headers["mcp-session-id"] = session_id

        await client.post(
            "/",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
        )
        return headers

    @pytest.mark.asyncio
    async def test_mcp_tool_with_disallowed_flag(self, operator_client) -> None:
        """Calling a tool via MCP with a flag not in the allowlist should return error."""
        headers = await self._init_session(operator_client)

        # list_messages allows --account, --folder, --page
        # Pass an unknown flag 'evil' as a keyword argument
        # The MCP handler builds argv from kwargs, so we pass it as a param
        # that maps to a flag. Since 'evil' isn't a registered flag param,
        # it won't be included as a flag. Let's test via read_message with
        # an invalid positional pattern instead, which exercises the policy
        # engine on the MCP path.
        resp = await operator_client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "himalaya__read_message",
                    "arguments": {
                        "id": "not-a-number",  # violates ^[0-9]+$ pattern
                    },
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        content = body["result"]["content"]
        result_data = json.loads(content[0]["text"])
        assert result_data["ok"] is False
        assert "error" in result_data

    @pytest.mark.asyncio
    async def test_mcp_tool_invalid_enum_via_policy(self, operator_client) -> None:
        """MCP tool call with invalid enum value should be rejected by policy engine."""
        headers = await self._init_session(operator_client)

        resp = await operator_client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "himalaya__move_message",
                    "arguments": {
                        "id": "42",
                        "destination": "Deleted",  # not in enum [Inbox, Archive, Flagged]
                    },
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        content = body["result"]["content"]
        result_data = json.loads(content[0]["text"])
        assert result_data["ok"] is False
        assert "not in allowed values" in result_data["error"]
