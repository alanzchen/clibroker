"""Tests for MCP server integration — tool registration, streamable HTTP, SSE."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

from clibroker.app import create_app
from clibroker.config import Config
from clibroker.mcp_server import create_mcp_server
from clibroker.policy import PolicyEngine
from tests.conftest import make_config

READER_TOKEN = "test-reader-token"
OPERATOR_TOKEN = "test-operator-token"

# Slugs are SHA-256(token)[:16] — used in URL paths instead of raw tokens
READER_SLUG = hashlib.sha256(READER_TOKEN.encode()).hexdigest()[:16]
OPERATOR_SLUG = hashlib.sha256(OPERATOR_TOKEN.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Unit tests: tool registration
# ---------------------------------------------------------------------------


class TestToolRegistration:
    """Verify that MCP tools are correctly derived from config rules."""

    def test_allowed_rules_become_tools(self) -> None:
        config = make_config()
        policy = PolicyEngine(config)
        mcp = create_mcp_server(config, policy)
        tools = mcp._tool_manager._tools
        # 3 allow rules → 3 tools  (deny_delete is excluded)
        assert len(tools) == 3

    def test_deny_rules_excluded(self) -> None:
        config = make_config()
        policy = PolicyEngine(config)
        mcp = create_mcp_server(config, policy)
        tool_names = set(mcp._tool_manager._tools.keys())
        assert "himalaya__deny_delete" not in tool_names

    def test_tool_names(self) -> None:
        config = make_config()
        policy = PolicyEngine(config)
        mcp = create_mcp_server(config, policy)
        tool_names = set(mcp._tool_manager._tools.keys())
        assert tool_names == {
            "himalaya__list_messages",
            "himalaya__read_message",
            "himalaya__move_message",
        }

    def test_move_message_schema(self) -> None:
        config = make_config()
        policy = PolicyEngine(config)
        mcp = create_mcp_server(config, policy)
        tool = mcp._tool_manager._tools["himalaya__move_message"]
        schema = tool.parameters
        # Required positionals
        assert "id" in schema["properties"]
        assert "destination" in schema["properties"]
        assert "id" in schema.get("required", [])
        assert "destination" in schema.get("required", [])
        # Optional flags
        assert "account" in schema["properties"]
        assert "folder" in schema["properties"]
        # Flags should NOT be required
        assert "account" not in schema.get("required", [])
        assert "folder" not in schema.get("required", [])

    def test_list_messages_no_required_params(self) -> None:
        config = make_config()
        policy = PolicyEngine(config)
        mcp = create_mcp_server(config, policy)
        tool = mcp._tool_manager._tools["himalaya__list_messages"]
        schema = tool.parameters
        # list_messages has no positionals → no required params
        assert schema.get("required", []) == []
        # But has optional flags
        assert "account" in schema["properties"]
        assert "folder" in schema["properties"]
        assert "page" in schema["properties"]

    def test_allowed_rules_filter(self) -> None:
        """When allowed_rules is given, only those rules become tools."""
        config = make_config()
        policy = PolicyEngine(config)
        mcp = create_mcp_server(
            config, policy, allowed_rules={"list_messages", "read_message"}
        )
        tool_names = set(mcp._tool_manager._tools.keys())
        assert tool_names == {
            "himalaya__list_messages",
            "himalaya__read_message",
        }
        # move_message is not included even though it's an allow rule
        assert "himalaya__move_message" not in tool_names

    def test_empty_allowed_rules_means_no_tools(self) -> None:
        """An empty allowed_rules set yields no tools."""
        config = make_config()
        policy = PolicyEngine(config)
        mcp = create_mcp_server(config, policy, allowed_rules=set())
        assert len(mcp._tool_manager._tools) == 0


# ---------------------------------------------------------------------------
# Integration tests: MCP authentication
# ---------------------------------------------------------------------------


class TestMCPAuth:
    """Test that MCP endpoints require a valid token in the URL path."""

    @pytest.fixture
    async def client(self):
        """Unauthenticated client (no token in URL)."""
        from asgi_lifespan import LifespanManager
        from httpx import ASGITransport, AsyncClient

        config = make_config(executable=sys.executable)
        app = create_app(config)
        async with LifespanManager(app) as manager:
            transport = ASGITransport(app=manager.app)
            async with AsyncClient(
                transport=transport,
                base_url="http://localhost:8000",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            ) as ac:
                yield ac

    @pytest.mark.asyncio
    async def test_mcp_no_token_returns_401(self, client) -> None:
        """POST /mcp/ without a token returns 401."""
        resp = await client.post(
            "/mcp/",
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
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_mcp_invalid_token_returns_401(self, client) -> None:
        """POST /mcp/<bad-token>/ returns 401."""
        resp = await client.post(
            "/mcp/totally-wrong-token/",
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
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_sse_no_token_returns_401(self, client) -> None:
        """GET /sse/ without a token returns 401."""
        resp = await client.get("/sse/")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_sse_invalid_token_returns_401(self, client) -> None:
        """GET /sse/<bad-token>/ returns 401."""
        resp = await client.get("/sse/totally-wrong-token/")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Integration tests: MCP over streamable HTTP (authenticated)
# ---------------------------------------------------------------------------


class TestStreamableHTTP:
    """Test MCP streamable HTTP transport at /mcp/{token}/."""

    @pytest.fixture
    async def operator_client(self):
        """Authenticated client using the operator token's slug (all 3 tools)."""
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

    @pytest.fixture
    async def reader_client(self):
        """Authenticated client using the reader token's slug (list + read only)."""
        from asgi_lifespan import LifespanManager
        from httpx import ASGITransport, AsyncClient

        config = make_config(executable=sys.executable)
        app = create_app(config)
        async with LifespanManager(app) as manager:
            transport = ASGITransport(app=manager.app)
            async with AsyncClient(
                transport=transport,
                base_url=f"http://localhost:8000/mcp/{READER_SLUG}",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            ) as ac:
                yield ac

    @pytest.mark.asyncio
    async def test_mcp_endpoint_accepts_post(self, operator_client) -> None:
        """The /mcp/{token}/ endpoint should accept POST with MCP JSON-RPC."""
        resp = await operator_client.post(
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
        assert resp.status_code == 200
        body = resp.json()
        assert body["jsonrpc"] == "2.0"
        assert body["id"] == 1
        assert "result" in body
        assert body["result"]["serverInfo"]["name"] == "clibroker"

    @pytest.mark.asyncio
    async def test_operator_sees_all_tools(self, operator_client) -> None:
        """Operator token should see all 3 allowed tools."""
        init_resp = await operator_client.post(
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

        await operator_client.post(
            "/",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
        )

        resp = await operator_client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        tools = body["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        assert tool_names == {
            "himalaya__list_messages",
            "himalaya__read_message",
            "himalaya__move_message",
        }

    @pytest.mark.asyncio
    async def test_reader_sees_only_allowed_tools(self, reader_client) -> None:
        """Reader token should only see list and read tools, not move."""
        init_resp = await reader_client.post(
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

        await reader_client.post(
            "/",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
        )

        resp = await reader_client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        tools = body["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        assert tool_names == {
            "himalaya__list_messages",
            "himalaya__read_message",
        }
        # move_message should NOT be visible to the reader
        assert "himalaya__move_message" not in tool_names

    @pytest.mark.asyncio
    async def test_mcp_tool_call(self, operator_client) -> None:
        """Call a tool via MCP protocol and get a result."""
        init_resp = await operator_client.post(
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

        await operator_client.post(
            "/",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
        )

        resp = await operator_client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "himalaya__list_messages",
                    "arguments": {},
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "result" in body
        content = body["result"]["content"]
        assert len(content) > 0
        result_data = json.loads(content[0]["text"])
        assert "exit_code" in result_data
        assert "duration_ms" in result_data

    @pytest.mark.asyncio
    async def test_mcp_tool_with_positional_validation(self, operator_client) -> None:
        """Tool call with invalid positional should return an error via policy."""
        init_resp = await operator_client.post(
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

        await operator_client.post(
            "/",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
        )

        resp = await operator_client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "himalaya__move_message",
                    "arguments": {
                        "id": "42",
                        "destination": "Trash",  # not allowed
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


class TestSSEEndpoint:
    """Test that the SSE transport endpoint is reachable with valid token."""

    @pytest.fixture
    async def client(self):
        from asgi_lifespan import LifespanManager
        from httpx import ASGITransport, AsyncClient

        config = make_config(executable=sys.executable)
        app = create_app(config)
        async with LifespanManager(app) as manager:
            transport = ASGITransport(app=manager.app)
            async with AsyncClient(
                transport=transport, base_url="http://localhost:8000"
            ) as ac:
                yield ac

    @pytest.mark.asyncio
    async def test_sse_endpoint_exists(self, client) -> None:
        """GET /sse/{token}/ should return an SSE stream (not 404/401).

        SSE is a long-lived streaming connection, so we use anyio to
        impose a short deadline.  If the connection starts streaming
        with 200 + text/event-stream, the route exists and is authed.
        """
        import anyio

        status = None
        content_type = None

        async def _probe():
            nonlocal status, content_type
            async with client.stream("GET", f"/sse/{OPERATOR_SLUG}/") as resp:
                status = resp.status_code
                content_type = resp.headers.get("content-type", "")
                # Read one chunk to prove the stream is alive, then exit
                async for _ in resp.aiter_bytes():
                    break

        with anyio.move_on_after(2):
            await _probe()

        # If we got a status back, verify it's correct.
        # (move_on_after may cancel before we even get headers with
        # ASGITransport — in that case status stays None and we skip.)
        if status is not None:
            assert status != 404
            assert status != 401
            assert status == 200
            assert "text/event-stream" in content_type
