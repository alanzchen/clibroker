"""End-to-end API tests using FastAPI TestClient."""

from __future__ import annotations

import sys

import pytest
from httpx import ASGITransport, AsyncClient

from clibroker.app import create_app
from tests.conftest import make_config

READER_TOKEN = "test-reader-token"
OPERATOR_TOKEN = "test-operator-token"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """Create an async test client with echo as the tool executable."""
    config = make_config(
        executable=sys.executable,
        token_reader=READER_TOKEN,
        token_operator=OPERATOR_TOKEN,
    )
    app = create_app(config)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestAuthentication:
    """Test bearer token authentication."""

    @pytest.mark.asyncio
    async def test_missing_auth_header(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "list"]},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "list"]},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_accepted(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "list"]},
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        # Should not be 401/403 — may be non-zero exit code from echo but the
        # request itself should be processed
        assert resp.status_code == 200


class TestAuthorization:
    """Test per-rule RBAC."""

    @pytest.mark.asyncio
    async def test_reader_cannot_move(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={
                "tool": "himalaya",
                "argv": ["message", "move", "42", "Archive"],
            },
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_operator_can_move(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={
                "tool": "himalaya",
                "argv": ["message", "move", "42", "Archive"],
            },
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )
        assert resp.status_code == 200


class TestPolicyEnforcement:
    """Test that policy denials and no-match are returned properly."""

    @pytest.mark.asyncio
    async def test_deny_rule_returns_denied(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "delete"]},
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["matched_rule"] == "deny_delete"

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_no_match(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "unknown", "argv": ["anything"]},
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["matched_rule"] == ""

    @pytest.mark.asyncio
    async def test_invalid_flag_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={
                "tool": "himalaya",
                "argv": ["message", "list", "--evil-flag", "payload"],
            },
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "not allowed" in body["stderr"]

    @pytest.mark.asyncio
    async def test_standalone_flag_accepted(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "list", "--unread"]},
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["matched_rule"] == "list_messages"

    @pytest.mark.asyncio
    async def test_invalid_positional_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "read", "not-a-number"]},
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "pattern" in body["stderr"]


class TestExecution:
    """Test actual subprocess execution through the API.

    Uses sys.executable (Python) as the 'himalaya' tool so we can verify
    end-to-end argv construction and execution.
    """

    @pytest.mark.asyncio
    async def test_list_messages_executes(self, client: AsyncClient) -> None:
        """The executable is Python, so it will receive the constructed argv.
        It won't do anything meaningful, but the process runs and returns."""
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "list"]},
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        # Python will fail because '--output' isn't a valid python flag,
        # but the point is the process ran
        assert "matched_rule" in body
        assert body["matched_rule"] == "list_messages"
        assert isinstance(body["duration_ms"], float)

    @pytest.mark.asyncio
    async def test_response_structure(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": ["message", "list"]},
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        body = resp.json()
        assert "ok" in body
        assert "exit_code" in body
        assert "stdout" in body
        assert "stderr" in body
        assert "duration_ms" in body
        assert "matched_rule" in body
        assert "timed_out" in body


class TestRequestValidation:
    """Test Pydantic request validation."""

    @pytest.mark.asyncio
    async def test_empty_argv_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"tool": "himalaya", "argv": []},
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_tool_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/execute",
            json={"argv": ["message", "list"]},
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
        assert resp.status_code == 422
