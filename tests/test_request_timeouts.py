"""Request deadlines own execution cleanup and preserve recoverable outcomes."""

import asyncio
import hashlib
import sys

import httpx
import pytest
from asgi_lifespan import LifespanManager
from starlette.responses import StreamingResponse

from clibroker.app import create_app
from clibroker.config import Config
from clibroker.middleware import TimeoutMiddleware


def timeout_app(tmp_path, *, control=True, approval=False):
    marker = tmp_path / "late-effect"
    script = (
        "import time; from pathlib import Path; "
        f"Path({str(tmp_path / 'started')!r}).write_text('started'); "
        f"time.sleep(.6); Path({str(marker)!r}).write_text('done')"
    )
    server = {
        "request_timeout_s": 0.2,
        "auth": {
            "tokens": [
                {"name": "agent", "value": "agent-secret", "allow_rules": ["run"]},
                {
                    "name": "owner",
                    "role": "owner",
                    "value": "owner-secret",
                    "allow_rules": [],
                },
            ]
        },
    }
    if control:
        server["control"] = {"database_path": str(tmp_path / "control.db")}
    config = Config.model_validate(
        {
            "server": server,
            "tools": {
                "demo": {
                    "executable": sys.executable,
                    "default_args": ["-c", script],
                    "timeout_s": 3,
                    "rules": [
                        {"id": "run", "command": ["run"], "require_approval": approval}
                    ],
                }
            },
        }
    )
    return create_app(config), marker


@pytest.mark.parametrize("control", [True, False])
async def test_deadline_stops_command_before_504(tmp_path, control):
    app, marker = timeout_app(tmp_path, control=control)
    bodies = []

    async def observed(scope, receive, send):
        async def capture(message):
            if message["type"] == "http.response.start":
                bodies.append((message["status"], marker.exists()))
            await send(message)

        await app(scope, receive, capture)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=observed), base_url="http://test"
    ) as client:
        response = await client.post(
            "/execute",
            headers={"Authorization": "Bearer agent-secret"},
            json={"tool": "demo", "argv": ["run"]},
        )
        result = response.json()
        assert response.status_code == 504
        assert result["request_timed_out"] is True
        assert result["timed_out"] is False  # Distinct from the tool's timeout.
        assert result["request_id"] and result["state"] == "interrupted"
        assert "Do not automatically retry" in result["stderr"]
        assert response.headers["cache-control"] == "no-store"
        assert bodies == [(504, False)]
        assert (tmp_path / "started").exists()
        if control:
            saved = await client.get(
                f"/control/requests/{result['request_id']}",
                headers={"Authorization": "Bearer agent-secret"},
            )
            assert saved.json()["state"] == "interrupted"
            assert saved.json()["result"]["request_id"] == result["request_id"]
    await asyncio.sleep(0.65)
    assert not marker.exists()


async def test_approval_deadline_retains_id_and_cannot_run_again(tmp_path):
    app, marker = timeout_app(tmp_path, approval=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        pending = (
            await client.post(
                "/execute",
                headers={"Authorization": "Bearer agent-secret"},
                json={"tool": "demo", "argv": ["run"]},
            )
        ).json()
        url = f"/control/requests/{pending['request_id']}/decision"
        response = await client.post(
            url,
            headers={"Authorization": "Bearer owner-secret"},
            json={"decision": "approve"},
        )
        assert response.status_code == 504
        assert response.json()["request_id"] == pending["request_id"]
        assert response.json()["state"] == "interrupted"
        assert (
            await client.post(
                url,
                headers={"Authorization": "Bearer owner-secret"},
                json={"decision": "approve"},
            )
        ).status_code == 409
    await asyncio.sleep(0.65)
    assert not marker.exists()


async def test_streaming_response_keeps_its_lifecycle_after_headers():
    async def app(scope, receive, send):
        async def chunks():
            yield b"first"
            await asyncio.sleep(0.05)
            yield b"last"

        await StreamingResponse(chunks())(scope, receive, send)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=TimeoutMiddleware(app, 0.01)),
        base_url="http://test",
    ) as client:
        response = await client.get("/")
    assert response.status_code == 200
    assert response.content == b"firstlast"


async def test_application_timeouterror_is_not_a_request_deadline():
    async def app(scope, receive, send):
        raise TimeoutError("downstream failure")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=TimeoutMiddleware(app, 1)),
        base_url="http://test",
    ) as client:
        with pytest.raises(TimeoutError, match="downstream failure"):
            await client.get("/")


async def test_mcp_deadline_cancels_dispatched_execution(tmp_path):
    app, marker = timeout_app(tmp_path)
    slug = hashlib.sha256(b"agent-secret").hexdigest()[:16]
    async with (
        LifespanManager(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8080"
        ) as client,
    ):
        response = await client.post(
            f"/mcp/{slug}/",
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "demo__run", "arguments": {}},
            },
        )
        assert response.status_code == 504, response.text
        result = response.json()
        assert result["request_id"] and result["state"] == "interrupted"
        saved = await client.get(
            f"/control/requests/{result['request_id']}",
            headers={"Authorization": "Bearer agent-secret"},
        )
        assert saved.json()["state"] == "interrupted"
        await asyncio.sleep(0.65)
        assert not marker.exists()


@pytest.mark.parametrize("approval", [False, True])
async def test_recorded_outcome_is_preserved_when_response_preparation_times_out(
    tmp_path, approval
):
    app, _ = timeout_app(tmp_path, approval=approval)
    execution = app.state.execution_service

    async def finished(tool, argv, **kwargs):
        from clibroker.execution import execution_error

        return execution_error("").model_copy(
            update={"ok": True, "exit_code": 0, "stdout": "already done"}
        )

    execution._execute = finished

    # Delay route completion after the execution pipeline has saved its outcome.
    original = execution.execute

    async def execute_then_wait(*args, **kwargs):
        result = await original(*args, **kwargs)
        await asyncio.sleep(0.5)
        return result

    execution.execute = execute_then_wait
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/execute",
            headers={"Authorization": "Bearer agent-secret"},
            json={"tool": "demo", "argv": ["run"]},
        )
        assert response.status_code == 504
        result = response.json()
        if approval:
            assert result["state"] == "pending"
            assert result["ok"] is False
            assert result["approval_url"]
        else:
            assert result["state"] == "succeeded"
            assert result["ok"] is True
            assert result["stdout"] == "already done"
        saved = await client.get(
            f"/control/requests/{result['request_id']}",
            headers={"Authorization": "Bearer agent-secret"},
        )
        assert saved.json()["state"] == result["state"]
