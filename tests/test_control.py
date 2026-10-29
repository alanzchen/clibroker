"""The owner UI gates the same operations as REST/MCP, including retries."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time

import httpx
import pytest
from asgi_lifespan import LifespanManager
from pydantic import ValidationError

from clibroker.app import create_app
from clibroker.config import Config
from tests.conftest import make_config


def config_for(tmp_path):
    data = make_config().model_dump()
    data["server"]["control"] = {
        "database_path": str(tmp_path / "state.sqlite3"),
        "approval_ttl_s": 3600,
    }
    data["server"]["auth"]["tokens"].append(
        {"name": "owner", "role": "owner", "value": "owner-secret", "allow_rules": []}
    )
    data["tools"]["himalaya"]["title"] = "Work mail"
    data["tools"]["himalaya"]["rules"][2]["title"] = "Move a message"
    data["tools"]["himalaya"]["rules"][2]["require_approval"] = True
    (tmp_path / "shared").mkdir(exist_ok=True)
    data["tools"]["himalaya"]["file_sharing"] = {
        "expose_working_dir": False,
        "shares": [
            {
                "name": "attachments",
                "path": str(tmp_path / "shared"),
                "access": "read_write",
            }
        ],
    }
    return Config.model_validate(data)


def headers(who="operator"):
    value = "owner-secret" if who == "owner" else f"test-{who}-token"
    return {"Authorization": f"Bearer {value}"}


def client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8080"
    )


async def submit(c, who="operator", argv=None):
    return await c.post(
        "/execute",
        headers=headers(who),
        json={"tool": "himalaya", "argv": argv or ["message", "move", "42", "Archive"]},
    )


async def decide(c, request_id, choice="approve", who="owner"):
    return await c.post(
        f"/control/requests/{request_id}/decision",
        headers=headers(who),
        json={"decision": choice},
    )


async def test_approval_persists_and_executes_once(tmp_path, monkeypatch):
    config = config_for(tmp_path)
    app = create_app(config)
    async with client(app) as c:
        response = await submit(c)
        assert response.status_code == 200
        pending = response.json()
        assert pending["state"] == "pending" and pending["request_id"]
        assert "owner-secret" not in response.text
        assert "owner-secret" not in pending["approval_url"]
        request_id = pending["request_id"]
    # New app simulates restart before the decision.
    app = create_app(config)
    import clibroker.execution as execution_module

    original = execution_module.run_command
    calls = 0

    async def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.02)
        return await original(*args, **kwargs)

    monkeypatch.setattr(execution_module, "run_command", counted)
    async with client(app) as c:
        saved = (
            await c.get(f"/control/requests/{request_id}", headers=headers())
        ).json()
        assert saved["state"] == "pending"
        first, second = await asyncio.gather(
            decide(c, request_id), decide(c, request_id)
        )
        assert sorted([first.status_code, second.status_code]) == [200, 409]
        assert calls == 1
        final = (
            await c.get(f"/control/requests/{request_id}", headers=headers())
        ).json()
        assert final["state"] == "succeeded"
        assert "message move 42 Archive" in final["result"]["stdout"]
        assert (await decide(c, request_id)).status_code == 409
    async with client(create_app(config)) as c:
        history = (await c.get("/control", headers=headers())).json()
        assert history["activity"][0]["state"] == "succeeded"
        assert history["requests"] == []
    assert os.stat(tmp_path / "state.sqlite3").st_mode & 0o777 == 0o600


async def test_owner_auth_and_caller_isolation(tmp_path):
    app = create_app(config_for(tmp_path))
    async with client(app) as c:
        assert (await c.get("/control")).status_code == 401
        pending = (await submit(c)).json()
        request_id = pending["request_id"]
        assert (await decide(c, request_id, who="operator")).status_code == 403
        assert (
            await c.get(f"/control/requests/{request_id}", headers=headers("reader"))
        ).status_code == 404
        assert (
            await c.patch(
                "/control/agents/operator", headers=headers(), json={"paused": True}
            )
        ).status_code == 403
        assert (
            await c.put(
                "/control/agents/operator/rules/move_message",
                headers=headers(),
                json={"decision": "allow"},
            )
        ).status_code == 403
        reader = (await c.get("/control", headers=headers("reader"))).json()
        assert reader["agents"] == reader["activity"] == reader["requests"] == []
        owner = (await c.get("/control", headers=headers("owner"))).json()
        assert len(owner["agents"]) == 2 and len(owner["requests"]) == 1
        assert "owner-secret" not in json.dumps(owner)


@pytest.mark.parametrize(
    "argv", [["message", "delete", "42"], ["unknown"], ["message", "read", "invalid"]]
)
async def test_policy_denials_never_become_approvable(tmp_path, argv):
    app = create_app(config_for(tmp_path))
    async with client(app) as c:
        result = (await submit(c, argv=argv)).json()
        assert result["state"] == "blocked"
        assert (await decide(c, result["request_id"])).status_code == 409
        assert (await c.get("/control", headers=headers("owner"))).json()[
            "requests"
        ] == []


async def test_rbac_cannot_be_elevated(tmp_path):
    app = create_app(config_for(tmp_path))
    async with client(app) as c:
        assert (await submit(c, who="reader")).status_code == 403
        forbidden = await c.put(
            "/control/agents/reader/rules/move_message",
            headers=headers("owner"),
            json={"decision": "allow"},
        )
        assert forbidden.status_code == 404
        denied = await c.put(
            "/control/agents/operator/rules/deny_delete",
            headers=headers("owner"),
            json={"decision": "allow"},
        )
        assert denied.status_code == 404
        ceiling = await c.put(
            "/control/agents/operator/rules/move_message",
            headers=headers("owner"),
            json={"decision": "allow"},
        )
        assert ceiling.status_code == 409


async def test_reject_expire_and_change_configuration(tmp_path):
    cfg = config_for(tmp_path)
    app = create_app(cfg)
    async with client(app) as c:
        rejected = (await submit(c)).json()["request_id"]
        assert (await decide(c, rejected, "reject")).json()["state"] == "rejected"
        expired = (await submit(c)).json()["request_id"]
        with app.state.control.db() as db:
            db.execute(
                "UPDATE requests SET expires_at=? WHERE id=?",
                (time.time() - 1, expired),
            )
        assert (await decide(c, expired)).status_code == 409
        assert (await c.get(f"/control/requests/{expired}", headers=headers())).json()[
            "state"
        ] == "expired"
        changed = (await submit(c)).json()["request_id"]
    cfg.tools["himalaya"].default_args.append("changed")
    async with client(create_app(cfg)) as c:
        result = (await decide(c, changed)).json()
        assert result["state"] == "blocked"
        assert "configuration changed" in result["result"]["stderr"]


async def test_pause_and_permissions_persist(tmp_path):
    cfg = config_for(tmp_path)
    app = create_app(cfg)
    async with client(app) as c:
        await c.put(
            "/control/agents/operator/rules/read_message",
            headers=headers("owner"),
            json={"decision": "ask"},
        )
        assert (await submit(c, argv=["message", "read", "42"])).json()[
            "state"
        ] == "pending"
        await c.put(
            "/control/agents/operator/rules/read_message",
            headers=headers("owner"),
            json={"decision": "block"},
        )
        assert (await submit(c, argv=["message", "read", "42"])).json()[
            "state"
        ] == "blocked"
        await c.patch(
            "/control/agents/operator", headers=headers("owner"), json={"paused": True}
        )
        assert (await submit(c)).json()["state"] == "blocked"
        assert (
            await c.get("/files/himalaya/attachments", headers=headers())
        ).status_code == 403
    async with client(create_app(cfg)) as c:
        agents = (await c.get("/control", headers=headers("owner"))).json()["agents"]
        assert next(a for a in agents if a["name"] == "operator")["paused"]
        await c.patch(
            "/control/agents/operator", headers=headers("owner"), json={"paused": False}
        )
        assert (await submit(c, argv=["message", "read", "42"])).json()[
            "state"
        ] == "blocked"


async def test_paused_mcp_files_and_artifacts(tmp_path):
    cfg = config_for(tmp_path)
    (tmp_path / "shared" / "receipt.txt").write_text("receipt")
    app = create_app(cfg)
    slug = hashlib.sha256(b"test-operator-token").hexdigest()[:16]
    async with LifespanManager(app), client(app) as c:
        await c.patch(
            "/control/agents/operator", headers=headers("owner"), json={"paused": True}
        )

        async def rpc(method, params):
            response = await c.post(
                f"/mcp/{slug}/",
                headers={**headers(), "Accept": "application/json, text/event-stream"},
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            )
            return response.json()

        file_result = await rpc(
            "tools/call",
            {
                "name": "himalaya__files_read",
                "arguments": {"share": "attachments", "path": "receipt.txt"},
            },
        )
        assert "paused" in json.dumps(file_result)
        assert '"content": "receipt"' not in json.dumps(file_result)
        resource_result = await rpc(
            "resources/read",
            {"uri": "clibroker://artifacts/himalaya/attachments/receipt.txt"},
        )
        assert "paused" in json.dumps(resource_result)
        command = await rpc(
            "tools/call",
            {
                "name": "himalaya__move_message",
                "arguments": {"id": "42", "destination": "Archive"},
            },
        )
        assert "paused" in json.dumps(command)


async def test_mcp_pending_and_status_poll(tmp_path):
    app = create_app(config_for(tmp_path))
    slug = hashlib.sha256(b"test-operator-token").hexdigest()[:16]
    async with LifespanManager(app), client(app) as c:

        async def rpc(name, args):
            response = await c.post(
                f"/mcp/{slug}/",
                headers={**headers(), "Accept": "application/json, text/event-stream"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                },
            )
            return response.json()["result"]

        pending = await rpc(
            "himalaya__move_message", {"id": "42", "destination": "Archive"}
        )
        assert pending.get("isError") is False
        request_id = pending["structuredContent"]["request_id"]
        await decide(c, request_id)
        final = await rpc("clibroker_request_status", {"request_id": request_id})
        assert "succeeded" in final["content"][0]["text"]


def test_control_configuration_is_explicit(tmp_path):
    data = config_for(tmp_path).model_dump()
    data["server"]["auth"]["tokens"][1]["name"] = "reader"
    with pytest.raises(ValidationError, match="unique token names"):
        Config.model_validate(data)
    data = config_for(tmp_path).model_dump()
    data["server"]["auth"]["tokens"][2]["value"] = "test-reader-token"
    with pytest.raises(ValidationError, match="distinct nonempty"):
        Config.model_validate(data)
    data = config_for(tmp_path).model_dump()
    data["server"]["control"] = None
    with pytest.raises(ValidationError, match="require_approval requires"):
        Config.model_validate(data)


async def test_legacy_control_disabled(config):
    async with client(create_app(config)) as c:
        view = (await c.get("/control", headers=headers())).json()
        assert view["enabled"] is False
        assert (
            await c.patch(
                "/control/agents/reader", headers=headers(), json={"paused": True}
            )
        ).status_code == 403


def test_database_is_never_exported_by_file_shares(tmp_path):
    data = config_for(tmp_path).model_dump()
    data["tools"]["himalaya"]["file_sharing"]["shares"][0]["path"] = str(tmp_path)
    with pytest.raises(ValidationError, match="outside every exposed"):
        Config.model_validate(data)
    data = config_for(tmp_path).model_dump()
    data["tools"]["himalaya"]["working_dir"] = str(tmp_path)
    data["tools"]["himalaya"]["file_sharing"]["expose_working_dir"] = True
    with pytest.raises(ValidationError, match="outside every exposed"):
        Config.model_validate(data)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    data = config_for(tmp_path).model_dump()
    data["tools"]["himalaya"]["file_sharing"]["shares"][0]["path"] = str(alias)
    with pytest.raises(ValidationError, match="outside every exposed"):
        Config.model_validate(data)


def test_direct_mcp_factory_has_controls(tmp_path):
    from clibroker.mcp_server import create_mcp_server
    from clibroker.policy import PolicyEngine

    cfg = config_for(tmp_path)
    mcp = create_mcp_server(
        cfg, PolicyEngine(cfg), allowed_rules={"move_message"}, client_name="operator"
    )
    assert "clibroker_request_status" in mcp._tool_manager._tools


async def test_cancellation_is_not_retryable(tmp_path, monkeypatch):
    cfg = config_for(tmp_path)
    app = create_app(cfg)
    import clibroker.execution as execution_module

    started = asyncio.Event()

    async def blocked(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(execution_module, "run_command", blocked)
    async with client(app) as c:
        pending = (await submit(c)).json()["request_id"]
        task = asyncio.create_task(decide(c, pending))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        row = (await c.get(f"/control/requests/{pending}", headers=headers())).json()
        assert row["state"] == "interrupted"
        assert (await decide(c, pending)).status_code == 409


async def test_activity_has_no_outputs_and_requests_have_actor(tmp_path):
    app = create_app(config_for(tmp_path))
    async with client(app) as c:
        request_id = (await submit(c)).json()["request_id"]
        final = (await decide(c, request_id)).json()
        assert final["decided_by"] == "owner" and final["decided_at"]
        view = await c.get("/control", headers=headers("owner"))
        assert view.headers["cache-control"] == "no-store"
        assert view.json()["activity"][0]["result"] is None
        assert (await c.get("/control")).headers["cache-control"] == "no-store"


async def test_direct_factory_executes_approval_pipeline(tmp_path):
    from clibroker.mcp_server import create_mcp_server
    from clibroker.policy import PolicyEngine

    cfg = config_for(tmp_path)
    mcp = create_mcp_server(cfg, PolicyEngine(cfg), client_name="reader")
    app = mcp.streamable_http_app(
        streamable_http_path="/", stateless_http=True, json_response=True
    )
    async with mcp.session_manager.run(), client(app) as c:
        # Even a direct caller omitting the registration allowlist cannot bypass
        # the configured reader's RBAC at execution time.
        denied = await c.post(
            "/",
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "himalaya__move_message",
                    "arguments": {"id": "42", "destination": "Archive"},
                },
            },
        )
        assert denied.json()["result"]["isError"] is True
    mcp = create_mcp_server(cfg, PolicyEngine(cfg), client_name="operator")
    app = mcp.streamable_http_app(
        streamable_http_path="/", stateless_http=True, json_response=True
    )
    async with mcp.session_manager.run(), client(app) as c:
        response = await c.post(
            "/",
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "himalaya__move_message",
                    "arguments": {"id": "42", "destination": "Archive"},
                },
            },
        )
        assert response.json()["result"]["structuredContent"]["state"] == "pending"


async def test_owner_mcp_slug_does_not_grant_cross_agent_history(tmp_path):
    cfg = config_for(tmp_path)
    app = create_app(cfg)
    slug = hashlib.sha256(b"owner-secret").hexdigest()[:16]
    async with LifespanManager(app), client(app) as c:
        request_id = (await submit(c)).json()["request_id"]
        response = await c.post(
            f"/mcp/{slug}/",
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "clibroker_request_status",
                    "arguments": {"request_id": request_id},
                },
            },
        )
        assert "Request not found" in response.text
