"""Wire-level regression coverage for typed execution and native artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from jsonschema import validate

from clibroker.app import create_app
from clibroker.config import Config
from clibroker.file_sharing import FileShareError

VERSION = "2026-07-28"
TOKEN = "artifact-test-token"
OTHER_TOKEN = "unrelated-token"
SLUG = hashlib.sha256(TOKEN.encode()).hexdigest()[:16]
OTHER_SLUG = hashlib.sha256(OTHER_TOKEN.encode()).hexdigest()[:16]
PDF = b"%PDF-test\x00\xff"
FILENAME = "résumé #100%.pdf"
SCRIPT = (
    "import json, pathlib, sys; "
    "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1]); "
    f"(out / {FILENAME!r}).write_bytes({PDF!r}); "
    "(out / 'nested').mkdir(); "
    "(out / 'nested' / 'note.txt').write_text('hello'); "
    "print(json.dumps({'label': sys.argv[-1]}))"
)


def make_artifact_config(tmp_path, *, script=SCRIPT, recursive=True, timeout_s=5):
    root = tmp_path / "artifacts"
    root.mkdir(exist_ok=True)
    return Config.model_validate(
        {
            "server": {
                "auth": {
                    "tokens": [
                        {"name": "exporter", "value": TOKEN, "allow_rules": ["export"]},
                        {
                            "name": "other",
                            "value": OTHER_TOKEN,
                            "allow_rules": ["other"],
                        },
                    ]
                }
            },
            "tools": {
                "exporter": {
                    "executable": sys.executable,
                    "default_args": ["-c", script],
                    "timeout_s": timeout_s,
                    "file_sharing": {
                        "expose_working_dir": False,
                        "max_file_bytes": 128,
                        "shares": [
                            {"name": "output", "path": str(root), "access": "read"}
                        ],
                    },
                    "rules": [
                        {
                            "id": "export",
                            "command": ["export"],
                            "effect": "allow",
                            "inject_args": ["--out", "{artifact_dir}"],
                            "artifact_capture": {
                                "share": "output",
                                "recursive": recursive,
                            },
                            "positionals": [{"name": "label", "pattern": "^.{1,100}$"}],
                        }
                    ],
                },
                "other": {
                    "executable": sys.executable,
                    "rules": [{"id": "other", "command": ["other"], "effect": "allow"}],
                },
            },
        }
    )


@asynccontextmanager
async def running(config):
    app = create_app(config)
    async with LifespanManager(app) as manager:
        async with AsyncClient(
            transport=ASGITransport(app=manager.app),
            base_url="http://localhost:8000",
        ) as client:
            yield app, client


async def rpc(
    client,
    method,
    params=None,
    *,
    version=VERSION,
    token=TOKEN,
    slug=SLUG,
    header_overrides=None,
    meta_overrides=None,
):
    params = dict(params or {})
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if version == VERSION or version == "2099-01-01":
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
            **(meta_overrides or {}),
        }
        headers.update({"MCP-Protocol-Version": version, "Mcp-Method": method})
        if method == "tools/call":
            headers["Mcp-Name"] = params["name"]
        elif method == "resources/read":
            headers["Mcp-Name"] = params["uri"]
    else:
        headers["MCP-Protocol-Version"] = version
    headers.update(header_overrides or {})
    return await client.post(
        f"/mcp/{slug}/",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )


async def export(client, *, label="example", version=VERSION):
    return await rpc(
        client,
        "tools/call",
        {
            "name": "exporter__export",
            "arguments": {"label": label},
        },
        version=version,
    )


@pytest.mark.parametrize("version", ["2025-06-18", "2025-11-25", VERSION])
async def test_typed_artifacts_roundtrip_and_rest_parity(tmp_path, version):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        if version != VERSION:
            response = await rpc(
                client,
                "initialize",
                {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
                version=version,
            )
            assert response.json()["result"]["protocolVersion"] == version

        tools = (await rpc(client, "tools/list", version=version)).json()["result"][
            "tools"
        ]
        tool = next(t for t in tools if t["name"] == "exporter__export")
        response = await export(client, label="{artifact_dir}", version=version)
        assert response.status_code == 200
        assert "mcp-session-id" not in response.headers
        result = response.json()["result"]
        data = result["structuredContent"]
        validate(data, tool["outputSchema"])
        assert result["isError"] is False
        assert json.loads(result["content"][0]["text"]) == data
        assert data["stdout"] == {"label": "{artifact_dir}"}
        assert data["matched_rule"] == "export"
        assert len(data["artifacts"]) == 2
        links = [c for c in result["content"] if c["type"] == "resource_link"]
        assert {a["uri"] for a in data["artifacts"]} == {c["uri"] for c in links}

        for artifact in data["artifacts"]:
            expected = PDF if artifact["name"] == FILENAME else b"hello"
            assert artifact["sha256"] == hashlib.sha256(expected).hexdigest()
            assert artifact["size"] == len(expected)
            assert TOKEN not in artifact["uri"]
            assert str(tmp_path) not in artifact["uri"]
            resource = await rpc(
                client, "resources/read", {"uri": artifact["uri"]}, version=version
            )
            content = resource.json()["result"]["contents"][0]
            assert content["uri"] == artifact["uri"]
            assert base64.b64decode(content["blob"]) == expected
            download = await client.get(
                artifact["download_url"], headers={"Authorization": f"Bearer {TOKEN}"}
            )
            assert download.content == expected

        rest = await client.post(
            "/execute",
            json={"tool": "exporter", "argv": ["export", "{artifact_dir}"]},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        for key in ("ok", "exit_code", "stdout", "stderr", "matched_rule", "timed_out"):
            assert rest.json()[key] == data[key]
        assert all("uri" not in a for a in rest.json()["artifacts"])


async def test_modern_discovery_private_catalogs_and_scopes(tmp_path):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        discovery = await rpc(client, "server/discover")
        assert discovery.status_code == 200
        result = discovery.json()["result"]
        assert VERSION in result["supportedVersions"]
        assert (
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "clibroker"
        )
        for method in ("tools/list", "resources/list", "resources/templates/list"):
            result = (await rpc(client, method)).json()["result"]
            assert result["cacheScope"] == "private"
            assert result["ttlMs"] == 0
        templates = (await rpc(client, "resources/templates/list")).json()["result"][
            "resourceTemplates"
        ]
        assert len(templates) == 1
        other = (
            await rpc(
                client, "resources/templates/list", slug=OTHER_SLUG, token=OTHER_TOKEN
            )
        ).json()["result"]
        assert other["resourceTemplates"] == []
        other_tools = (
            await rpc(client, "tools/list", slug=OTHER_SLUG, token=OTHER_TOKEN)
        ).json()["result"]["tools"]
        assert {tool["name"] for tool in other_tools} == {"other__other"}


@pytest.mark.parametrize(
    "header_overrides",
    [
        {"MCP-Protocol-Version": "2099-01-01"},
        {"Mcp-Method": "tools/list"},
        {"Mcp-Name": "other__other"},
    ],
)
async def test_modern_routing_mismatch_never_executes(tmp_path, header_overrides):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        response = await rpc(
            client,
            "tools/call",
            {
                "name": "exporter__export",
                "arguments": {"label": "example"},
            },
            header_overrides=header_overrides,
        )
        assert response.status_code == 400
        assert "error" in response.json()
        assert list((tmp_path / "artifacts").iterdir()) == []


async def test_unsupported_protocol_reports_supported_versions(tmp_path):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        response = await rpc(client, "tools/list", version="2099-01-01")
        error = response.json()["error"]
        assert VERSION in error["data"]["supported"]


@pytest.mark.parametrize(
    "token,slug",
    [(None, SLUG), ("wrong", SLUG), (OTHER_TOKEN, SLUG), (TOKEN, OTHER_SLUG)],
)
async def test_resource_requires_bearer_and_endpoint_authorization(
    tmp_path, token, slug
):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        result = (await export(client)).json()["result"]
        uri = result["structuredContent"]["artifacts"][0]["uri"]
        response = await rpc(
            client, "resources/read", {"uri": uri}, token=token, slug=slug
        )
        assert "error" in response.json()
        assert "blob" not in response.text


@pytest.mark.parametrize(
    "path",
    [
        "../secret.txt",
        "%2e%2e/secret.txt",
        "%252e%252e/secret.txt",
        "%2Fetc%2Fpasswd",
        "escape.txt",
        "large.txt",
        "missing.txt",
        ".",
    ],
)
async def test_resource_read_rejects_unsafe_or_unavailable_files(tmp_path, path):
    config = make_artifact_config(tmp_path)
    (tmp_path / "secret.txt").write_text("secret outside share")
    (tmp_path / "artifacts" / "escape.txt").symlink_to(tmp_path / "secret.txt")
    (tmp_path / "artifacts" / "large.txt").write_bytes(b"x" * 129)
    async with running(config) as (_, client):
        response = await rpc(
            client,
            "resources/read",
            {"uri": f"clibroker://artifacts/exporter/output/{path}"},
        )
        assert "error" in response.json()
        assert "secret outside share" not in response.text
        assert "blob" not in response.text


@pytest.mark.parametrize(
    "script,timeout_s,exit_code,timed_out",
    [
        ("import sys; print('failed', file=sys.stderr); sys.exit(7)", 5, 7, False),
        ("import time; time.sleep(10)", 0.05, None, True),
    ],
)
async def test_command_failures_are_typed_native_errors(
    tmp_path, script, timeout_s, exit_code, timed_out
):
    async with running(
        make_artifact_config(tmp_path, script=script, timeout_s=timeout_s)
    ) as (_, client):
        result = (await export(client)).json()["result"]
        assert result["isError"] is True
        data = result["structuredContent"]
        assert data["ok"] is False
        assert data["timed_out"] is timed_out
        if exit_code is not None:
            assert data["exit_code"] == exit_code
        assert data["matched_rule"] == "export"


async def test_policy_failure_is_typed_and_does_not_run(tmp_path):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        result = (await export(client, label="x" * 101)).json()["result"]
        assert result["isError"] is True
        data = result["structuredContent"]
        assert data["exit_code"] == -1
        assert data["matched_rule"] == "export"
        assert "Validation failed" in data["stderr"]
        assert list((tmp_path / "artifacts").iterdir()) == []


async def test_artifact_failures_surface_and_never_report_success(
    tmp_path, monkeypatch
):
    async with running(make_artifact_config(tmp_path)) as (app, client):

        def fail(*args, **kwargs):
            raise FileShareError("capture unavailable")

        monkeypatch.setattr(app.state.file_share_service, "artifact_metadata", fail)
        result = (await export(client)).json()["result"]
        assert result["isError"] is True
        assert result["structuredContent"]["exit_code"] == 0
        assert "Failed to collect artifacts" in result["structuredContent"]["stderr"]


async def test_spawn_failure_does_not_leak_host_paths(tmp_path):
    config = make_artifact_config(tmp_path)
    config.tools["exporter"].executable = str(tmp_path / "missing-secret-executable")
    async with running(config) as (_, client):
        result = (await export(client)).json()["result"]
        assert result["isError"] is True
        assert result["structuredContent"]["stderr"] == "Internal server error"
        assert str(tmp_path) not in json.dumps(result)


async def test_nonrecursive_capture_returns_only_top_level_files(tmp_path):
    async with running(make_artifact_config(tmp_path, recursive=False)) as (_, client):
        result = (await export(client)).json()["result"]
        assert [a["name"] for a in result["structuredContent"]["artifacts"]] == [
            FILENAME
        ]


@pytest.mark.parametrize(
    "argv,expected",
    [
        (["export", "example"], "not authorized"),
        (["blocked", "child"], "Denied by rule"),
        ([], "No matching policy rule"),
    ],
)
async def test_raw_argv_rechecks_matched_rule_and_deny_precedence(
    tmp_path, argv, expected
):
    raw = make_artifact_config(tmp_path).model_dump()
    raw["server"]["auth"]["tokens"][0]["allow_rules"] = ["all"]
    raw["tools"]["exporter"]["rules"].extend(
        [
            {"id": "all", "command": ["*"], "effect": "allow", "allow_any_args": True},
            {"id": "blocked", "command": ["blocked"], "effect": "deny"},
        ]
    )
    async with running(Config.model_validate(raw)) as (_, client):
        result = (
            await rpc(
                client,
                "tools/call",
                {
                    "name": "exporter__all",
                    "arguments": {"args": argv},
                },
            )
        ).json()["result"]
        assert result["isError"] is True
        assert expected in result["structuredContent"]["stderr"]
        assert list((tmp_path / "artifacts").iterdir()) == []
        if argv:
            rest = await client.post(
                "/execute",
                json={"tool": "exporter", "argv": argv},
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            if argv[0] == "export":
                assert rest.status_code == 403
            else:
                assert rest.json()["ok"] is False


async def test_artifact_preparation_failure_does_not_execute(tmp_path):
    raw = make_artifact_config(tmp_path).model_dump()
    (tmp_path / "artifacts" / "blocked").write_text("not a directory")
    raw["tools"]["exporter"]["rules"][0]["artifact_capture"]["path_template"] = (
        "blocked/{execution_id}"
    )
    raw["tools"]["exporter"]["default_args"] = ["-c", "print('COMMAND RAN')"]
    async with running(Config.model_validate(raw)) as (_, client):
        result = (await export(client)).json()["result"]
        assert result["isError"] is True
        assert result["structuredContent"]["exit_code"] == -1
        assert result["structuredContent"]["stdout"] == ""
        assert (
            "Failed to prepare artifact directory"
            in result["structuredContent"]["stderr"]
        )


async def test_modern_missing_capabilities_is_rejected(tmp_path):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        response = await client.post(
            f"/mcp/{SLUG}/",
            headers={
                "Accept": "application/json",
                "MCP-Protocol-Version": VERSION,
                "Mcp-Method": "tools/list",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": VERSION,
                    }
                },
            },
        )
        assert "error" in response.json()


async def test_resource_read_caps_a_file_that_grows_after_stat(tmp_path, monkeypatch):
    config = make_artifact_config(tmp_path)
    path = tmp_path / "artifacts" / "growing.bin"
    path.write_bytes(b"small")
    original_open = Path.open

    def grow_before_read(self, mode="r", *args, **kwargs):
        if self == path and mode == "rb":
            with original_open(self, "ab") as stream:
                stream.write(b"x" * 256)
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", grow_before_read)
    async with running(config) as (_, client):
        response = await rpc(
            client,
            "resources/read",
            {
                "uri": "clibroker://artifacts/exporter/output/growing.bin",
            },
        )
        assert "error" in response.json()
        assert "max_file_bytes" in response.text
