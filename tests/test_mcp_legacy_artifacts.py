"""Artifact results remain usable by clients predating resource links."""

from __future__ import annotations

import json

import pytest

from tests.test_mcp_artifacts import TOKEN, export, make_artifact_config, rpc, running


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26"])
async def test_legacy_artifact_calls_use_supported_content(tmp_path, version):
    async with running(make_artifact_config(tmp_path)) as (_, client):
        initialized = await rpc(
            client,
            "initialize",
            {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "legacy-client", "version": "1"},
            },
            version=version,
        )
        assert initialized.json()["result"]["protocolVersion"] == version

        response = await export(client, version=version)
        result = response.json()["result"]
        assert result["isError"] is False
        # Pre-June clients cannot parse resource_link in their content union.
        assert [content["type"] for content in result["content"]] == ["text"]
        data = json.loads(result["content"][0]["text"])
        assert data == result["structuredContent"]
        assert len(data["artifacts"]) == 2
        for artifact in data["artifacts"]:
            download = await client.get(
                artifact["download_url"],
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            assert download.status_code == 200
            assert len(download.content) == artifact["size"]


async def test_context_injection_preserves_a_same_named_cli_parameter(tmp_path):
    config = make_artifact_config(tmp_path)
    config.tools["exporter"].rules[0].positionals[0].name = "mcp_context"
    async with running(config) as (_, client):
        tools = (await rpc(client, "tools/list")).json()["result"]["tools"]
        tool = next(tool for tool in tools if tool["name"] == "exporter__export")
        assert set(tool["inputSchema"]["properties"]) == {"mcp_context"}
        result = (
            await rpc(
                client,
                "tools/call",
                {
                    "name": "exporter__export",
                    "arguments": {"mcp_context": "example"},
                },
            )
        ).json()["result"]
        assert result["structuredContent"]["stdout"] == {"label": "example"}
        assert result["isError"] is False
        assert any(content["type"] == "resource_link" for content in result["content"])
