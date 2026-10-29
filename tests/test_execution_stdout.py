"""Command output must survive typed REST and MCP response serialization."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from clibroker.app import create_app
from clibroker.config import Config

TOKEN = "stdout-test-token"
SLUG = hashlib.sha256(TOKEN.encode()).hexdigest()[:16]
VERSION = "2026-07-28"


@pytest.mark.parametrize("transport", ["rest", "mcp"])
@pytest.mark.parametrize(
    "output,parsed,exit_code",
    [
        pytest.param(
            '{"items": [1, null, true], "name": "résumé"}\n', True, 0, id="object"
        ),
        pytest.param('"\\ud83d\\ude00"\n', True, 0, id="surrogate-pair"),
        pytest.param("42\n", True, 0, id="scalar"),
        pytest.param("plain output\n", False, 0, id="text"),
        pytest.param("NaN\n", False, 0, id="nan"),
        pytest.param("Infinity\n", False, 0, id="infinity"),
        pytest.param("-Infinity\n", False, 0, id="negative-infinity"),
        pytest.param('{"number": NaN}\n', False, 0, id="nested-nan"),
        pytest.param("1e999\n", False, 0, id="float-overflow"),
        pytest.param('"\\ud800"\n', False, 0, id="unpaired-surrogate"),
        pytest.param('{"\\udfff": 1}\n', False, 0, id="surrogate-key"),
        pytest.param("[" * 255 + "0" + "]" * 255 + "\n", False, 0, id="deep-json"),
        pytest.param("[" * 1200 + "0" + "]" * 1200, False, 0, id="excessive-depth"),
        pytest.param('"\\ud800"\n', False, 7, id="failed-command"),
    ],
)
async def test_stdout_preserves_execution_result(
    tmp_path, transport, output, parsed, exit_code
):
    root = tmp_path / "output"
    root.mkdir()
    script = (
        "import pathlib, sys; "
        "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1]); "
        "(out / 'artifact.txt').write_text('captured'); "
        f"sys.stdout.write({output!r}); sys.exit({exit_code})"
    )
    config = Config.model_validate(
        {
            "server": {
                "auth": {
                    "tokens": [
                        {"name": "reader", "value": TOKEN, "allow_rules": ["run"]}
                    ]
                }
            },
            "tools": {
                "emitter": {
                    "executable": sys.executable,
                    "default_args": ["-c", script],
                    "file_sharing": {
                        "expose_working_dir": False,
                        "shares": [{"name": "output", "path": str(root)}],
                    },
                    "rules": [
                        {
                            "id": "run",
                            "command": ["run"],
                            "inject_args": ["--out", "{artifact_dir}"],
                            "artifact_capture": {"share": "output"},
                        }
                    ],
                }
            },
        }
    )
    async with (
        LifespanManager(create_app(config)) as manager,
        AsyncClient(
            transport=ASGITransport(app=manager.app), base_url="http://localhost:8000"
        ) as client,
    ):
        headers = {"Authorization": f"Bearer {TOKEN}"}
        if transport == "rest":
            response = await client.post(
                "/execute",
                headers=headers,
                json={"tool": "emitter", "argv": ["run"]},
            )
            result = response.json()
        else:
            headers.update(
                {
                    "Accept": "application/json",
                    "MCP-Protocol-Version": VERSION,
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": "emitter__run",
                }
            )
            response = await client.post(
                f"/mcp/{SLUG}/",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "emitter__run",
                        "arguments": {},
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": VERSION,
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                    },
                },
            )
            mcp_result = response.json()["result"]
            assert mcp_result["isError"] is (exit_code != 0)
            result = mcp_result["structuredContent"]
            assert json.loads(mcp_result["content"][0]["text"]) == result
            assert (
                len([c for c in mcp_result["content"] if c["type"] == "resource_link"])
                == 1
            )

    assert response.status_code == 200
    assert result["stdout"] == (json.loads(output) if parsed else output)
    assert result["ok"] is (exit_code == 0)
    assert result["exit_code"] == exit_code
    assert result["stderr"] == ""
    assert result["matched_rule"] == "run"
    assert result["timed_out"] is False
    assert len(result["artifacts"]) == 1
    assert result["artifacts"][0]["name"] == "artifact.txt"
