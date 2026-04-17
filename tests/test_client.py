"""Tests for the broker client package and token-scoped discovery endpoint."""

from __future__ import annotations

import hashlib
import json
import textwrap

import pytest
import yaml
from httpx import ASGITransport, AsyncClient

from clibroker.app import create_app
from clibroker.config import Config
from clibroker.client import HttpBackend, load_client_config
from clibroker.client.__main__ import main as client_main
from clibroker.client.config import (
    BrokerClientConfig,
    HTTPBackendConfig,
    resolve_client_config_path,
)
from tests.conftest import make_config

READER_TOKEN = "test-reader-token"
OPERATOR_TOKEN = "test-operator-token"
READER_SLUG = hashlib.sha256(READER_TOKEN.encode()).hexdigest()[:16]


@pytest.fixture
def anyio_backend():
    return "asyncio"


class TestClientConfigEndpoint:
    """Token-scoped server discovery document for the client."""

    @pytest.fixture
    async def client(self):
        app = create_app(make_config())
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_client_config_requires_auth(self, client: AsyncClient) -> None:
        resp = await client.get("/client-config")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_reader_gets_only_authorized_rules(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/client-config",
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["client_name"] == "reader"
        assert body["execute_url"] == "/execute"
        assert body["token_info_url"] == "/token-info"
        assert body["mcp_url"] == f"/mcp/{READER_SLUG}/"
        assert body["sse_url"] == f"/sse/{READER_SLUG}/"

        assert len(body["tools"]) == 1
        assert body["tools"][0]["name"] == "himalaya"

        rule_ids = {rule["id"] for rule in body["tools"][0]["rules"]}
        assert rule_ids == {"list_messages", "read_message"}
        assert "move_message" not in rule_ids
        assert "deny_delete" not in rule_ids

        list_rule = next(
            rule for rule in body["tools"][0]["rules"] if rule["id"] == "list_messages"
        )
        assert list_rule["standalone_flags"] == ["--unread"]

        read_rule = next(
            rule for rule in body["tools"][0]["rules"] if rule["id"] == "read_message"
        )
        assert "inject_args" not in read_rule

    @pytest.mark.asyncio
    async def test_operator_gets_move_rule(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/client-config",
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )

        assert resp.status_code == 200
        body = resp.json()
        rule_ids = {rule["id"] for rule in body["tools"][0]["rules"]}
        assert "move_message" in rule_ids

    @pytest.mark.asyncio
    async def test_client_config_exposes_variadic_positionals(self) -> None:
        raw = yaml.safe_load(
            """
            server:
              bind: "127.0.0.1:9999"
              auth:
                type: bearer
                tokens:
                  - name: reader
                    value: "test-reader-token"
                    allow_rules: ["search_messages"]
            tools:
              himalaya:
                executable: "/usr/bin/echo"
                default_args: []
                rules:
                  - id: search_messages
                    command: ["envelope", "list"]
                    effect: allow
                    positionals:
                      - name: query
                        pattern: "^[A-Za-z0-9_@.+:-]+$"
                        variadic: true
            """
        )
        app = create_app(Config.model_validate(raw))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/client-config",
                headers={"Authorization": f"Bearer {READER_TOKEN}"},
            )

        assert resp.status_code == 200
        rule = resp.json()["tools"][0]["rules"][0]
        assert rule["positionals"] == [
            {
                "name": "query",
                "pattern": "^[A-Za-z0-9_@.+:-]+$",
                "enum": None,
                "variadic": True,
            }
        ]

    @pytest.mark.asyncio
    async def test_client_config_exposes_argv_normalization(self) -> None:
        raw = yaml.safe_load(
            """
            server:
              bind: "127.0.0.1:9999"
              auth:
                type: bearer
                tokens:
                  - name: reader
                    value: "test-reader-token"
                    allow_rules: ["search_messages"]
            tools:
              obsidian:
                executable: "/usr/bin/echo"
                default_args: []
                argv_normalization:
                  patterns:
                    - id: vault
                      kind: key_value
                      key_pattern: "^vault$"
                      value_pattern: "^[A-Za-z0-9_. -]+$"
                      canonical_position: before_command
                      allow_positions: ["before_command", "after_command"]
                      multiple: false
                rules:
                  - id: search_messages
                    command: ["search"]
                    effect: allow
                    positionals:
                      - name: query
                        pattern: "^query=.+$"
            """
        )
        app = create_app(Config.model_validate(raw))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/client-config",
                headers={"Authorization": f"Bearer {READER_TOKEN}"},
            )

        assert resp.status_code == 200
        tool = resp.json()["tools"][0]
        assert tool["argv_normalization"] == {
            "patterns": [
                {
                    "id": "vault",
                    "kind": "key_value",
                    "key_pattern": "^vault$",
                    "value_pattern": "^[A-Za-z0-9_. -]+$",
                    "canonical_position": "before_command",
                    "allow_positions": ["before_command", "after_command"],
                    "multiple": False,
                }
            ]
        }


class TestClientLocalConfig:
    """Client-side YAML config parsing and env token resolution."""

    def test_load_client_config(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("BROKER_CLIENT_TOKEN", READER_TOKEN)
        path = tmp_path / "client.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                default_backend: local
                backends:
                  local:
                    type: http
                    base_url: http://127.0.0.1:8080/
                    token: env:BROKER_CLIENT_TOKEN
                    timeout_s: 12.5
                    verify_tls: false
                """
            )
        )

        config = load_client_config(path)
        backend = config.get_backend()

        assert config.default_backend == "local"
        assert backend.base_url == "http://127.0.0.1:8080"
        assert backend.resolve_token() == READER_TOKEN
        assert backend.verify_tls is False

    def test_default_backend_must_exist(self, tmp_path) -> None:
        path = tmp_path / "client.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                default_backend: missing
                backends:
                  local:
                    type: http
                    base_url: http://127.0.0.1:8080
                    token: literal-token
                """
            )
        )

        with pytest.raises(ValueError) as exc_info:
            load_client_config(path)
        assert "default_backend 'missing' does not exist" in str(exc_info.value)

    def test_get_backend_selects_named_backend(self, tmp_path) -> None:
        path = tmp_path / "client.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                default_backend: local
                backends:
                  local:
                    type: http
                    base_url: http://127.0.0.1:8080
                    token: literal-local-token
                  review:
                    type: http
                    base_url: http://127.0.0.1:8081
                    token: literal-review-token
                """
            )
        )

        config = load_client_config(path)

        assert config.get_backend("review").base_url == "http://127.0.0.1:8081"

    def test_get_backend_error_lists_available_backends(self, tmp_path) -> None:
        path = tmp_path / "client.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                default_backend: local
                backends:
                  local:
                    type: http
                    base_url: http://127.0.0.1:8080
                    token: literal-local-token
                  review:
                    type: http
                    base_url: http://127.0.0.1:8081
                    token: literal-review-token
                """
            )
        )

        config = load_client_config(path)

        with pytest.raises(KeyError) as exc_info:
            config.get_backend("missing")

        assert "Available backends: local, review" in str(exc_info.value)

    def test_literal_token_is_redacted_for_display(self) -> None:
        backend = HTTPBackendConfig(
            base_url="http://127.0.0.1:8080",
            token="super-secret",
        )
        assert backend.redacted_dict()["token"] == "<redacted>"

    def test_resolve_client_config_path_prefers_explicit_path(self, tmp_path) -> None:
        path = tmp_path / "client.yaml"
        path.write_text("default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n")

        resolved = resolve_client_config_path(path)

        assert resolved == path

    def test_resolve_client_config_path_uses_env_var(self, tmp_path, monkeypatch) -> None:
        path = tmp_path / "env-client.yaml"
        path.write_text("default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n")
        monkeypatch.setenv("CLIBROKER_CLIENT_CONFIG", str(path))

        resolved = resolve_client_config_path()

        assert resolved == path

    def test_resolve_client_config_path_prefers_openclaw_default(self, tmp_path, monkeypatch) -> None:
        home = tmp_path / "home"
        openclaw_dir = home / ".openclaw"
        openclaw_dir.mkdir(parents=True)
        path = openclaw_dir / "clibroker-client.yaml"
        path.write_text("default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("CLIBROKER_CLIENT_CONFIG", raising=False)
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

        resolved = resolve_client_config_path()

        assert resolved == path

    def test_resolve_client_config_path_falls_back_to_xdg(self, tmp_path, monkeypatch) -> None:
        xdg = tmp_path / "xdg"
        config_dir = xdg / "clibroker"
        config_dir.mkdir(parents=True)
        path = config_dir / "client.yaml"
        path.write_text("default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.delenv("CLIBROKER_CLIENT_CONFIG", raising=False)

        resolved = resolve_client_config_path()

        assert resolved == path

    def test_resolve_client_config_path_raises_when_missing(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
        monkeypatch.delenv("CLIBROKER_CLIENT_CONFIG", raising=False)

        with pytest.raises(FileNotFoundError) as exc_info:
            resolve_client_config_path()

        assert "No client config found" in str(exc_info.value)


class TestHttpBackend:
    """Direct client backend that talks to the broker server."""

    @pytest.fixture
    def app(self):
        return create_app(make_config())

    @pytest.mark.asyncio
    async def test_fetch_config(self, app) -> None:
        backend = HttpBackend(
            HTTPBackendConfig(
                base_url="http://test",
                token=READER_TOKEN,
            ),
            transport=ASGITransport(app=app),
        )

        remote = await backend.fetch_config()
        assert remote.client_name == "reader"
        assert remote.execute_url == "/execute"
        assert {rule.id for tool in remote.tools for rule in tool.rules} == {
            "list_messages",
            "read_message",
        }

    @pytest.mark.asyncio
    async def test_execute(self, app) -> None:
        backend = HttpBackend(
            HTTPBackendConfig(
                base_url="http://test",
                token=READER_TOKEN,
            ),
            transport=ASGITransport(app=app),
        )

        result = await backend.execute("himalaya", ["message", "list"])
        assert result.matched_rule == "list_messages"
        assert result.ok is True


class TestClientCLI:
    """CLI entrypoint behavior for the client package."""

    @staticmethod
    def _make_remote(client_name: str, tool_names: list[str]) -> dict[str, object]:
        return {
            "version": "0.1.0",
            "client_name": client_name,
            "execute_url": "/execute",
            "token_info_url": "/token-info",
            "mcp_url": f"/mcp/{READER_SLUG}/",
            "sse_url": f"/sse/{READER_SLUG}/",
            "tools": [
                {
                    "name": tool_name,
                    "rules": [],
                }
                for tool_name in tool_names
            ],
        }

    def test_config_show(self, tmp_path, capsys) -> None:
        path = tmp_path / "client.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                default_backend: local
                backends:
                  local:
                    type: http
                    base_url: http://127.0.0.1:8080
                    token: literal-token
                """
            )
        )

        exit_code = client_main(["--config", str(path), "config", "show"])
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["selected_backend"] == "local"
        assert payload["backend"]["token"] == "<redacted>"

    def test_config_list(self, tmp_path, capsys) -> None:
        path = tmp_path / "client.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                default_backend: local
                backends:
                  local:
                    type: http
                    base_url: http://127.0.0.1:8080
                    token: literal-token
                  review:
                    type: http
                    base_url: http://127.0.0.1:8081
                    token: env:REVIEW_TOKEN
                """
            )
        )

        exit_code = client_main(["--config", str(path), "config", "list"])
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["default_backend"] == "local"
        assert [item["name"] for item in payload["backends"]] == ["local", "review"]
        assert payload["backends"][0]["is_default"] is True
        assert payload["backends"][1]["config"]["token"] == "env:REVIEW_TOKEN"

    def test_tools_command_uses_default_config_path(self, tmp_path, monkeypatch, capsys) -> None:
        path = tmp_path / "client.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                default_backend: local
                backends:
                  local:
                    type: http
                    base_url: http://127.0.0.1:8080
                    token: literal-token
                """
            )
        )

        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(
                    {
                        "version": "0.1.0",
                        "client_name": "reader",
                        "execute_url": "/execute",
                        "token_info_url": "/token-info",
                        "mcp_url": f"/mcp/{READER_SLUG}/",
                        "sse_url": f"/sse/{READER_SLUG}/",
                        "tools": [],
                    }
                )

        monkeypatch.setenv("CLIBROKER_CLIENT_CONFIG", str(path))
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(),
        )

        exit_code = client_main(["tools"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Client: reader" in captured.out

    def test_tools_command_honors_backend_override(self, monkeypatch, capsys) -> None:
        remote = self._make_remote("reader", [])

        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(remote)

        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    },
                    "review": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8081",
                        "token": "literal-token",
                    },
                },
            }
        )

        observed_backend_name = None

        def fake_build_backend(config, backend_name=None):
            nonlocal observed_backend_name
            observed_backend_name = backend_name
            return FakeBackend()

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            fake_build_backend,
        )

        exit_code = client_main(["--config", "ignored.yaml", "--backend", "review", "tools"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Client: reader" in captured.out
        assert observed_backend_name == "review"

    def test_tools_command_aggregates_multiple_backends_as_json(
        self, monkeypatch, capsys
    ) -> None:
        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    },
                    "review": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8081",
                        "token": "literal-token",
                    },
                },
            }
        )

        remotes = {
            "local": self._make_remote("local-reader", ["himalaya", "calendar"]),
            "review": self._make_remote("review-reader", ["himalaya", "notes"]),
        }

        class FakeBackend:
            def __init__(self, backend_name: str) -> None:
                self.backend_name = backend_name

            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(remotes[self.backend_name])

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(backend_name or config.default_backend),
        )

        exit_code = client_main(["--config", "ignored.yaml", "tools", "--json"])
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["default_backend"] == "local"
        assert [item["name"] for item in payload["tool_index"]] == [
            "calendar",
            "himalaya",
            "notes",
        ]
        himalaya = next(item for item in payload["tool_index"] if item["name"] == "himalaya")
        assert himalaya["backends"] == ["local", "review"]
        assert himalaya["conflict"] is True

    def test_execute_command_auto_selects_unique_backend(self, monkeypatch, capsys) -> None:
        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    },
                    "review": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8081",
                        "token": "literal-token",
                    },
                },
            }
        )

        remotes = {
            "local": self._make_remote("local-reader", ["himalaya"]),
            "review": self._make_remote("review-reader", ["calendar"]),
        }
        executed_backend = None

        class FakeBackend:
            def __init__(self, backend_name: str) -> None:
                self.backend_name = backend_name

            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(remotes[self.backend_name])

            async def execute(self, tool: str, argv: list[str]):
                nonlocal executed_backend
                from clibroker.models import ExecuteResponse

                executed_backend = self.backend_name
                return ExecuteResponse(
                    ok=True,
                    exit_code=0,
                    stdout={"tool": tool, "argv": argv, "backend": self.backend_name},
                    stderr="",
                    duration_ms=1.23,
                    matched_rule="calendar_list",
                    timed_out=False,
                )

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(backend_name or config.default_backend),
        )

        exit_code = client_main(
            ["--config", "ignored.yaml", "execute", "calendar", "--", "list"]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["stdout"]["backend"] == "review"
        assert executed_backend == "review"

    def test_execute_command_requires_backend_for_conflicting_tool(
        self, monkeypatch, capsys
    ) -> None:
        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    },
                    "review": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8081",
                        "token": "literal-token",
                    },
                },
            }
        )

        remotes = {
            "local": self._make_remote("local-reader", ["himalaya"]),
            "review": self._make_remote("review-reader", ["himalaya"]),
        }

        class FakeBackend:
            def __init__(self, backend_name: str) -> None:
                self.backend_name = backend_name

            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(remotes[self.backend_name])

            async def execute(self, tool: str, argv: list[str]):  # pragma: no cover - should not execute
                raise AssertionError("execute should not be called when tool is ambiguous")

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(backend_name or config.default_backend),
        )

        exit_code = client_main(
            ["--config", "ignored.yaml", "execute", "himalaya", "--", "folder", "list"]
        )
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "exists in multiple backends (local, review)" in captured.err
        assert "Specify --backend <name>" in captured.err

    def test_tools_command(self, monkeypatch, capsys) -> None:
        remote = {
            "version": "0.1.0",
            "client_name": "reader",
            "execute_url": "/execute",
            "token_info_url": "/token-info",
            "mcp_url": f"/mcp/{READER_SLUG}/",
            "sse_url": f"/sse/{READER_SLUG}/",
            "tools": [
                {
                    "name": "himalaya",
                    "argv_normalization": {
                        "patterns": [
                            {
                                "id": "account",
                                "kind": "key_value",
                                "key_pattern": "^account$",
                                "value_pattern": "^[A-Za-z0-9_.-]+$",
                                "canonical_position": "before_command",
                                "allow_positions": [
                                    "before_command",
                                    "after_command",
                                ],
                                "multiple": False,
                            }
                        ]
                    },
                    "rules": [
                        {
                            "id": "list_messages",
                            "command": ["message", "list"],
                            "flags": ["--account"],
                            "positionals": [],
                        }
                    ],
                }
            ],
        }

        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(remote)

        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    }
                },
            }
        )

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(),
        )

        exit_code = client_main(["--config", "ignored.yaml", "tools"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Client: reader" in captured.out
        assert "himalaya" in captured.out
        assert "argv_normalization:" in captured.out
        assert "list_messages: message list" in captured.out

    def test_execute_command(self, monkeypatch, capsys) -> None:
        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(
                    {
                        "version": "0.1.0",
                        "client_name": "reader",
                        "execute_url": "/execute",
                        "token_info_url": "/token-info",
                        "mcp_url": f"/mcp/{READER_SLUG}/",
                        "sse_url": f"/sse/{READER_SLUG}/",
                        "tools": [
                            {
                                "name": "himalaya",
                                "rules": [],
                            }
                        ],
                    }
                )

            async def execute(self, tool: str, argv: list[str]):
                from clibroker.models import ExecuteResponse

                return ExecuteResponse(
                    ok=True,
                    exit_code=0,
                    stdout={"tool": tool, "argv": argv},
                    stderr="",
                    duration_ms=1.23,
                    matched_rule="list_messages",
                    timed_out=False,
                )

        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    }
                },
            }
        )

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(),
        )

        exit_code = client_main(
            [
                "--config",
                "ignored.yaml",
                "execute",
                "himalaya",
                "--",
                "message",
                "list",
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["matched_rule"] == "list_messages"
        assert payload["stdout"]["argv"] == ["message", "list"]

    def test_execute_command_rejects_ambiguous_global_args(
        self, monkeypatch, capsys
    ) -> None:
        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(
                    {
                        "version": "0.1.0",
                        "client_name": "reader",
                        "execute_url": "/execute",
                        "token_info_url": "/token-info",
                        "mcp_url": f"/mcp/{READER_SLUG}/",
                        "sse_url": f"/sse/{READER_SLUG}/",
                        "tools": [
                            {
                                "name": "obsidian",
                                "argv_normalization": {
                                    "patterns": [
                                        {
                                            "id": "vault",
                                            "kind": "key_value",
                                            "key_pattern": "^vault$",
                                            "value_pattern": "^[A-Za-z0-9_. -]+$",
                                            "canonical_position": "before_command",
                                            "allow_positions": [
                                                "before_command",
                                                "after_command",
                                            ],
                                            "multiple": False,
                                        }
                                    ]
                                },
                                "rules": [],
                            }
                        ],
                    }
                )

            async def execute(self, tool: str, argv: list[str]):  # pragma: no cover - should not execute
                raise AssertionError("execute should not be called for ambiguous globals")

        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    }
                },
            }
        )

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(),
        )

        exit_code = client_main(
            [
                "--config",
                "ignored.yaml",
                "execute",
                "obsidian",
                "--",
                "vault=Main",
                "search",
                "query=thyroid",
                "vault=Other",
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "Ambiguous global arg usage" in captured.err

    def test_execute_command_rejects_malformed_global_args(
        self, monkeypatch, capsys
    ) -> None:
        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(
                    {
                        "version": "0.1.0",
                        "client_name": "reader",
                        "execute_url": "/execute",
                        "token_info_url": "/token-info",
                        "mcp_url": f"/mcp/{READER_SLUG}/",
                        "sse_url": f"/sse/{READER_SLUG}/",
                        "tools": [
                            {
                                "name": "obsidian",
                                "argv_normalization": {
                                    "patterns": [
                                        {
                                            "id": "vault",
                                            "kind": "key_value",
                                            "key_pattern": "^vault$",
                                            "value_pattern": "^[A-Za-z0-9_. -]+$",
                                            "canonical_position": "before_command",
                                            "allow_positions": [
                                                "before_command",
                                                "after_command",
                                            ],
                                            "multiple": False,
                                        }
                                    ]
                                },
                                "rules": [],
                            }
                        ],
                    }
                )

            async def execute(self, tool: str, argv: list[str]):  # pragma: no cover - should not execute
                raise AssertionError("execute should not be called for malformed globals")

        config = BrokerClientConfig.model_validate(
            {
                "default_backend": "local",
                "backends": {
                    "local": {
                        "type": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "token": "literal-token",
                    }
                },
            }
        )

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(),
        )

        exit_code = client_main(
            [
                "--config",
                "ignored.yaml",
                "execute",
                "obsidian",
                "--",
                "search",
                "query=thyroid",
                "vault=bad/value",
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "Invalid global arg usage" in captured.err
