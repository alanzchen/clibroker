"""Tests for the broker client package and token-scoped discovery endpoint."""

from __future__ import annotations

import builtins
import hashlib
import json
from pathlib import Path
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
        path.write_text(
            "default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n"
        )

        resolved = resolve_client_config_path(path)

        assert resolved == path

    def test_resolve_client_config_path_uses_env_var(
        self, tmp_path, monkeypatch
    ) -> None:
        path = tmp_path / "env-client.yaml"
        path.write_text(
            "default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n"
        )
        monkeypatch.setenv("CLIBROKER_CLIENT_CONFIG", str(path))

        resolved = resolve_client_config_path()

        assert resolved == path

    def test_resolve_client_config_path_prefers_openclaw_default(
        self, tmp_path, monkeypatch
    ) -> None:
        home = tmp_path / "home"
        openclaw_dir = home / ".openclaw"
        openclaw_dir.mkdir(parents=True)
        path = openclaw_dir / "clibroker-client.yaml"
        path.write_text(
            "default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n"
        )
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("CLIBROKER_CLIENT_CONFIG", raising=False)
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

        resolved = resolve_client_config_path()

        assert resolved == path

    def test_resolve_client_config_path_falls_back_to_xdg(
        self, tmp_path, monkeypatch
    ) -> None:
        xdg = tmp_path / "xdg"
        config_dir = xdg / "clibroker"
        config_dir.mkdir(parents=True)
        path = config_dir / "client.yaml"
        path.write_text(
            "default_backend: local\nbackends: {local: {type: http, base_url: http://127.0.0.1:8080, token: literal-token}}\n"
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.delenv("CLIBROKER_CLIENT_CONFIG", raising=False)

        resolved = resolve_client_config_path()

        assert resolved == path

    def test_resolve_client_config_path_raises_when_missing(
        self, tmp_path, monkeypatch
    ) -> None:
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

    @pytest.mark.asyncio
    async def test_execute_preserves_broker_timeout_outcome(self) -> None:
        import httpx

        payload = {
            "request_id": "request-with-known-outcome",
            "state": "interrupted",
            "ok": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "Request timed out",
            "duration_ms": 20,
            "matched_rule": "action",
            "request_timed_out": True,
        }
        backend = HttpBackend(
            HTTPBackendConfig(base_url="http://test", token="test"),
            transport=httpx.MockTransport(
                lambda req: httpx.Response(504, json=payload)
            ),
        )
        result = await backend.execute("tool", ["action"])
        assert result.request_id == payload["request_id"]
        assert result.state == "interrupted"
        assert result.request_timed_out is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body", [b"Gateway timeout", b'{"detail":"proxy timeout"}']
    )
    async def test_execute_marks_proxy_timeout_outcome_unknown(self, body) -> None:
        import httpx
        from clibroker.client import ClientBackendError

        backend = HttpBackend(
            HTTPBackendConfig(base_url="http://test", token="test"),
            transport=httpx.MockTransport(
                lambda req: httpx.Response(504, content=body)
            ),
        )
        with pytest.raises(
            ClientBackendError, match="outcome is unknown; do not automatically retry"
        ):
            await backend.execute("tool", ["action"])

    @pytest.mark.asyncio
    async def test_list_and_download_shared_file(self, tmp_path) -> None:
        share_root = tmp_path / "attachments"
        share_root.mkdir()
        (share_root / "receipt.pdf").write_bytes(b"%PDF-test")
        raw = yaml.safe_load(
            f"""
            server:
              bind: "127.0.0.1:9999"
              auth:
                type: bearer
                tokens:
                  - name: reader
                    value: "{READER_TOKEN}"
                    allow_rules: ["list_messages"]
            tools:
              himalaya:
                executable: "/usr/bin/echo"
                default_args: []
                file_sharing:
                  expose_working_dir: false
                  shares:
                    - name: attachments
                      path: "{share_root}"
                      access: read
                rules:
                  - id: list_messages
                    command: ["message", "list"]
                    effect: allow
            """
        )
        backend = HttpBackend(
            HTTPBackendConfig(base_url="http://test", token=READER_TOKEN),
            transport=ASGITransport(app=create_app(Config.model_validate(raw))),
        )

        listing = await backend.list_files("himalaya", "attachments")
        assert listing["ok"] is True
        assert listing["entries"][0]["name"] == "receipt.pdf"

        destination = tmp_path / "downloaded.pdf"
        result = await backend.download_file(
            "himalaya",
            "attachments",
            "receipt.pdf",
            destination,
        )
        assert result["path"] == str(destination)
        assert destination.read_bytes() == b"%PDF-test"


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

    def test_tools_command_uses_default_config_path(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
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

        exit_code = client_main(
            ["--config", "ignored.yaml", "--backend", "review", "tools"]
        )
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
            lambda config, backend_name=None: FakeBackend(
                backend_name or config.default_backend
            ),
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
        himalaya = next(
            item for item in payload["tool_index"] if item["name"] == "himalaya"
        )
        assert himalaya["backends"] == ["local", "review"]
        assert himalaya["conflict"] is True

    def test_execute_command_auto_selects_unique_backend(
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
            lambda config, backend_name=None: FakeBackend(
                backend_name or config.default_backend
            ),
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

            async def execute(
                self, tool: str, argv: list[str]
            ):  # pragma: no cover - should not execute
                raise AssertionError(
                    "execute should not be called when tool is ambiguous"
                )

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(
                backend_name or config.default_backend
            ),
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

    def test_files_list_prints_share_entries(self, monkeypatch, capsys) -> None:
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

        class FakeBackend:
            async def list_files(self, tool, share, path="."):
                return {
                    "ok": True,
                    "tool": tool,
                    "share": share,
                    "path": path,
                    "entries": [
                        {
                            "name": "receipt.pdf",
                            "path": "receipt.pdf",
                            "type": "file",
                            "size": 9,
                        }
                    ],
                }

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
                "files",
                "list",
                "himalaya",
                "attachments",
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "receipt.pdf" in captured.out
        assert "9 bytes" in captured.out

    def test_files_list_suppresses_broken_pipe(self, monkeypatch) -> None:
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

        class FakeBackend:
            async def list_files(self, tool, share, path="."):
                return {
                    "ok": True,
                    "tool": tool,
                    "share": share,
                    "path": path,
                    "entries": [
                        {
                            "name": "receipt.pdf",
                            "path": "receipt.pdf",
                            "type": "file",
                            "size": 9,
                        }
                    ],
                }

        def closed_pipe_print(*args, **kwargs):
            raise BrokenPipeError

        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend",
            lambda config, backend_name=None: FakeBackend(),
        )
        monkeypatch.setattr(builtins, "print", closed_pipe_print)

        exit_code = client_main(
            [
                "--config",
                "ignored.yaml",
                "files",
                "list",
                "himalaya",
                "attachments",
            ]
        )

        assert exit_code == 0

    def test_files_get_downloads_to_output_directory(
        self,
        tmp_path,
        monkeypatch,
        capsys,
    ) -> None:
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

        class FakeBackend:
            async def download_file(self, tool, share, path, destination):
                return {
                    "tool": tool,
                    "share": share,
                    "remote_path": path,
                    "path": str(destination),
                    "size": 9,
                }

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
                "files",
                "get",
                "himalaya",
                "attachments",
                "receipt.pdf",
                "--output",
                str(tmp_path),
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["path"] == str(tmp_path / "receipt.pdf")

    def test_files_get_suffixless_output_is_file(
        self,
        tmp_path,
        monkeypatch,
        capsys,
    ) -> None:
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

        class FakeBackend:
            async def download_file(self, tool, share, path, destination):
                return {
                    "tool": tool,
                    "share": share,
                    "remote_path": path,
                    "path": str(destination),
                    "size": 9,
                }

        output_path = tmp_path / "LICENSE"
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
                "files",
                "get",
                "himalaya",
                "attachments",
                "receipt.pdf",
                "--output",
                str(output_path),
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["path"] == str(output_path)

    def test_execute_download_artifacts_fetches_returned_files(
        self,
        tmp_path,
        monkeypatch,
        capsys,
    ) -> None:
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

        class FakeResult:
            ok = True
            exit_code = 0
            artifacts = [
                {
                    "tool": "himalaya",
                    "share": "attachments",
                    "path": "runs/abc/receipt.pdf",
                    "name": "receipt.pdf",
                    "size": 9,
                    "modified": 1.0,
                    "sha256": "0" * 64,
                    "url": "/files/himalaya/attachments/runs/abc/receipt.pdf",
                    "download_url": "/files/himalaya/attachments/runs/abc/receipt.pdf",
                }
            ]

            def model_dump(self):
                return {
                    "ok": self.ok,
                    "exit_code": self.exit_code,
                    "stdout": "",
                    "stderr": "",
                    "duration_ms": 1.0,
                    "matched_rule": "download_attachments",
                    "timed_out": False,
                    "artifacts": self.artifacts,
                }

        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(self_remote)

            async def execute(self, tool, argv):
                return FakeResult()

            async def download_url(self, download_url, destination):
                return {
                    "download_url": download_url,
                    "path": str(destination),
                    "size": 9,
                }

        self_remote = self._make_remote("reader", ["himalaya"])
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
                "--download-artifacts",
                str(tmp_path),
                "himalaya",
                "--",
                "attachment",
                "download",
                "42",
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["downloaded_artifacts"][0]["path"] == str(
            tmp_path / "receipt.pdf"
        )

    def test_execute_download_artifacts_sanitizes_returned_names(
        self,
        tmp_path,
        monkeypatch,
        capsys,
    ) -> None:
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

        class FakeResult:
            ok = True
            exit_code = 0
            artifacts = [
                {
                    "tool": "himalaya",
                    "share": "attachments",
                    "path": "runs/abc/passwd",
                    "name": "../../passwd",
                    "size": 9,
                    "modified": 1.0,
                    "sha256": "0" * 64,
                    "url": "/files/himalaya/attachments/runs/abc/passwd",
                    "download_url": "/files/himalaya/attachments/runs/abc/passwd",
                }
            ]

            def model_dump(self):
                return {
                    "ok": self.ok,
                    "exit_code": self.exit_code,
                    "stdout": "",
                    "stderr": "",
                    "duration_ms": 1.0,
                    "matched_rule": "download_attachments",
                    "timed_out": False,
                    "artifacts": self.artifacts,
                }

        class FakeBackend:
            async def fetch_config(self):
                from clibroker.models import ClientConfigResponse

                return ClientConfigResponse.model_validate(self_remote)

            async def execute(self, tool, argv):
                return FakeResult()

            async def download_url(self, download_url, destination):
                return {
                    "download_url": download_url,
                    "path": str(destination),
                    "size": 9,
                }

        self_remote = self._make_remote("reader", ["himalaya"])
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
                "--download-artifacts",
                str(tmp_path),
                "himalaya",
                "--",
                "attachment",
                "download",
                "42",
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["downloaded_artifacts"][0]["path"] == str(tmp_path / "passwd")

    @pytest.mark.parametrize(
        "argv",
        [
            ["vault=Main", "search", "query=thyroid", "vault=Other"],
            ["search", "query=thyroid", "vault=bad/value"],
            ["v=Main", "search", "query=thyroid", "vault=Main"],
            ["vault=Main", "search", "--", "vault=bad/value"],
            ["vault=Main", "search", "--query", "vault=bad/value"],
        ],
    )
    def test_execute_forwards_argv_for_server_validation(
        self, argv, monkeypatch, capsys
    ) -> None:
        from clibroker.models import ExecuteResponse

        class FakeBackend:
            async def execute(self, tool, forwarded):
                assert tool == "obsidian"
                assert forwarded == argv
                return ExecuteResponse(
                    ok=False,
                    exit_code=-1,
                    stdout="",
                    stderr="server policy result",
                    duration_ms=0,
                    matched_rule="search",
                )

        config = BrokerClientConfig(
            default_backend="local",
            backends={"local": {"base_url": "http://test", "token": "test"}},
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend", lambda *args: FakeBackend()
        )
        code = client_main(["--config", "unused", "execute", "obsidian", "--", *argv])
        assert code == 1
        assert json.loads(capsys.readouterr().out)["stderr"] == "server policy result"

    @pytest.mark.parametrize("directory_failure", [False, True])
    def test_artifact_transfer_failure_preserves_execution_result(
        self, directory_failure, tmp_path, monkeypatch, capsys
    ) -> None:
        from clibroker.client import ClientBackendError
        from clibroker.models import ExecuteResponse

        artifacts = [
            {
                "tool": "tool",
                "share": "outputs",
                "path": f"runs/id/{name}",
                "name": name,
                "size": 1,
                "modified": 0,
                "sha256": "a" * 64,
                "url": f"/files/tool/outputs/runs/id/{name}",
                "download_url": f"/files/tool/outputs/runs/id/{name}",
            }
            for name in ["first.txt", "missing.txt", "last.txt"]
        ]
        calls = []

        class FakeBackend:
            async def execute(self, tool, argv):
                calls.append("execute")
                return ExecuteResponse(
                    request_id="completed-request",
                    state="succeeded",
                    ok=True,
                    exit_code=0,
                    stdout="external action completed",
                    stderr="",
                    duration_ms=1,
                    matched_rule="action",
                    artifacts=artifacts,
                )

            async def download_url(self, url, destination):
                calls.append(url)
                if url.endswith("missing.txt"):
                    raise ClientBackendError("HTTP 404")
                destination.write_text("artifact")
                return {"path": str(destination)}

            async def download_file(self, tool, share, path, destination):
                calls.append((tool, share, path))
                return {"path": str(destination), "remote_path": path}

        backend = FakeBackend()
        config = BrokerClientConfig(
            default_backend="local",
            backends={"local": {"base_url": "http://test", "token": "test"}},
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.load_client_config", lambda path: config
        )
        monkeypatch.setattr(
            "clibroker.client.__main__.build_backend", lambda *args: backend
        )
        output = tmp_path / "downloads"
        if directory_failure:
            output.write_text("existing file")
        code = client_main(
            [
                "--config",
                "unused",
                "execute",
                "--download-artifacts",
                str(output),
                "tool",
                "--",
                "action",
            ]
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert code == 0
        assert payload["ok"] is True
        assert payload["state"] == "succeeded"
        assert payload["request_id"] == "completed-request"
        assert payload["stdout"] == "external action completed"
        assert payload["artifact_downloads"]["ok"] is False
        statuses = [item["status"] for item in payload["artifact_downloads"]["results"]]
        assert statuses == (
            ["failed"] * 3
            if directory_failure
            else ["downloaded", "failed", "downloaded"]
        )
        assert len(payload["downloaded_artifacts"]) == (0 if directory_failure else 2)
        assert "files get" in captured.err
        # Retrieval can be retried through its own command without executing again.
        missing = payload["artifact_downloads"]["results"][1]
        assert (
            client_main(
                [
                    "--config",
                    "unused",
                    "files",
                    "get",
                    missing["tool"],
                    missing["share"],
                    missing["path"],
                    "--output",
                    str(tmp_path / "retry.txt"),
                ]
            )
            == 0
        )
        assert calls.count("execute") == 1
        assert ("tool", "outputs", "runs/id/missing.txt") in calls


class TestArtifactDownloadSafety:
    @pytest.mark.asyncio
    async def test_recursive_artifacts_and_existing_paths_are_never_overwritten(
        self, tmp_path
    ):
        import httpx
        from clibroker.client.__main__ import _download_execute_artifacts

        output = tmp_path / "downloads"
        output.mkdir()
        (output / "report.csv").write_text("existing")
        victim = tmp_path / "victim.csv"
        victim.write_text("private")
        (output / "report.1.csv").symlink_to(victim)
        missing = tmp_path / "not-created.csv"
        (output / "report.2.csv").symlink_to(missing)
        artifacts = [
            {
                "name": "report.csv",
                "path": f"runs/id/{folder}/report.csv",
                "download_url": f"/files/tool/outputs/runs/id/{folder}/report.csv",
            }
            for folder in ["a", "b"]
        ]
        backend = HttpBackend(
            HTTPBackendConfig(base_url="http://test", token="test"),
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, content=req.url.path.encode())
            ),
        )
        transfers = await _download_execute_artifacts(backend, artifacts, output)
        assert all(item["status"] == "downloaded" for item in transfers)
        local_paths = [Path(item["local_path"]) for item in transfers]
        assert len(set(local_paths)) == 2
        assert [path.read_text() for path in local_paths] == [
            a["download_url"] for a in artifacts
        ]
        assert (output / "report.csv").read_text() == "existing"
        assert victim.read_text() == "private"
        assert not missing.exists()
        assert (output / "report.1.csv").is_symlink()
        assert (output / "report.2.csv").is_symlink()

    @pytest.mark.asyncio
    async def test_parallel_artifact_downloads_allocate_distinct_files(self, tmp_path):
        import asyncio
        import threading
        import httpx

        count = 4
        ready = threading.Barrier(count)

        def respond(request):
            ready.wait(timeout=5)
            return httpx.Response(200, content=request.url.path.encode())

        backend = HttpBackend(
            HTTPBackendConfig(base_url="http://test", token="test"),
            transport=httpx.MockTransport(respond),
        )

        def download(number):
            return asyncio.run(
                backend.download_url(
                    f"/files/tool/share/{number}", tmp_path / "report.csv"
                )
            )

        results = await asyncio.gather(
            *[asyncio.to_thread(download, number) for number in range(count)]
        )
        assert len({item["path"] for item in results}) == count
        assert {Path(item["path"]).read_text() for item in results} == {
            f"/files/tool/share/{number}" for number in range(count)
        }
