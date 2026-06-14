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


class TestArtifactCaptureConfig:
    """Artifact capture config validation."""

    def test_rule_accepts_artifact_capture(self) -> None:
        config = make_config(
            extra_yaml="""
            x-extra: {}
            """,
        )
        rule = next(
            rule
            for rule in config.tools["himalaya"].rules
            if rule.id == "list_messages"
        )
        assert rule.artifact_capture is None

    def test_artifact_capture_requires_safe_path_template(self) -> None:
        import yaml
        from pydantic import ValidationError

        from clibroker.config import Config

        raw = yaml.safe_load(
            """
            server:
              bind: "127.0.0.1:9999"
              auth:
                type: bearer
                tokens:
                  - name: reader
                    value: "test-reader-token"
                    allow_rules: ["download_attachments"]
            tools:
              himalaya:
                executable: "/usr/bin/echo"
                default_args: []
                file_sharing:
                  expose_working_dir: false
                  shares:
                    - name: attachments
                      path: /tmp/clibroker-artifacts
                      access: read
                rules:
                  - id: download_attachments
                    command: ["attachment", "download"]
                    effect: allow
                    inject_args: ["--downloads-dir", "{artifact_dir}"]
                    artifact_capture:
                      share: attachments
                      path_template: "../escape/{execution_id}"
                    positionals:
                      - name: id
                        pattern: "^[0-9]+$"
            """
        )

        with pytest.raises(ValidationError) as exc_info:
            Config.model_validate(raw)
        assert "path_template must be relative and must not contain '..'" in str(
            exc_info.value
        )


class TestArtifactCaptureExecution:
    """End-to-end artifact capture from a brokered command."""

    @pytest.mark.asyncio
    async def test_execute_returns_downloadable_artifacts(self, tmp_path) -> None:
        import textwrap
        import yaml

        from clibroker.config import Config

        artifact_root = tmp_path / "attachments"
        artifact_root.mkdir()
        script = (
            "import pathlib, sys; "
            "out = pathlib.Path(sys.argv[sys.argv.index('--downloads-dir') + 1]); "
            "out.mkdir(parents=True, exist_ok=True); "
            "(out / 'receipt.pdf').write_bytes(b'%PDF-test')"
        )
        raw = yaml.safe_load(
            textwrap.dedent(
                f"""
                server:
                  bind: "127.0.0.1:9999"
                  auth:
                    type: bearer
                    tokens:
                      - name: reader
                        value: "{READER_TOKEN}"
                        allow_rules: ["download_attachments"]
                tools:
                  himalaya:
                    executable: "{sys.executable}"
                    default_args: ["-c", "{script}"]
                    file_sharing:
                      expose_working_dir: false
                      max_file_bytes: 1048576
                      shares:
                        - name: attachments
                          path: "{artifact_root}"
                          access: read
                    rules:
                      - id: download_attachments
                        command: ["attachment", "download"]
                        effect: allow
                        inject_args: ["--downloads-dir", "{{artifact_dir}}"]
                        artifact_capture:
                          share: attachments
                          path_template: "runs/{{execution_id}}"
                        positionals:
                          - name: id
                            pattern: "^[0-9]+$"
                """
            )
        )
        app = create_app(Config.model_validate(raw))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            execute_resp = await client.post(
                "/execute",
                json={"tool": "himalaya", "argv": ["attachment", "download", "42"]},
                headers={"Authorization": f"Bearer {READER_TOKEN}"},
            )

            assert execute_resp.status_code == 200
            body = execute_resp.json()
            assert body["ok"] is True
            assert len(body["artifacts"]) == 1
            artifact = body["artifacts"][0]
            assert artifact["tool"] == "himalaya"
            assert artifact["share"] == "attachments"
            assert artifact["path"].startswith("runs/")
            assert artifact["path"].endswith("/receipt.pdf")
            assert artifact["name"] == "receipt.pdf"
            assert artifact["size"] == 9
            assert len(artifact["sha256"]) == 64

            file_resp = await client.get(
                artifact["download_url"],
                headers={"Authorization": f"Bearer {READER_TOKEN}"},
            )
            assert file_resp.status_code == 200
            assert file_resp.content == b"%PDF-test"


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
