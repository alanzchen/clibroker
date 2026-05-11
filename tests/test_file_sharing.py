"""Tests for per-tool file sharing."""

from __future__ import annotations

import base64
import hashlib
import sys
import textwrap

import pytest
import yaml
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from clibroker.app import create_app
from clibroker.config import Config, FileShareConfig, FileSharingConfig
from clibroker.file_sharing import (
    FileShareForbidden,
    FileShareNotFound,
    FileShareService,
    FileShareTooLarge,
)
from clibroker.mcp_server import create_mcp_server
from clibroker.policy import PolicyEngine

READER_TOKEN = "test-reader-token"
OTHER_TOKEN = "test-other-token"
READER_SLUG = hashlib.sha256(READER_TOKEN.encode()).hexdigest()[:16]


def make_file_config(tmp_path, *, working_dir: str | None = None) -> tuple[Config, dict]:
    workdir = tmp_path / "workdir"
    docs = tmp_path / "docs"
    rw = tmp_path / "rw"
    other = tmp_path / "other"
    for directory in (workdir, docs, rw, other):
        directory.mkdir()

    (workdir / "state.txt").write_text("state", encoding="utf-8")
    (docs / "readme.txt").write_text("hello", encoding="utf-8")
    (docs / "large.txt").write_text("x" * 20, encoding="utf-8")
    (rw / "old.txt").write_text("old", encoding="utf-8")

    raw = yaml.safe_load(
        textwrap.dedent(f"""\
        server:
          bind: "127.0.0.1:9999"
          auth:
            type: bearer
            tokens:
              - name: reader
                value: "{READER_TOKEN}"
                allow_rules: ["list_messages"]
              - name: other
                value: "{OTHER_TOKEN}"
                allow_rules: ["other_rule"]
        tools:
          himalaya:
            executable: "{sys.executable}"
            default_args: []
            working_dir: "{working_dir if working_dir is not None else workdir}"
            file_sharing:
              max_file_bytes: 16
              shares:
                - name: docs
                  path: "{docs}"
                  access: read
                - name: rw
                  path: "{rw}"
                  access: read_write
            rules:
              - id: list_messages
                command: ["message", "list"]
                effect: allow
          other:
            executable: "{sys.executable}"
            default_args: []
            working_dir: "{other}"
            file_sharing:
              expose_working_dir: false
            rules:
              - id: other_rule
                command: ["other"]
                effect: allow
        """)
    )
    return Config.model_validate(raw), {
        "workdir": workdir,
        "docs": docs,
        "rw": rw,
        "other": other,
    }


class TestFileShareConfigValidation:
    def test_share_name_must_be_safe(self) -> None:
        with pytest.raises(ValidationError):
            FileShareConfig(name="../bad", path="/tmp/shared")

    def test_share_path_must_be_absolute(self) -> None:
        with pytest.raises(ValidationError):
            FileShareConfig(name="docs", path="relative/path")

    def test_duplicate_share_names_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            FileSharingConfig.model_validate(
                {
                    "shares": [
                        {"name": "docs", "path": "/tmp/docs-a"},
                        {"name": "docs", "path": "/tmp/docs-b"},
                    ]
                }
            )
        assert "Duplicate file share name" in str(exc_info.value)

    def test_working_dir_is_exposed_read_only_by_default(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)

        share = service.get_share("himalaya", "working_dir", ["list_messages"])

        assert share.access == "read"

    def test_explicit_working_dir_share_overrides_default(self, tmp_path) -> None:
        config, paths = make_file_config(tmp_path)
        raw = config.model_dump()
        raw["tools"]["himalaya"]["file_sharing"]["shares"].append(
            {
                "name": "working_dir",
                "path": str(paths["rw"]),
                "access": "read_write",
            }
        )
        config = Config.model_validate(raw)
        service = FileShareService(config)

        share = service.get_share("himalaya", "working_dir", ["list_messages"])

        assert share.access == "read_write"
        assert share.root == paths["rw"]

    def test_relative_working_dir_is_not_auto_shared(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path, working_dir="relative-workdir")
        service = FileShareService(config)

        with pytest.raises(FileShareNotFound):
            service.get_share("himalaya", "working_dir", ["list_messages"])


class TestFileShareAuthorization:
    def test_any_tool_rule_grants_share_access(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)

        share = service.get_share("himalaya", "docs", ["list_messages"])

        assert share.name == "docs"

    def test_unrelated_tool_rule_does_not_grant_share_access(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)

        with pytest.raises(FileShareForbidden):
            service.get_share("himalaya", "docs", ["other_rule"])

    def test_client_shares_hide_host_paths(self, tmp_path) -> None:
        config, paths = make_file_config(tmp_path)
        service = FileShareService(config)

        shares = service.get_client_shares("himalaya", ["list_messages"])

        assert {share["name"] for share in shares} == {"working_dir", "docs", "rw"}
        assert all(str(paths["docs"]) not in repr(share) for share in shares)
        assert any(share["url"] == "/files/himalaya/docs" for share in shares)


class TestFileShareOperations:
    def test_list_stat_and_read_text_file(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)
        share = service.get_share("himalaya", "docs", ["list_messages"])

        listing = service.list_dir(share)
        stat = service.stat_path(share, "readme.txt")
        read = service.read_file(share, "readme.txt")

        assert [entry["path"] for entry in listing["entries"]] == [
            "large.txt",
            "readme.txt",
        ]
        assert stat["entry"]["type"] == "file"
        assert read["content"] == "hello"
        assert read["encoding"] == "utf-8"

    def test_binary_read_and_write_base64(self, tmp_path) -> None:
        config, paths = make_file_config(tmp_path)
        service = FileShareService(config)
        share = service.get_share("himalaya", "rw", ["list_messages"])
        payload = base64.b64encode(b"\x00\xffdata").decode("ascii")

        written = service.write_file(
            share,
            "blob.bin",
            payload,
            encoding="base64",
        )
        read = service.read_file(share, "blob.bin", encoding="base64")

        assert written["entry"]["path"] == "blob.bin"
        assert base64.b64decode(read["content"]) == b"\x00\xffdata"
        assert (paths["rw"] / "blob.bin").read_bytes() == b"\x00\xffdata"

    def test_mkdir_move_and_delete(self, tmp_path) -> None:
        config, paths = make_file_config(tmp_path)
        service = FileShareService(config)
        share = service.get_share("himalaya", "rw", ["list_messages"])

        service.mkdir(share, "nested")
        service.write_file(share, "nested/item.txt", "content")
        moved = service.move(share, "nested/item.txt", "nested/moved.txt")
        deleted = service.delete(share, "nested", recursive=True)

        assert moved["destination_path"] == "nested/moved.txt"
        assert deleted["deleted"] == "nested"
        assert not (paths["rw"] / "nested").exists()

    def test_read_only_share_rejects_write(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)
        share = service.get_share("himalaya", "docs", ["list_messages"])

        with pytest.raises(FileShareForbidden):
            service.write_file(share, "new.txt", "content")

    def test_large_file_rejected(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)
        share = service.get_share("himalaya", "docs", ["list_messages"])

        with pytest.raises(FileShareTooLarge):
            service.read_file(share, "large.txt")

    def test_path_traversal_and_absolute_paths_rejected(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)
        share = service.get_share("himalaya", "docs", ["list_messages"])

        with pytest.raises(FileShareForbidden):
            service.read_file(share, "../outside.txt")
        with pytest.raises(FileShareForbidden):
            service.read_file(share, "/etc/passwd")

    def test_symlink_escape_rejected(self, tmp_path) -> None:
        config, paths = make_file_config(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        (paths["docs"] / "escape").symlink_to(outside)
        service = FileShareService(config)
        share = service.get_share("himalaya", "docs", ["list_messages"])

        with pytest.raises(FileShareForbidden):
            service.read_file(share, "escape")


class TestFileShareHTTP:
    @pytest.fixture
    async def client(self, tmp_path):
        config, _ = make_file_config(tmp_path)
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_file_download_requires_auth(self, client: AsyncClient) -> None:
        resp = await client.get("/files/himalaya/docs/readme.txt")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_file_download_uses_bearer_auth(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/files/himalaya/docs/readme.txt",
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )

        assert resp.status_code == 200
        assert resp.text == "hello"

    @pytest.mark.asyncio
    async def test_directory_listing_hides_host_paths(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/files/himalaya/docs",
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert {entry["path"] for entry in body["entries"]} == {
            "large.txt",
            "readme.txt",
        }
        assert "/tmp/" not in resp.text

    @pytest.mark.asyncio
    async def test_unrelated_token_cannot_access_tool_share(
        self,
        client: AsyncClient,
    ) -> None:
        resp = await client.get(
            "/files/himalaya/docs/readme.txt",
            headers={"Authorization": f"Bearer {OTHER_TOKEN}"},
        )

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_client_config_exposes_file_shares(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/client-config",
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )

        assert resp.status_code == 200
        tool = next(item for item in resp.json()["tools"] if item["name"] == "himalaya")
        shares = {share["name"]: share for share in tool["file_shares"]}
        assert shares["working_dir"]["access"] == "read"
        assert shares["rw"]["access"] == "read_write"
        assert shares["docs"]["url"] == "/files/himalaya/docs"


class TestFileShareMCP:
    def test_file_tools_registered_for_authorized_tool(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)
        policy = PolicyEngine(config)
        mcp = create_mcp_server(
            config,
            policy,
            file_share_service=service,
            allowed_rules={"list_messages"},
        )

        tool_names = set(mcp._tool_manager._tools)

        assert "himalaya__files_list" in tool_names
        assert "himalaya__files_write" in tool_names
        assert "other__files_list" not in tool_names

    def test_file_tools_not_registered_for_unrelated_rule(self, tmp_path) -> None:
        config, _ = make_file_config(tmp_path)
        service = FileShareService(config)
        policy = PolicyEngine(config)
        mcp = create_mcp_server(
            config,
            policy,
            file_share_service=service,
            allowed_rules={"other_rule"},
        )

        tool_names = set(mcp._tool_manager._tools)

        assert "himalaya__files_list" not in tool_names
        assert "other__files_list" not in tool_names

    @pytest.mark.asyncio
    async def test_mcp_file_read_call(self, tmp_path) -> None:
        from asgi_lifespan import LifespanManager

        config, _ = make_file_config(tmp_path)
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
            ) as client:
                init_resp = await client.post(
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

                await client.post(
                    "/",
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers=headers,
                )
                resp = await client.post(
                    "/",
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "himalaya__files_read",
                            "arguments": {
                                "share": "docs",
                                "path": "readme.txt",
                            },
                        },
                    },
                    headers=headers,
                )

        assert resp.status_code == 200
        content = resp.json()["result"]["content"]
        result_data = yaml.safe_load(content[0]["text"])
        assert result_data["ok"] is True
        assert result_data["content"] == "hello"
