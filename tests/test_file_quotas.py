"""File quotas and in-memory read limits remain independent across transports."""

from __future__ import annotations

import base64
import json
import os

import pytest
from pydantic import ValidationError

from clibroker.config import Config, FileSharingConfig
from clibroker.file_sharing import FileShareService, FileShareTooLarge
from tests.test_mcp_artifacts import TOKEN, export, make_artifact_config, rpc, running

MIB = 1_048_576
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def quota_config(tmp_path, *, quota, inline=None, script=None):
    kwargs = {} if script is None else {"script": script}
    raw = make_artifact_config(tmp_path, **kwargs).model_dump()
    sharing = raw["tools"]["exporter"]["file_sharing"]
    sharing["max_file_bytes"] = quota
    sharing["max_inline_read_bytes"] = inline
    sharing["shares"][0]["access"] = "read_write"
    return Config.model_validate(raw)


async def resource_read(client, path):
    return await rpc(
        client,
        "resources/read",
        {"uri": f"clibroker://artifacts/exporter/output/{path}"},
    )


async def file_tool(client, operation, **arguments):
    response = await rpc(
        client,
        "tools/call",
        {
            "name": f"exporter__files_{operation}",
            "arguments": {"share": "output", **arguments},
        },
    )
    return json.loads(response.json()["result"]["content"][0]["text"])


@pytest.mark.parametrize(
    "settings",
    [
        {"max_file_bytes": -1},
        {"max_inline_read_bytes": 0},
        {"max_inline_read_bytes": -1},
    ],
)
def test_invalid_file_limits_are_rejected(settings):
    with pytest.raises(ValidationError):
        FileSharingConfig(**settings)


def test_zero_quota_and_optional_inline_limit_are_valid():
    assert FileSharingConfig(max_file_bytes=0).max_inline_read_bytes is None
    assert FileSharingConfig(max_inline_read_bytes=None).max_file_bytes == MIB
    assert FileSharingConfig(max_inline_read_bytes=1).max_inline_read_bytes == 1


@pytest.mark.parametrize("quota,inline", [(0, None), (32, None), (0, 8), (32, 8)])
async def test_short_inline_reads_return_all_bytes(tmp_path, quota, inline):
    config = quota_config(tmp_path, quota=quota, inline=inline)
    payload = b"\x00\xffhello"
    (tmp_path / "artifacts" / "short.bin").write_bytes(payload)
    async with running(config) as (_, client):
        resource = await resource_read(client, "short.bin")
        assert resource.status_code == 200
        content = resource.json()["result"]["contents"][0]
        assert base64.b64decode(content["blob"]) == payload
        read = await file_tool(client, "read", path="short.bin", encoding="base64")
        assert read["ok"] is True
        assert read["size"] == len(payload)
        assert base64.b64decode(read["content"]) == payload


@pytest.mark.parametrize("transport", ["rest", "mcp"])
async def test_zero_quota_allows_large_artifacts_downloads_and_writes(
    tmp_path, transport
):
    payload = b"x" * (MIB + 1)
    script = (
        "import pathlib, sys; "
        "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1]); "
        f"(out / 'large.bin').write_bytes(b'x' * {len(payload)})"
    )
    config = quota_config(tmp_path, quota=0, script=script)
    async with running(config) as (_, client):
        if transport == "rest":
            response = await client.post(
                "/execute",
                headers=AUTH,
                json={"tool": "exporter", "argv": ["export", "example"]},
            )
            execution = response.json()
        else:
            response = await export(client)
            result = response.json()["result"]
            assert result["isError"] is False
            execution = result["structuredContent"]
            assert any(c["type"] == "resource_link" for c in result["content"])
        assert response.status_code == 200
        assert execution["ok"] is True
        assert len(execution["artifacts"]) == 1
        artifact = execution["artifacts"][0]
        assert artifact["size"] == len(payload)
        assert artifact["sha256"]
        download = await client.get(artifact["download_url"], headers=AUTH)
        assert download.status_code == 200
        assert download.content == payload

        # Disabling the on-disk quota does not disable the default 1 MiB
        # bound on data returned inside either form of MCP JSON result.
        resource = await resource_read(client, artifact["path"])
        assert "error" in resource.json()
        assert "blob" not in resource.text
        read = await file_tool(client, "read", path=artifact["path"])
        assert read["ok"] is False

        written = await file_tool(
            client, "write", path="uploaded.txt", content=payload.decode()
        )
        assert written["ok"] is True
        assert written["entry"]["size"] == len(payload)
        uploaded = await client.get(written["entry"]["download_url"], headers=AUTH)
        assert uploaded.content == payload


@pytest.mark.parametrize("quota,inline,limit", [(0, 8, 8), (16, 8, 8), (8, 16, 8)])
async def test_inline_reads_use_the_smaller_positive_limit(
    tmp_path, quota, inline, limit
):
    config = quota_config(tmp_path, quota=quota, inline=inline)
    root = tmp_path / "artifacts"
    (root / "allowed.txt").write_bytes(b"a" * limit)
    (root / "oversized.txt").write_bytes(b"b" * (limit + 1))
    async with running(config) as (_, client):
        allowed = await resource_read(client, "allowed.txt")
        assert base64.b64decode(allowed.json()["result"]["contents"][0]["blob"]) == (
            b"a" * limit
        )
        read = await file_tool(client, "read", path="allowed.txt")
        assert read["content"] == "a" * limit

        oversized = await resource_read(client, "oversized.txt")
        assert "error" in oversized.json()
        assert "blob" not in oversized.text
        read = await file_tool(client, "read", path="oversized.txt")
        assert read["ok"] is False
        download = await client.get(
            "/files/exporter/output/oversized.txt", headers=AUTH
        )
        if quota and quota <= limit:
            assert download.status_code == 413
        else:
            assert download.status_code == 200
            assert download.content == b"b" * (limit + 1)


async def test_positive_quota_still_limits_writes_downloads_and_capture(tmp_path):
    script = (
        "import pathlib, sys; "
        "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1]); "
        "(out / 'allowed.txt').write_text('12345678'); "
        "(out / 'oversized.txt').write_text('123456789')"
    )
    config = quota_config(tmp_path, quota=8, script=script)
    async with running(config) as (_, client):
        execution = (await export(client)).json()["result"]["structuredContent"]
        assert execution["ok"] is True
        assert [a["name"] for a in execution["artifacts"]] == ["allowed.txt"]
        allowed = execution["artifacts"][0]
        download = await client.get(allowed["download_url"], headers=AUTH)
        assert download.content == b"12345678"
        oversized_path = allowed["path"].replace("allowed.txt", "oversized.txt")
        oversized = await client.get(
            f"/files/exporter/output/{oversized_path}", headers=AUTH
        )
        assert oversized.status_code == 413
        assert "error" in (await resource_read(client, oversized_path)).json()
        read = await file_tool(client, "read", path=oversized_path)
        assert read["ok"] is False

        write = await file_tool(
            client, "write", path="uploaded.txt", content="12345678"
        )
        assert write["ok"] is True
        rejected = await file_tool(
            client, "write", path="uploaded.txt", content="123456789"
        )
        assert rejected["ok"] is False
        assert (tmp_path / "artifacts" / "uploaded.txt").read_bytes() == b"12345678"


@pytest.mark.parametrize(
    "quota,inline,limit", [(16, None, 16), (0, None, MIB), (0, 8, 8)]
)
def test_working_directory_shares_inherit_inline_limits(tmp_path, quota, inline, limit):
    config = quota_config(tmp_path, quota=quota, inline=inline)
    config.tools["exporter"].working_dir = str(tmp_path / "artifacts")
    config.tools["exporter"].file_sharing.expose_working_dir = True
    target = tmp_path / "artifacts" / "large.txt"
    target.write_bytes(b"x" * (limit + 1))
    service = FileShareService(config)
    share = service.get_share("exporter", "working_dir", ["export"])
    with pytest.raises(FileShareTooLarge):
        service.read_file(share, "large.txt")


async def test_zero_quota_bounds_a_resource_that_grows_after_fstat(
    tmp_path, monkeypatch
):
    config = quota_config(tmp_path, quota=0, inline=8)
    path = tmp_path / "artifacts" / "growing.bin"
    path.write_bytes(b"small")
    inode = path.stat().st_ino
    original_fstat = os.fstat
    original_fdopen = os.fdopen
    reads = []
    grew = False

    def grow_after_fstat(fd):
        nonlocal grew
        snapshot = original_fstat(fd)
        if snapshot.st_ino == inode and not grew:
            grew = True
            with path.open("ab") as stream:
                stream.write(b"x" * 100)
        return snapshot

    class ObservedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            assert 0 < size <= 9
            reads.append(size)
            return self.stream.read(size)

    def observe_fdopen(fd, *args, **kwargs):
        stream = original_fdopen(fd, *args, **kwargs)
        if original_fstat(fd).st_ino == inode:
            return ObservedReader(stream)
        return stream

    async with running(config) as (_, client):
        monkeypatch.setattr(os, "fstat", grow_after_fstat)
        monkeypatch.setattr(os, "fdopen", observe_fdopen)
        response = await resource_read(client, "growing.bin")
    assert grew
    assert reads
    assert "error" in response.json()
    assert "blob" not in response.text
