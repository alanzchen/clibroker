"""Artifact reads keep containment when files change after path validation."""

from __future__ import annotations

import base64
import os

import pytest

from tests.test_mcp_artifacts import make_artifact_config, rpc, running


@pytest.mark.parametrize("replacement", ["file", "directory", "root_ancestor"])
async def test_resource_read_rejects_replacement_symlink(
    tmp_path, monkeypatch, replacement
):
    host = tmp_path / "host"
    host.mkdir()
    config = make_artifact_config(host)
    directory = host / "artifacts" / "nested"
    directory.mkdir()
    target = directory / "note.txt"
    target.write_bytes(b"safe")
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = b"OUTSIDE-ROOT-SECRET"

    if replacement == "file":
        original = target
        destination = outside / "note.txt"
        destination.write_bytes(secret)
    elif replacement == "directory":
        original = directory
        destination = outside
        (destination / "note.txt").write_bytes(secret)
    else:
        original = host
        destination = outside
        (destination / "artifacts" / "nested").mkdir(parents=True)
        (destination / "artifacts" / "nested" / "note.txt").write_bytes(secret)

    original_open = os.open
    replaced = False

    def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if path == original.name and dir_fd is not None and not replaced:
            original.rename(tmp_path / "saved")
            original.symlink_to(destination)
            replaced = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    async with running(config) as (_, client):
        monkeypatch.setattr(os, "open", replace_before_open)
        response = await rpc(
            client,
            "resources/read",
            {"uri": "clibroker://artifacts/exporter/output/nested/note.txt"},
        )
    assert replaced
    assert "error" in response.json()
    assert "blob" not in response.text
    assert secret.decode() not in response.text
    assert base64.b64encode(secret).decode() not in response.text


async def test_resource_read_rejects_replacement_fifo_without_blocking(
    tmp_path, monkeypatch
):
    config = make_artifact_config(tmp_path)
    target = tmp_path / "artifacts" / "note.txt"
    target.write_bytes(b"safe")
    original_open = os.open
    replaced = False

    def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if path == target.name and dir_fd is not None:
            # Fail immediately if a regression would block opening the FIFO.
            assert flags & os.O_NONBLOCK
            target.unlink()
            os.mkfifo(target)
            replaced = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    async with running(config) as (_, client):
        monkeypatch.setattr(os, "open", replace_before_open)
        response = await rpc(
            client,
            "resources/read",
            {"uri": "clibroker://artifacts/exporter/output/note.txt"},
        )
    assert replaced
    assert "error" in response.json()
    assert "not a file" in response.text


async def test_resource_read_preserves_contained_symlinks(tmp_path):
    config = make_artifact_config(tmp_path)
    root = tmp_path / "artifacts"
    (root / "nested").mkdir()
    expected = b"inside the share"
    (root / "nested" / "note.txt").write_bytes(expected)
    (root / "file-link.txt").symlink_to(root / "nested" / "note.txt")
    (root / "directory-link").symlink_to(root / "nested")
    async with running(config) as (_, client):
        for path in ("file-link.txt", "directory-link/note.txt"):
            response = await rpc(
                client,
                "resources/read",
                {"uri": f"clibroker://artifacts/exporter/output/{path}"},
            )
            contents = response.json()["result"]["contents"]
            assert base64.b64decode(contents[0]["blob"]) == expected


async def test_resource_read_follows_configured_root_symlink(tmp_path):
    config = make_artifact_config(tmp_path)
    root = tmp_path / "artifacts"
    real_root = tmp_path / "real-artifacts"
    root.rename(real_root)
    root.symlink_to(real_root)
    expected = b"configured root"
    (real_root / "note.txt").write_bytes(expected)
    async with running(config) as (_, client):
        response = await rpc(
            client,
            "resources/read",
            {"uri": "clibroker://artifacts/exporter/output/note.txt"},
        )
    contents = response.json()["result"]["contents"]
    assert base64.b64decode(contents[0]["blob"]) == expected
