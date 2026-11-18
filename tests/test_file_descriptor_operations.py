"""File operations use pinned descriptors across concurrent path replacements."""

from __future__ import annotations

import errno
import os

import pytest
from httpx import ASGITransport, AsyncClient

import clibroker.file_sharing as sharing
import clibroker.routes as routes
from clibroker.app import create_app
from clibroker.file_sharing import (
    FileShareConflict,
    FileShareError,
    FileShareForbidden,
    FileShareService,
)
from tests.test_file_sharing import READER_TOKEN, make_file_config


@pytest.mark.parametrize("replacement", ["file", "directory", "root_ancestor"])
async def test_download_rejects_symlink_replacement_before_open(
    tmp_path, monkeypatch, replacement
):
    host = tmp_path / "host"
    host.mkdir()
    config, paths = make_file_config(host)
    outside = tmp_path / "outside"
    outside.mkdir()
    if replacement == "file":
        original = paths["docs"] / "readme.txt"
        destination = outside / "readme.txt"
        destination.write_text("OUTSIDE-SECRET")
    elif replacement == "directory":
        original = paths["docs"]
        destination = outside
        (outside / "readme.txt").write_text("OUTSIDE-SECRET")
    else:
        original = host
        destination = outside
        (outside / "docs").mkdir()
        (outside / "docs" / "readme.txt").write_text("OUTSIDE-SECRET")
    real_open = os.open
    swapped = False

    def swap(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == original.name and dir_fd is not None and not swapped:
            original.rename(tmp_path / "saved")
            original.symlink_to(destination)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    app = create_app(config)
    monkeypatch.setattr(os, "open", swap)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/files/himalaya/docs/readme.txt",
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
    assert swapped
    assert response.status_code == 403
    assert "OUTSIDE-SECRET" not in response.text


async def test_download_keeps_open_file_after_path_changes_and_closes_it(
    tmp_path, monkeypatch
):
    config, paths = make_file_config(tmp_path)
    target = paths["docs"] / "readme.txt"
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE-SECRET")
    original_call = routes._OpenFileResponse.__call__
    streams = []

    async def swap_after_open(self, scope, receive, send):
        streams.append(self.stream)
        target.unlink()
        target.symlink_to(outside)
        return await original_call(self, scope, receive, send)

    monkeypatch.setattr(routes._OpenFileResponse, "__call__", swap_after_open)
    app = create_app(config)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/files/himalaya/docs/readme.txt",
            headers={"Authorization": f"Bearer {READER_TOKEN}"},
        )
    assert response.status_code == 200
    assert response.text == "hello"
    assert response.headers["content-length"] == "5"
    assert streams and all(stream.closed for stream in streams)


@pytest.mark.parametrize(
    "operation",
    ["write", "mkdir", "move", "delete", "recursive_delete", "artifact_dir"],
)
def test_mutations_reject_parent_symlink_swap(tmp_path, monkeypatch, operation):
    config, paths = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "rw", ["list_messages"])
    parent = paths["rw"] / "nested"
    parent.mkdir()
    (parent / "item.txt").write_text("inside")
    (parent / "deep").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "item.txt").write_text("outside")
    (outside / "deep").mkdir()
    (outside / "deep" / "keep.txt").write_text("keep")
    real_open = os.open
    swapped = False

    def swap(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == parent.name and dir_fd is not None and not swapped:
            parent.rename(paths["rw"] / "saved")
            parent.symlink_to(outside)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    operations = {
        "write": lambda: service.write_file(share, "nested/item.txt", "changed"),
        "mkdir": lambda: service.mkdir(share, "nested/new/sub"),
        "move": lambda: service.move(
            share, "nested/item.txt", "nested/moved.txt", overwrite=True
        ),
        "delete": lambda: service.delete(share, "nested/item.txt"),
        "recursive_delete": lambda: service.delete(
            share, "nested/deep", recursive=True
        ),
        "artifact_dir": lambda: service.prepare_artifact_dir(
            share, "nested/new/execution"
        ),
    }
    monkeypatch.setattr(os, "open", swap)
    with pytest.raises(FileShareForbidden):
        operations[operation]()
    assert swapped
    assert (outside / "item.txt").read_text() == "outside"
    assert (outside / "deep" / "keep.txt").read_text() == "keep"
    assert not (outside / "new").exists()
    assert not (outside / "moved.txt").exists()


def test_write_never_follows_replacement_leaf_and_preserves_in_share_symlinks(
    tmp_path, monkeypatch
):
    config, paths = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "rw", ["list_messages"])
    target = paths["rw"] / "old.txt"
    alias = paths["rw"] / "alias.txt"
    alias.symlink_to(target)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    real_replace = os.replace

    def replace_after_swap(source, destination, *, src_dir_fd=None, dst_dir_fd=None):
        target.unlink()
        target.symlink_to(outside)
        return real_replace(
            source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
        )

    monkeypatch.setattr(os, "replace", replace_after_swap)
    result = service.write_file(share, "alias.txt", "updated")
    assert result["ok"]
    assert alias.is_symlink()
    assert alias.read_text() == "updated"
    assert outside.read_text() == "outside"


def test_failed_write_preserves_existing_contents_and_cleans_stage(
    tmp_path, monkeypatch
):
    config, paths = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "rw", ["list_messages"])

    def fail(*args, **kwargs):
        raise OSError(errno.EIO, "simulated commit failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(FileShareError):
        service.write_file(share, "old.txt", "replacement")
    assert (paths["rw"] / "old.txt").read_text() == "old"
    assert list(paths["rw"].glob(".clibroker-*.tmp")) == []


@pytest.mark.parametrize("operation", ["write", "move"])
def test_no_overwrite_is_atomic_against_concurrent_creation(
    tmp_path, monkeypatch, operation
):
    config, paths = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "rw", ["list_messages"])
    real_rename = sharing._rename_noreplace

    def create_before_rename(source_fd, source, destination_fd, destination):
        (paths["rw"] / destination).write_text("concurrent")
        return real_rename(source_fd, source, destination_fd, destination)

    monkeypatch.setattr(sharing, "_rename_noreplace", create_before_rename)
    with pytest.raises(FileShareConflict):
        if operation == "write":
            service.write_file(share, "target.txt", "replacement", overwrite=False)
        else:
            service.move(share, "old.txt", "target.txt")
    assert (paths["rw"] / "target.txt").read_text() == "concurrent"
    assert (paths["rw"] / "old.txt").read_text() == "old"
    assert list(paths["rw"].glob(".clibroker-*.tmp")) == []


def test_move_same_path_is_non_destructive_and_failed_replace_preserves_destination(
    tmp_path, monkeypatch
):
    config, paths = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "rw", ["list_messages"])
    service.move(share, "old.txt", "old.txt", overwrite=True)
    assert (paths["rw"] / "old.txt").read_text() == "old"
    (paths["rw"] / "target.txt").write_text("destination")

    def fail(*args, **kwargs):
        raise OSError(errno.EXDEV, "simulated cross-device error")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(FileShareError):
        service.move(share, "old.txt", "target.txt", overwrite=True)
    assert (paths["rw"] / "old.txt").read_text() == "old"
    assert (paths["rw"] / "target.txt").read_text() == "destination"


def test_replacing_configured_root_cannot_redefine_authorized_directory(tmp_path):
    config, paths = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "docs", ["list_messages"])
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "readme.txt").write_text("OUTSIDE-SECRET")
    paths["docs"].rename(tmp_path / "saved-docs")
    paths["docs"].symlink_to(outside)
    with pytest.raises(FileShareForbidden):
        service.read_file(share, "readme.txt")
    with pytest.raises(FileShareForbidden):
        service.open_for_download(share, "readme.txt")


@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="Linux descriptor traversal")
def test_reads_allow_execute_only_ancestors(tmp_path):
    config, paths = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "docs", ["list_messages"])
    tmp_path.chmod(0o111)
    try:
        assert service.read_file(share, "readme.txt")["content"] == "hello"
        stream, _, _ = service.open_for_download(share, "readme.txt")
        with stream:
            assert stream.read() == b"hello"
    finally:
        tmp_path.chmod(0o700)


async def test_request_deadline_waits_for_delayed_open_and_closes_undispatched_file(
    tmp_path, monkeypatch
):
    import asyncio
    import threading

    config, _ = make_file_config(tmp_path)
    config.server.request_timeout_s = 0.03
    app = create_app(config)
    service = app.state.file_share_service
    real_open = service.open_for_download
    opened = threading.Event()
    release = threading.Event()
    streams = []

    def delayed_open(*args, **kwargs):
        result = real_open(*args, **kwargs)
        streams.append(result[0])
        opened.set()
        assert release.wait(timeout=3)
        return result

    monkeypatch.setattr(service, "open_for_download", delayed_open)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        request = asyncio.create_task(
            client.get(
                "/files/himalaya/docs/readme.txt",
                headers={"Authorization": f"Bearer {READER_TOKEN}"},
            )
        )
        try:
            assert await asyncio.to_thread(opened.wait, 1)
            await asyncio.sleep(0.08)
            assert not request.done()  # The request still owns the worker.
        finally:
            release.set()
        response = await request
    assert response.status_code == 504
    assert streams and all(stream.closed for stream in streams)


async def test_repeated_cancellation_closes_file_returned_by_pending_opener(
    tmp_path, monkeypatch
):
    import asyncio
    import threading

    config, _ = make_file_config(tmp_path)
    service = FileShareService(config)
    share = service.get_share("himalaya", "docs", ["list_messages"])
    real_open = service.open_for_download
    opened = threading.Event()
    release = threading.Event()
    streams = []

    def delayed_open(*args, **kwargs):
        result = real_open(*args, **kwargs)
        streams.append(result[0])
        opened.set()
        assert release.wait(timeout=3)
        return result

    monkeypatch.setattr(service, "open_for_download", delayed_open)
    task = asyncio.create_task(routes._open_download(service, share, "readme.txt"))
    try:
        assert await asyncio.to_thread(opened.wait, 1)
        task.cancel()
        await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert streams and all(stream.closed for stream in streams)
