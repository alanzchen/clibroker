"""MCP disk operations remain owned until their worker threads have finished."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import threading

import httpx
import pytest
from asgi_lifespan import LifespanManager

from clibroker.app import create_app
from clibroker.config import Config
from clibroker.execution import ExecutionProgress, execution_progress
from clibroker.mcp_server import _owned_file_handler
from clibroker.thread_work import run_owned_thread

TOKEN = "file-lifecycle-token"
SLUG = hashlib.sha256(TOKEN.encode()).hexdigest()[:16]


def file_app(tmp_path):
    return create_app(
        Config.model_validate(
            {
                "server": {
                    "request_timeout_s": 0.2,
                    "auth": {
                        "tokens": [
                            {
                                "name": "agent",
                                "value": TOKEN,
                                "allow_rules": ["run"],
                            }
                        ]
                    },
                },
                "tools": {
                    "demo": {
                        "executable": "/usr/bin/echo",
                        "file_sharing": {
                            "expose_working_dir": False,
                            "shares": [
                                {
                                    "name": "data",
                                    "path": str(tmp_path),
                                    "access": "read_write",
                                }
                            ],
                        },
                        "rules": [{"id": "run", "command": ["run"]}],
                    }
                },
            }
        )
    )


async def wait_for_cancellation(progress):
    async with asyncio.timeout(3):
        while not any(task.cancelling() for task in progress.tasks):
            await asyncio.sleep(0.005)


async def test_mcp_timeout_waits_for_a_started_file_write(tmp_path, monkeypatch):
    app = file_app(tmp_path)
    files = app.state.file_share_service
    original = files.write_file
    started = asyncio.Event()
    release = threading.Event()
    progress = []
    marker = tmp_path / "result.txt"
    at_response = []
    loop = asyncio.get_running_loop()

    def delayed_write(*args, **kwargs):
        progress.append(execution_progress.get())
        loop.call_soon_threadsafe(started.set)
        assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(files, "write_file", delayed_write)

    async def observed(scope, receive, send):
        async def capture(message):
            if message["type"] == "http.response.start":
                at_response.append((message["status"], marker.exists()))
            await send(message)

        await app(scope, receive, capture)

    async with (
        LifespanManager(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=observed),
            base_url="http://localhost:8000",
        ) as client,
    ):
        request = asyncio.create_task(
            client.post(
                f"/mcp/{SLUG}/",
                headers={"Accept": "application/json, text/event-stream"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "demo__files_write",
                        "arguments": {
                            "share": "data",
                            "path": marker.name,
                            "content": "written",
                        },
                    },
                },
            )
        )
        try:
            await asyncio.wait_for(started.wait(), 3)
            assert progress[0] is not None
            await wait_for_cancellation(progress[0])
            assert not request.done()
            assert not marker.exists()
        finally:
            release.set()
        response = await asyncio.wait_for(request, 3)

    assert response.status_code == 504
    assert response.json()["request_timed_out"] is True
    assert response.json()["request_id"] is None
    assert "Do not automatically retry" in response.json()["stderr"]
    # A running disk write cannot be rolled back. It must have finished before
    # the timeout response, rather than mutating the share after the caller returns.
    assert at_response == [(504, True)]
    assert marker.read_text() == "written"


async def test_repeated_cancellation_waits_for_file_operation(tmp_path):
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    marker = tmp_path / "completed"

    def write(path: str, content: str = "done") -> str:
        loop.call_soon_threadsafe(started.set)
        assert release.wait(3)
        marker.write_text(content)
        return path

    owned = _owned_file_handler(write)
    assert inspect.signature(owned) == inspect.signature(write)
    progress = ExecutionProgress()
    context_token = execution_progress.set(progress)
    try:
        task = asyncio.create_task(owned(marker.name))
        await asyncio.wait_for(started.wait(), 3)
        assert task in progress.tasks
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert not marker.exists()
    finally:
        release.set()
        execution_progress.reset(context_token)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    assert marker.read_text() == "done"


async def test_cancelled_worker_error_does_not_replace_cancellation():
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()

    def fail():
        loop.call_soon_threadsafe(started.set)
        assert release.wait(3)
        raise OSError("disk failed after cancellation")

    task = asyncio.create_task(run_owned_thread(fail))
    try:
        await asyncio.wait_for(started.wait(), 3)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)


async def test_cancelling_all_operation_tasks_does_not_detach_the_thread(tmp_path):
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    marker = tmp_path / "completed-during-shutdown"

    def write():
        loop.call_soon_threadsafe(started.set)
        assert release.wait(3)
        marker.write_text("done")

    existing = asyncio.all_tasks()
    task = asyncio.create_task(run_owned_thread(write))
    try:
        await asyncio.wait_for(started.wait(), 3)
        # asyncio.run shutdown cancels every Task, including any nested
        # to_thread Task; the actual blocking operation must remain owned.
        for pending in asyncio.all_tasks() - existing:
            pending.cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not task.done()
        assert not marker.exists()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    assert marker.read_text() == "done"


def test_file_tool_schemas_retain_original_parameters(tmp_path):
    app = file_app(tmp_path)
    tools = app.state.mcp_servers[SLUG]["mcp"]._tool_manager._tools
    schema = tools["demo__files_write"].parameters
    assert set(schema["properties"]) == {
        "share",
        "path",
        "content",
        "encoding",
        "overwrite",
    }
    assert set(schema["required"]) == {"share", "path", "content"}
    assert schema["properties"]["encoding"]["default"] == "utf-8"
    assert schema["properties"]["overwrite"]["default"] is True
    assert all(
        inspect.iscoroutinefunction(tool.fn)
        for name, tool in tools.items()
        if name.startswith("demo__files_")
    )
