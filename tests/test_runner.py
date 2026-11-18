"""Tests for the hardened async subprocess runner."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from clibroker.runner import execute


class TestBasicExecution:
    """Test subprocess execution basics."""

    @pytest.mark.asyncio
    async def test_echo_stdout(self) -> None:
        result = await execute(
            [sys.executable, "-c", "print('hello world')"],
            timeout_s=5.0,
        )
        assert result.exit_code == 0
        assert "hello world" in result.stdout
        assert result.timed_out is False

    @pytest.mark.asyncio
    async def test_stderr_captured(self) -> None:
        result = await execute(
            [sys.executable, "-c", "import sys; sys.stderr.write('oops\\n')"],
            timeout_s=5.0,
        )
        assert "oops" in result.stderr

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self) -> None:
        result = await execute(
            [sys.executable, "-c", "raise SystemExit(42)"],
            timeout_s=5.0,
        )
        assert result.exit_code == 42

    @pytest.mark.asyncio
    async def test_duration_tracked(self) -> None:
        result = await execute(
            [sys.executable, "-c", "print('fast')"],
            timeout_s=5.0,
        )
        assert result.duration_ms > 0


class TestEnvironmentIsolation:
    """Test that environment is controlled."""

    @pytest.mark.asyncio
    async def test_empty_env_by_default(self) -> None:
        # The critical security property: parent env vars like PATH, HOME,
        # USER, etc. must NOT leak into the subprocess.
        result = await execute(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('PATH', 'ABSENT'))",
            ],
            timeout_s=5.0,
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "ABSENT"

    @pytest.mark.asyncio
    async def test_explicit_env_passed(self) -> None:
        result = await execute(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('MY_VAR', 'missing'))",
            ],
            env={"MY_VAR": "test_value"},
            timeout_s=5.0,
        )
        assert "test_value" in result.stdout


class TestTimeout:
    """Test process timeout and kill behavior."""

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self) -> None:
        result = await execute(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            timeout_s=1.0,
        )
        assert result.timed_out is True
        assert result.exit_code != 0  # killed


class TestOutputCapping:
    """Test that output is capped at max_output_bytes."""

    @pytest.mark.asyncio
    async def test_stdout_capped(self) -> None:
        # Generate 100KB of output, cap at 1KB
        result = await execute(
            [sys.executable, "-c", "print('A' * 100_000)"],
            timeout_s=5.0,
            max_output_bytes=1024,
        )
        assert result.exit_code == 0
        assert len(result.stdout.encode()) <= 1024 + 128  # small tolerance for encoding


class TestNoShellInvocation:
    """Verify that shell metacharacters have no effect."""

    @pytest.mark.asyncio
    async def test_shell_metacharacters_are_literal(self) -> None:
        # If this were passed through a shell, the semicolon would execute
        # the second command. With direct exec, it's just an argument.
        result = await execute(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", "hello; rm -rf /"],
            timeout_s=5.0,
        )
        assert result.exit_code == 0
        assert "hello; rm -rf /" in result.stdout


# These tests use real subprocesses: inherited output descriptors and descendants
# are precisely what mocking create_subprocess_exec would miss.
def process_tree_script(tmp_path: Path, *, parent_exits: bool = False) -> str:
    marker = tmp_path / "late-side-effect"
    pids = tmp_path / "descendants.json"
    grandchild = (
        "import pathlib,time; time.sleep(0.7); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped'); time.sleep(60)"
    )
    child = (
        "import json,os,pathlib,subprocess,time; "
        f"p=subprocess.Popen([{sys.executable!r},'-c',{grandchild!r}]); "
        f"pathlib.Path({str(pids)!r}).write_text(json.dumps([os.getpid(),p.pid])); "
        "time.sleep(60)"
    )
    return (
        "import subprocess,time; "
        f"subprocess.Popen([{sys.executable!r},'-c',{child!r}]); "
        + ("time.sleep(0.1)" if parent_exits else "time.sleep(60)")
    )


async def wait_for_path(path: Path) -> None:
    async with asyncio.timeout(5):
        while not path.exists():
            await asyncio.sleep(0.01)


def process_is_running(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat")
        if sys.platform == "linux":
            # A killed orphan may remain a zombie until the host init reaps it.
            return stat.exists() and stat.read_text().split(")", 1)[1].split()[0] != "Z"
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, FileNotFoundError):
        return False


async def assert_tree_stopped(tmp_path: Path) -> None:
    pids = json.loads((tmp_path / "descendants.json").read_text())
    async with asyncio.timeout(2):
        while any(process_is_running(pid) for pid in pids):
            await asyncio.sleep(0.01)
    await asyncio.sleep(0.8)
    assert not (tmp_path / "late-side-effect").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group lifetime")
@pytest.mark.parametrize("parent_exits", [False, True])
async def test_timeout_kills_child_and_grandchild_with_inherited_pipes(
    tmp_path, parent_exits
):
    task = asyncio.create_task(
        execute(
            [
                sys.executable,
                "-c",
                process_tree_script(tmp_path, parent_exits=parent_exits),
            ],
            timeout_s=0.3,
        )
    )
    await wait_for_path(tmp_path / "descendants.json")
    result = await asyncio.wait_for(task, 3)
    assert result.timed_out
    await assert_tree_stopped(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group lifetime")
async def test_cancellation_kills_child_and_grandchild(tmp_path):
    task = asyncio.create_task(
        execute([sys.executable, "-c", process_tree_script(tmp_path)], timeout_s=60)
    )
    await wait_for_path(tmp_path / "descendants.json")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    await assert_tree_stopped(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group lifetime")
async def test_normal_exit_terminates_background_children(tmp_path):
    child = (
        "import pathlib,time; time.sleep(0.7); "
        f"pathlib.Path({str(tmp_path / 'late-side-effect')!r}).write_text('escaped')"
    )
    parent = (
        "import pathlib,subprocess; "
        f"p=subprocess.Popen([{sys.executable!r},'-c',{child!r}], "
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        f"pathlib.Path({str(tmp_path / 'descendants.json')!r}).write_text('['+str(p.pid)+']')"
    )
    result = await execute([sys.executable, "-c", parent], timeout_s=5)
    assert result.exit_code == 0
    assert not result.timed_out
    await assert_tree_stopped(tmp_path)


async def test_timeout_keeps_bounded_stdout_and_stderr_prefixes():
    result = await execute(
        [
            sys.executable,
            "-c",
            "import os,time; "
            "os.write(1,b'out-prefix'+b'x'*100000); "
            "os.write(2,b'err-prefix'+b'y'*100000); time.sleep(60)",
        ],
        timeout_s=0.2,
        max_output_bytes=1024,
    )
    assert result.timed_out
    assert result.stdout.startswith("out-prefix")
    assert result.stderr.startswith("err-prefix")
    assert len(result.stdout) == len(result.stderr) == 1024


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group lifetime")
async def test_repeated_cancellation_waits_for_cleanup(tmp_path, monkeypatch):
    import clibroker.runner as runner

    original_cleanup = runner._cleanup
    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()

    async def delayed_cleanup(*args):
        cleanup_started.set()
        await release_cleanup.wait()
        await original_cleanup(*args)

    monkeypatch.setattr(runner, "_cleanup", delayed_cleanup)
    task = asyncio.create_task(
        execute([sys.executable, "-c", process_tree_script(tmp_path)], timeout_s=60)
    )
    await wait_for_path(tmp_path / "descendants.json")
    task.cancel()
    await cleanup_started.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release_cleanup.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    await assert_tree_stopped(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group lifetime")
async def test_cancellation_during_spawn_keeps_process_handle(tmp_path, monkeypatch):
    original_create = asyncio.create_subprocess_exec
    spawned = asyncio.Event()
    release_spawn = asyncio.Event()

    async def delayed_create(*args, **kwargs):
        proc = await original_create(*args, **kwargs)
        spawned.set()
        await release_spawn.wait()
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_create)
    task = asyncio.create_task(
        execute([sys.executable, "-c", process_tree_script(tmp_path)], timeout_s=60)
    )
    await spawned.wait()
    await wait_for_path(tmp_path / "descendants.json")
    task.cancel()
    release_spawn.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    await assert_tree_stopped(tmp_path)
