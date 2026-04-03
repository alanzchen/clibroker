"""Tests for the hardened async subprocess runner."""

from __future__ import annotations

import sys

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
