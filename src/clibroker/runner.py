"""Hardened async subprocess runner — never invokes a shell."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger("clibroker.runner")


@dataclass
class RunResult:
    """Result of a subprocess execution."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False


async def execute(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout_s: float = 30.0,
    max_output_bytes: int = 1_048_576,
) -> RunResult:
    """Execute a command directly (no shell) with hardened constraints.

    - Uses asyncio.create_subprocess_exec: each argv element is passed
      directly to execvp, preventing shell metacharacter injection.
    - Clears the environment unless explicit env dict is provided.
    - Enforces a timeout; kills the process if exceeded.
    - Caps stdout/stderr to max_output_bytes.
    """
    t0 = time.monotonic()
    timed_out = False

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env if env is not None else {},  # empty env if None
        cwd=cwd,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            _communicate_capped(proc, max_output_bytes),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        # Drain whatever output is available
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=5.0
            )
            stdout_bytes = stdout_bytes[:max_output_bytes]
            stderr_bytes = stderr_bytes[:max_output_bytes]
        except asyncio.TimeoutError:
            stdout_bytes = b""
            stderr_bytes = b"<process did not exit after kill>"
        # Ensure the process is reaped
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass

    elapsed_ms = (time.monotonic() - t0) * 1000.0

    return RunResult(
        exit_code=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        duration_ms=round(elapsed_ms, 2),
        timed_out=timed_out,
    )


async def _communicate_capped(
    proc: asyncio.subprocess.Process,
    max_bytes: int,
) -> tuple[bytes, bytes]:
    """Read stdout and stderr concurrently, capping each at max_bytes."""

    async def _read_capped(stream: asyncio.StreamReader | None) -> bytes:
        if stream is None:
            return b""
        chunks: list[bytes] = []
        total = 0
        while total < max_bytes:
            chunk = await stream.read(min(8192, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        # Drain remaining so the process doesn't block on a full pipe
        if stream.at_eof() is False:
            try:
                while True:
                    leftover = await stream.read(8192)
                    if not leftover:
                        break
            except Exception:
                logger.debug("Exception draining subprocess output", exc_info=True)
        return b"".join(chunks)

    stdout_bytes, stderr_bytes = await asyncio.gather(
        _read_capped(proc.stdout),
        _read_capped(proc.stderr),
    )

    await proc.wait()
    return stdout_bytes, stderr_bytes
