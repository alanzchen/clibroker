"""Hardened async subprocess runner — never invokes a shell."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from dataclasses import dataclass

logger = logging.getLogger("clibroker.runner")
_CLEANUP_TIMEOUT_S = 5.0


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
    """Execute directly, retaining bounded output and owning the process lifetime.

    POSIX commands run in a separate session so timeout, cancellation, and normal
    completion also terminate children in the command's process group. A command
    deliberately starting another session requires an OS sandbox for containment.
    """
    t0 = time.monotonic()
    timed_out = False
    stdout = bytearray()
    stderr = bytearray()
    communication = None
    # Shield creation so cancellation cannot lose the handle between spawning a
    # process and receiving its Process object. Cleanup also owns this task.
    creation = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env if env is not None else {},
            cwd=cwd,
            start_new_session=os.name == "posix",
        )
    )
    try:
        proc = await asyncio.shield(creation)
        communication = asyncio.create_task(
            _communicate_capped(proc, max_output_bytes, stdout, stderr)
        )
        try:
            # Keep the same bounded readers alive during timeout cleanup; using
            # communicate() here would allocate unbounded output and lose prefixes.
            await asyncio.wait_for(asyncio.shield(communication), timeout_s)
        except asyncio.TimeoutError:
            timed_out = True
    finally:
        cleanup = asyncio.create_task(_cleanup(creation, communication))
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError

    elapsed_ms = (time.monotonic() - t0) * 1000.0
    return RunResult(
        exit_code=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
        duration_ms=round(elapsed_ms, 2),
        timed_out=timed_out,
    )


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    try:
        if os.name == "posix":
            # The leader may have exited while children still hold its pipes.
            os.killpg(proc.pid, signal.SIGKILL)
        elif proc.returncode is None:
            proc.kill()
    except ProcessLookupError:
        pass


async def _cleanup(creation, communication) -> None:
    try:
        proc = await creation
    except Exception:
        # Let execute propagate the original spawn error.
        return
    _kill_process_group(proc)
    draining = communication or asyncio.create_task(proc.wait())
    try:
        await asyncio.wait_for(asyncio.shield(draining), _CLEANUP_TIMEOUT_S)
    except asyncio.TimeoutError:
        logger.warning("Subprocess pipes remained open after process-group cleanup")
        # A descendant that deliberately escaped its session can retain the pipe.
        # Process has no public close API; close its transport to release our FDs.
        proc._transport.close()
        draining.cancel()
        await asyncio.gather(draining, return_exceptions=True)
        try:
            await asyncio.wait_for(proc.wait(), _CLEANUP_TIMEOUT_S)
        except asyncio.TimeoutError:
            logger.warning("Subprocess could not be reaped after cleanup")


async def _communicate_capped(
    proc: asyncio.subprocess.Process,
    max_bytes: int,
    stdout: bytearray,
    stderr: bytearray,
) -> None:
    """Drain both pipes continuously, retaining only each bounded prefix."""

    async def read(stream: asyncio.StreamReader | None, output: bytearray) -> None:
        if stream is None:
            return
        while chunk := await stream.read(8192):
            remaining = max_bytes - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])

    await asyncio.gather(read(proc.stdout, stdout), read(proc.stderr, stderr))
    await proc.wait()
