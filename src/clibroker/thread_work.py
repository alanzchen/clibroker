"""Keep a blocking operation owned until its worker thread has finished."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextvars import copy_context
from functools import partial
from typing import Any, TypeVar

_Result = TypeVar("_Result")


async def run_owned_thread(
    function: Callable[..., _Result], /, *args: Any, **kwargs: Any
) -> _Result:
    """Defer cancellation until the blocking operation can no longer mutate state.

    Cancelling an await cannot stop a running Python thread. Keep the worker
    shielded through repeated cancellation, retrieve its outcome, then propagate
    cancellation. Callers that open resources retain responsibility for disposing
    their result when cancellation prevents transferring ownership to the caller.
    """
    # Match to_thread's context propagation, but own the executor Future directly.
    # A nested asyncio Task would itself be cancelled during loop shutdown and
    # could lose ownership of a thread that was already running.
    worker = asyncio.get_running_loop().run_in_executor(
        None, copy_context().run, partial(function, *args, **kwargs)
    )
    cancelled = False
    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            # Retrieve the exception below, after considering deferred cancellation.
            break

    if cancelled:
        if not worker.cancelled():
            worker.exception()
        raise asyncio.CancelledError
    return worker.result()
