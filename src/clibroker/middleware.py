"""Own request cancellation until response headers have been sent."""

from __future__ import annotations

import asyncio

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .execution import ExecutionProgress, execution_error, execution_progress


class TimeoutMiddleware:
    """Cancel and await work before returning a pre-response timeout.

    Streaming responses retain their own lifecycle once their headers are sent.
    A request deadline cannot roll back side effects that already happened.
    """

    def __init__(self, app: ASGIApp, timeout_s: float = 30.0) -> None:
        self.app = app
        self.timeout_s = timeout_s

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        progress = ExecutionProgress()
        token = execution_progress.set(progress)
        headers_sent = asyncio.get_running_loop().create_future()

        async def observed_send(message):
            if message["type"] == "http.response.start" and not headers_sent.done():
                headers_sent.set_result(None)
            await send(message)

        app_task = asyncio.create_task(self.app(scope, receive, observed_send))
        try:
            done, _ = await asyncio.wait(
                (app_task, headers_sent),
                timeout=self.timeout_s,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if done or headers_sent.done():
                await app_task
                return

            await self._cancel_work(app_task, progress)
            # Completion may have been recorded before response serialization.
            result = progress.result or execution_error(
                "Request deadline exceeded. Execution was interrupted and its "
                "external outcome may be unknown. Do not automatically retry."
            ).model_copy(
                update={
                    "request_id": progress.request_id,
                    "state": "interrupted" if progress.request_id else None,
                }
            )
            result = result.model_copy(update={"request_timed_out": True})
            response = JSONResponse(
                status_code=504,
                content=result.model_dump(mode="json"),
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
        except asyncio.CancelledError:
            await self._cancel_work(app_task, progress)
            raise
        finally:
            if not headers_sent.done():
                headers_sent.cancel()
            execution_progress.reset(token)

    @staticmethod
    async def _cancel_work(app_task: asyncio.Task, progress: ExecutionProgress) -> None:
        # SDK transports may dispatch a command outside the ASGI handler task.
        # Wait for process cleanup and the saved outcome before responding.
        tasks = {app_task, *progress.tasks}
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
