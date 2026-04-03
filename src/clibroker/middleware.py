"""Request-level timeout middleware."""

from __future__ import annotations

import asyncio

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse


class TimeoutMiddleware(BaseHTTPMiddleware):
    """Enforce a request-level timeout on the entire request lifecycle."""

    def __init__(self, app, timeout_s: float = 30.0) -> None:  # noqa: ANN001
        super().__init__(app)
        self.timeout_s = timeout_s

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        try:
            return await asyncio.wait_for(call_next(request), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={
                    "ok": False,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Request timed out after {self.timeout_s}s",
                    "duration_ms": 0,
                    "matched_rule": "",
                    "timed_out": True,
                },
            )
