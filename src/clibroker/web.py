"""Serve the optional browser client; all data uses existing authenticated APIs."""

from pathlib import Path

from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope


class DashboardFiles(StaticFiles):
    """Static assets with a same-origin, script-only security policy."""

    def __init__(self) -> None:
        super().__init__(directory=Path(__file__).parent / "dashboard", html=True)

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers.update({
            "Content-Security-Policy": (
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'"
            ),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        })
        return response
