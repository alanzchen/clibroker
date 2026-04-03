"""FastAPI application factory."""

from __future__ import annotations

import hashlib
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

from .audit import configure_logging
from .auth import Authenticator
from .config import Config
from .mcp_server import create_mcp_server
from .middleware import TimeoutMiddleware
from .policy import PolicyEngine
from .routes import router


def _token_slug(value: str) -> str:
    """Derive a short, opaque, URL-safe slug from a token value.

    Uses the first 16 hex characters of the SHA-256 hash.  This is
    placed in the URL path instead of the raw secret so that the
    plaintext token never appears in access logs, Referer headers,
    browser history, or APM dashboards.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def create_app(config: Config) -> FastAPI:
    """Build and return the configured FastAPI application.

    Mounts:
        POST /execute              — REST API (bearer-auth + RBAC)
        POST /mcp/{slug}/         — MCP streamable HTTP transport (per-token)
        GET  /sse/{slug}/         — MCP SSE transport (per-token)

    Each configured bearer token gets its own MCP server instance that only
    exposes the tools the token is authorized for (RBAC at the MCP layer).

    Token slugs are derived from SHA-256(token)[:16] so that plaintext
    secrets never appear in URLs.  Callers discover their slug via
    ``GET /token-info`` (authenticated) or from documentation/config.

    Requests to /mcp/ or /sse/ without a valid slug receive 401.
    """
    configure_logging()

    policy = PolicyEngine(config)

    # --- Per-token MCP servers ---
    # Map slug -> {mcp, streamable, sse, name}
    mcp_servers: dict[str, dict] = {}

    for token_cfg in config.server.auth.tokens:
        resolved_token = token_cfg.resolve_value()
        slug = _token_slug(resolved_token)
        allowed = set(token_cfg.allow_rules)

        mcp_server = create_mcp_server(config, policy, allowed_rules=allowed)
        streamable_app = mcp_server.streamable_http_app()
        sse_app = mcp_server.sse_app()

        mcp_servers[slug] = {
            "mcp": mcp_server,
            "streamable": streamable_app,
            "sse": sse_app,
            "name": token_cfg.name,
        }

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ARG001
        async with AsyncExitStack() as stack:
            for entry in mcp_servers.values():
                await stack.enter_async_context(entry["mcp"].session_manager.run())
            yield

    app = FastAPI(
        title="clibroker",
        description="Policy-driven CLI command broker",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Attach shared state
    app.state.config = config
    app.state.policy = policy
    app.state.authenticator = Authenticator(config)
    app.state.mcp_servers = mcp_servers

    # Middleware (outermost first)
    app.add_middleware(TimeoutMiddleware, timeout_s=config.server.request_timeout_s)

    # REST API routes (matched before mounts)
    app.include_router(router)

    # Mount per-token MCP endpoints using opaque slug (not raw token)
    for slug, entry in mcp_servers.items():
        app.mount(f"/mcp/{slug}", entry["streamable"])
        app.mount(f"/sse/{slug}", entry["sse"])

    # Catch-all for unauthenticated /mcp and /sse access.
    # These must be added AFTER the per-token mounts so Starlette tries
    # the specific slug paths first.
    @app.api_route(
        "/mcp/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
    )
    async def mcp_unauthorized(request: Request, path: str = "") -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized: valid token required in URL path"},
        )

    @app.api_route(
        "/sse/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
    )
    async def sse_unauthorized(request: Request, path: str = "") -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized: valid token required in URL path"},
        )

    # Health endpoint (unauthenticated — no secrets exposed)
    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.1.0"}

    # Token info endpoint — authenticated clients can discover their slug
    @app.get("/token-info")
    async def token_info(request: Request) -> dict:
        authenticator: Authenticator = request.app.state.authenticator
        client = authenticator.authenticate(request)
        # Re-derive slug from the token in the request
        token_value = request.headers.get("Authorization", "")[7:]
        slug = _token_slug(token_value)
        return {
            "name": client.name,
            "slug": slug,
            "mcp_url": f"/mcp/{slug}/",
            "sse_url": f"/sse/{slug}/",
            "allow_rules": client.allow_rules,
        }

    return app
