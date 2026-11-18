"""API routes — the POST /execute endpoint."""

from __future__ import annotations

import hashlib
import os
from typing import BinaryIO

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import FileResponse, StreamingResponse

from . import __version__
from .auth import AuthenticatedClient, Authenticator
from .execution import ExecutionForbidden, ExecutionService
from .file_sharing import FileShareError, FileShareService
from .models import (
    ClientArgvNormalizationSchema,
    ClientConfigResponse,
    ClientFileShareSchema,
    ClientGlobalArgPatternSchema,
    ClientPositionalSchema,
    ClientRuleSchema,
    ClientToolSchema,
    ExecuteRequest,
    ExecuteResponse,
)
from .thread_work import run_owned_thread

router = APIRouter()


class _OpenFileResponse(StreamingResponse):
    """Stream the validated descriptor, and close it even on disconnect."""

    def __init__(self, stream: BinaryIO, path: str, snapshot: os.stat_result):
        self.stream = stream

        def chunks():
            remaining = snapshot.st_size
            while remaining:
                chunk = stream.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

        # Let Starlette supply the standard MIME/stat headers without opening
        # the pathname a second time. Content reads use only the pinned fd.
        headers = dict(FileResponse(path, stat_result=snapshot).headers)
        headers.pop("accept-ranges", None)
        super().__init__(chunks(), headers=headers)

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.stream.close()


async def _open_download(file_shares, share_cfg, path):
    """Keep ownership until an opened file reaches the response or is closed."""
    opened_stream = None

    def open_file():
        nonlocal opened_stream
        result = file_shares.open_for_download(share_cfg, path)
        opened_stream = result[0]
        return result

    try:
        return await run_owned_thread(open_file)
    except BaseException:
        # The owned worker has completed even when cancellation arrived during
        # its open. No eventual result can escape this cleanup path.
        if opened_stream is not None:
            opened_stream.close()
        raise


def _token_slug(value: str) -> str:
    """Return the opaque token slug used by MCP/SSE URLs."""

    return hashlib.sha256(value.encode()).hexdigest()[:16]


@router.post("/execute", response_model=ExecuteResponse)
async def execute_command(body: ExecuteRequest, request: Request) -> ExecuteResponse:
    """Authenticate and execute through the shared REST/MCP pipeline."""
    authenticator: Authenticator = request.app.state.authenticator
    client = authenticator.authenticate(request)
    execution: ExecutionService = request.app.state.execution_service
    try:
        return await execution.execute(
            body.tool,
            body.argv,
            client=client.name,
            allowed_rules=client.allow_rules,
        )
    except ExecutionForbidden as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/client-config", response_model=ClientConfigResponse)
async def get_client_config(request: Request) -> ClientConfigResponse:
    """Return a token-scoped discovery document for the broker client."""

    authenticator: Authenticator = request.app.state.authenticator
    config = request.app.state.config
    file_shares: FileShareService = request.app.state.file_share_service
    client: AuthenticatedClient = authenticator.authenticate(request)

    token_value = request.headers.get("Authorization", "")[7:]
    slug = _token_slug(token_value)

    tools: list[ClientToolSchema] = []
    allowed_rule_ids = set(client.allow_rules)

    for tool_name, tool_cfg in config.tools.items():
        rules: list[ClientRuleSchema] = []
        for rule in tool_cfg.rules:
            if rule.effect != "allow" or rule.id not in allowed_rule_ids:
                continue

            rules.append(
                ClientRuleSchema(
                    id=rule.id,
                    title=rule.title,
                    description=rule.description,
                    decision=request.app.state.control.decision(client.name, rule)
                    if request.app.state.control
                    else "allow",
                    command=rule.command,
                    allow_any_args=rule.allow_any_args,
                    flags=rule.flags.allowed if rule.flags else [],
                    standalone_flags=rule.flags.standalone if rule.flags else [],
                    positionals=[
                        ClientPositionalSchema(
                            name=pos.name,
                            pattern=pos.pattern,
                            enum=pos.enum,
                            variadic=pos.variadic,
                        )
                        for pos in rule.positionals
                    ],
                )
            )

        client_file_shares = [
            ClientFileShareSchema.model_validate(share)
            for share in file_shares.get_client_shares(tool_name, allowed_rule_ids)
        ]

        argv_normalization = None
        if (
            tool_cfg.argv_normalization is not None
            and tool_cfg.argv_normalization.patterns
        ):
            argv_normalization = ClientArgvNormalizationSchema(
                patterns=[
                    ClientGlobalArgPatternSchema(
                        id=pattern.id,
                        kind=pattern.kind,
                        key_pattern=pattern.key_pattern,
                        value_pattern=pattern.value_pattern,
                        canonical_position=pattern.canonical_position,
                        allow_positions=list(pattern.allow_positions),
                        multiple=pattern.multiple,
                    )
                    for pattern in tool_cfg.argv_normalization.patterns
                ]
            )

        if rules or client_file_shares:
            tools.append(
                ClientToolSchema(
                    name=tool_name,
                    title=tool_cfg.title,
                    description=tool_cfg.description,
                    rules=rules,
                    file_shares=client_file_shares,
                    argv_normalization=argv_normalization,
                )
            )

    return ClientConfigResponse(
        version=__version__,
        client_name=client.name,
        execute_url="/execute",
        token_info_url="/token-info",
        mcp_url=f"/mcp/{slug}/",
        sse_url=f"/sse/{slug}/",
        tools=tools,
        control={"enabled": request.app.state.control is not None, "role": client.role},
    )


@router.get("/files/{tool}/{share}")
@router.get("/files/{tool}/{share}/{path:path}")
async def get_shared_file(
    tool: str,
    share: str,
    request: Request,
    path: str = ".",
):
    """Serve an authenticated file or directory listing from a configured share."""

    authenticator: Authenticator = request.app.state.authenticator
    file_shares: FileShareService = request.app.state.file_share_service
    client: AuthenticatedClient = authenticator.authenticate(request)

    if request.app.state.control:
        request.app.state.control.ensure_active(client.name)
    stream = None
    try:
        share_cfg = file_shares.get_share(tool, share, client.allow_rules)
        stream, rel_path, snapshot = await _open_download(file_shares, share_cfg, path)
        if stream is None:
            return await run_owned_thread(file_shares.list_dir, share_cfg, path)
        response = _OpenFileResponse(stream, rel_path, snapshot)
        stream = None  # The response now owns the descriptor.
        return response
    except FileShareError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    finally:
        if stream is not None:
            stream.close()
