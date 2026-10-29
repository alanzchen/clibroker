"""API routes — the POST /execute endpoint."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import FileResponse

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

router = APIRouter()


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
    )


@router.get("/files/{tool}/{share}")
@router.get("/files/{tool}/{share}/{path:path}")
def get_shared_file(
    tool: str,
    share: str,
    request: Request,
    path: str = ".",
):
    """Serve an authenticated file or directory listing from a configured share."""

    authenticator: Authenticator = request.app.state.authenticator
    file_shares: FileShareService = request.app.state.file_share_service
    client: AuthenticatedClient = authenticator.authenticate(request)

    try:
        share_cfg = file_shares.get_share(tool, share, client.allow_rules)
        local_path, _ = file_shares.local_path_for_read(share_cfg, path)
        if local_path.is_dir():
            return file_shares.list_dir(share_cfg, path)
        if not local_path.is_file():
            raise FileShareError("Path is not a file or directory")
        return FileResponse(local_path)
    except FileShareError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
