"""API routes — the POST /execute endpoint."""

from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import FileResponse

from . import __version__
from .audit import get_audit_logger
from .auth import AuthenticatedClient, Authenticator
from .file_sharing import FileShareError, FileShareService
from .models import (
    ClientConfigResponse,
    ClientFileShareSchema,
    ClientPositionalSchema,
    ClientRuleSchema,
    ClientToolSchema,
    ExecuteRequest,
    ExecuteResponse,
)
from .policy import (
    PolicyDenied,
    PolicyEngine,
    PolicyNoMatch,
    PolicyValidationError,
)
from .runner import execute

router = APIRouter()


def _try_parse_json(s: str) -> str | dict | list:
    """Attempt to parse a string as JSON; return original string on failure."""
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return s


def _token_slug(value: str) -> str:
    """Return the opaque token slug used by MCP/SSE URLs."""

    return hashlib.sha256(value.encode()).hexdigest()[:16]


@router.post("/execute", response_model=ExecuteResponse)
async def execute_command(body: ExecuteRequest, request: Request) -> ExecuteResponse:
    """Execute a CLI command through the policy engine.

    Flow: authenticate -> policy evaluate -> execute subprocess -> respond.
    """
    log = get_audit_logger()
    authenticator: Authenticator = request.app.state.authenticator
    policy: PolicyEngine = request.app.state.policy

    # 1. Authenticate
    client: AuthenticatedClient = authenticator.authenticate(request)

    # 2. Policy evaluation
    try:
        result = policy.evaluate(body.tool, body.argv)
    except PolicyDenied as exc:
        log.warning(
            "policy_denied",
            client=client.name,
            tool=body.tool,
            argv=body.argv,
            rule=exc.rule_id,
        )
        return ExecuteResponse(
            ok=False,
            exit_code=-1,
            stdout="",
            stderr=str(exc),
            duration_ms=0,
            matched_rule=exc.rule_id,
        )
    except PolicyNoMatch:
        log.warning(
            "policy_no_match",
            client=client.name,
            tool=body.tool,
            argv=body.argv,
        )
        return ExecuteResponse(
            ok=False,
            exit_code=-1,
            stdout="",
            stderr=f"No matching policy rule for tool '{body.tool}' with argv {body.argv}",
            duration_ms=0,
            matched_rule="",
        )
    except PolicyValidationError as exc:
        log.warning(
            "policy_validation_error",
            client=client.name,
            tool=body.tool,
            argv=body.argv,
            rule=exc.rule_id,
            detail=exc.detail,
        )
        return ExecuteResponse(
            ok=False,
            exit_code=-1,
            stdout="",
            stderr=str(exc),
            duration_ms=0,
            matched_rule=exc.rule_id,
        )

    # 3. Authorize client for matched rule
    Authenticator.authorize(client, result.rule_id)

    # 4. Execute
    tool_cfg = result.tool_config
    run_result = await execute(
        result.full_argv,
        env=tool_cfg.env or None,
        cwd=tool_cfg.working_dir,
        timeout_s=tool_cfg.timeout_s,
        max_output_bytes=tool_cfg.max_output_bytes,
    )

    # 5. Audit log (post-execution)
    log.info(
        "command_executed",
        client=client.name,
        tool=body.tool,
        matched_rule=result.rule_id,
        argv=result.full_argv,
        exit_code=run_result.exit_code,
        duration_ms=run_result.duration_ms,
        timed_out=run_result.timed_out,
    )

    # 6. Build response
    return ExecuteResponse(
        ok=run_result.exit_code == 0 and not run_result.timed_out,
        exit_code=run_result.exit_code,
        stdout=_try_parse_json(run_result.stdout),
        stderr=run_result.stderr,
        duration_ms=run_result.duration_ms,
        matched_rule=result.rule_id,
        timed_out=run_result.timed_out,
    )


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

        if rules or client_file_shares:
            tools.append(
                ClientToolSchema(
                    name=tool_name,
                    rules=rules,
                    file_shares=client_file_shares,
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
