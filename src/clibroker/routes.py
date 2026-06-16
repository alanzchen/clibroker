"""API routes — the POST /execute endpoint."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import FileResponse

from . import __version__
from .audit import get_audit_logger
from .auth import AuthenticatedClient, Authenticator
from .file_sharing import FileShareError, FileShareService
from .models import (
    ClientArgvNormalizationSchema,
    ClientGlobalArgPatternSchema,
    ClientConfigResponse,
    ClientFileShareSchema,
    ClientPositionalSchema,
    ClientRuleSchema,
    ClientToolSchema,
    ExecuteArtifactSchema,
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


def _expand_artifact_arg(arg: str, context: dict[str, str]) -> str:
    """Expand server-controlled artifact placeholders without formatting user argv."""

    return (
        arg.replace("{execution_id}", context["execution_id"])
        .replace("{artifact_dir}", context["artifact_dir"])
        .replace("{artifact_rel_dir}", context["artifact_rel_dir"])
    )


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

    # 4. Prepare per-execution artifact capture when configured
    file_shares: FileShareService = request.app.state.file_share_service
    artifact_context: dict[str, str] = {}
    artifact_share = None
    artifact_rel_dir = None

    if result.rule.artifact_capture is not None:
        execution_id = uuid.uuid4().hex
        capture = result.rule.artifact_capture
        try:
            artifact_share = file_shares.get_share(
                body.tool,
                capture.share,
                client.allow_rules,
            )
            artifact_rel_dir = capture.path_template.format(
                execution_id=execution_id
            )
            artifact_dir, artifact_rel_dir = file_shares.prepare_artifact_dir(
                artifact_share,
                artifact_rel_dir,
            )
            artifact_context = {
                "execution_id": execution_id,
                "artifact_dir": str(artifact_dir),
                "artifact_rel_dir": artifact_rel_dir,
            }
        except FileShareError as exc:
            log.warning(
                "artifact_prep_failed",
                client=client.name,
                tool=body.tool,
                matched_rule=result.rule_id,
                detail=str(exc),
            )
            return ExecuteResponse(
                ok=False,
                exit_code=-1,
                stdout="",
                stderr=f"Failed to prepare artifact directory: {exc}",
                duration_ms=0,
                matched_rule=result.rule_id,
            )

    full_argv = [
        _expand_artifact_arg(arg, artifact_context) if artifact_context else arg
        for arg in result.full_argv
    ]

    # 5. Execute
    tool_cfg = result.tool_config
    run_result = await execute(
        full_argv,
        env=tool_cfg.env or None,
        cwd=tool_cfg.working_dir,
        timeout_s=tool_cfg.timeout_s,
        max_output_bytes=tool_cfg.max_output_bytes,
    )

    # 6. Audit log (post-execution)
    log.info(
        "command_executed",
        client=client.name,
        tool=body.tool,
        matched_rule=result.rule_id,
        argv=full_argv,
        exit_code=run_result.exit_code,
        duration_ms=run_result.duration_ms,
        timed_out=run_result.timed_out,
    )

    # 7. Build response
    artifacts: list[ExecuteArtifactSchema] = []
    if artifact_share is not None and artifact_rel_dir is not None:
        try:
            metadata_list = await asyncio.to_thread(
                file_shares.artifact_metadata,
                artifact_share,
                artifact_rel_dir,
                recursive=result.rule.artifact_capture.recursive,
            )
            artifacts = [
                ExecuteArtifactSchema(
                    tool=body.tool,
                    share=artifact_share.name,
                    path=item["path"],
                    name=item["name"],
                    size=item["size"],
                    modified=item["modified"],
                    sha256=item["sha256"],
                    url=item["url"],
                    download_url=item["download_url"],
                )
                for item in metadata_list
            ]
        except FileShareError as exc:
            log.warning(
                "artifact_capture_failed",
                client=client.name,
                tool=body.tool,
                matched_rule=result.rule_id,
                detail=str(exc),
            )

    return ExecuteResponse(
        ok=run_result.exit_code == 0 and not run_result.timed_out,
        exit_code=run_result.exit_code,
        stdout=_try_parse_json(run_result.stdout),
        stderr=run_result.stderr,
        duration_ms=run_result.duration_ms,
        matched_rule=result.rule_id,
        timed_out=run_result.timed_out,
        artifacts=artifacts,
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
