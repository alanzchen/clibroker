"""MCP server — exposes clibroker policy rules as MCP tools.

Each allowed policy rule becomes a typed MCP tool with:
- Required parameters for positional arguments (with regex/enum validation)
- Optional parameters for allowed flags
- Full descriptions for LLM discoverability

All tool invocations still pass through the policy engine (defense in depth)
and the hardened subprocess runner.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import keyword
import mimetypes
import re
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import HTTPException
from mcp.server import MCPServer
from mcp.server.caching import CacheHint
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ResourceError
from mcp.types import CallToolResult, ResourceLink, TextContent

from . import __version__
from .audit import get_audit_logger
from .auth import Authenticator
from .config import Config, Rule
from .execution import ExecutionForbidden, ExecutionService, execution_error
from .file_sharing import FileShareError, FileShareService
from .models import ExecuteArtifactSchema, ExecuteResponse
from .policy import PolicyEngine


class MCPArtifactSchema(ExecuteArtifactSchema):
    """An artifact with both an authenticated HTTP URL and a native MCP URI."""

    uri: str
    mime_type: str


class MCPExecuteResponse(ExecuteResponse):
    artifacts: list[MCPArtifactSchema]


def _artifact_uri(tool: str, share: str, path: str) -> str:
    return (
        f"clibroker://artifacts/{quote(tool, safe='')}/"
        f"{quote(share, safe='')}/{quote(path, safe='/')}"
    )


def _execution_result(response: ExecuteResponse) -> CallToolResult:
    artifacts = [
        MCPArtifactSchema(
            **artifact.model_dump(),
            uri=_artifact_uri(artifact.tool, artifact.share, artifact.path),
            mime_type=mimetypes.guess_type(artifact.name)[0]
            or "application/octet-stream",
        )
        for artifact in response.artifacts
    ]
    result = MCPExecuteResponse(
        **response.model_dump(exclude={"artifacts"}), artifacts=artifacts
    )
    return CallToolResult(
        content=[
            TextContent(type="text", text=result.model_dump_json()),
            *[
                ResourceLink(
                    type="resource_link",
                    uri=artifact.uri,
                    name=artifact.name,
                    mime_type=artifact.mime_type,
                    size=artifact.size,
                )
                for artifact in artifacts
            ],
        ],
        structured_content=result.model_dump(mode="json"),
        is_error=not result.ok,
    )


def _register_artifact_resource(
    mcp: MCPServer,
    tool: str,
    share: str,
    file_shares: FileShareService,
    allowed_rules: set[str] | None,
    authenticator: Authenticator,
) -> None:
    """Read through the same bearer auth, share RBAC and containment checks as REST."""

    async def read_artifact(path: str, ctx: Context) -> bytes:
        request = ctx.request_context.request
        if request is None:
            raise ResourceError("Artifact reads require bearer authentication")
        try:
            client = authenticator.authenticate(request)
            # Both the routed MCP view and the supplied bearer must grant access.
            file_shares.get_share(tool, share, allowed_rules)
            share_cfg = file_shares.get_share(tool, share, client.allow_rules)
            payload = await asyncio.to_thread(
                file_shares.read_file,
                share_cfg,
                path,
                encoding="base64",
            )
            return base64.b64decode(payload["content"])
        except HTTPException as exc:
            raise ResourceError(str(exc.detail)) from exc
        except FileShareError as exc:
            raise ResourceError(str(exc)) from exc
        except Exception as exc:
            get_audit_logger().exception(
                "mcp_artifact_read_failed", tool=tool, share=share
            )
            raise ResourceError("Unable to read artifact") from exc

    prefix = _artifact_uri(tool, share, "")
    mcp.resource(
        prefix + "{+path}",
        name=f"{tool}__{share}__artifacts",
        description="Read an artifact using an authorized bearer token. Returns exact file bytes.",
        mime_type="application/octet-stream",
    )(read_artifact)


def create_mcp_server(
    config: Config,
    policy: PolicyEngine,
    *,
    file_share_service: FileShareService | None = None,
    allowed_rules: set[str] | None = None,
    execution_service: ExecutionService | None = None,
    client_name: str = "mcp",
) -> MCPServer:
    """Create an MCP server with tools derived from the clibroker config.

    Each allowed rule is registered as a separate MCP tool with a typed
    parameter schema.  Deny rules are excluded entirely — they simply
    have no corresponding tool, enforcing deny-by-default at the MCP layer.

    Args:
        config: The full application config.
        policy: The policy engine for validation.
        allowed_rules: If provided, only register tools for rules whose id
            is in this set.  Used for per-token RBAC so each authenticated
            MCP endpoint only exposes the tools the token is authorized for.
    """
    mcp = MCPServer(
        "clibroker",
        version=__version__,
        subscriptions=False,
        cache_hints={
            method: CacheHint(ttl_ms=0, scope="private")
            for method in (
                "tools/list",
                "resources/list",
                "resources/templates/list",
                "resources/read",
            )
        },
    )
    if file_share_service is None:
        file_share_service = FileShareService(config)
    if execution_service is None:
        execution_service = ExecutionService(policy, file_share_service)
    authenticator = Authenticator(config)

    for tool_name, tool_cfg in config.tools.items():
        for rule in tool_cfg.rules:
            if rule.effect != "allow":
                continue
            if allowed_rules is not None and rule.id not in allowed_rules:
                continue
            _register_rule_tool(
                mcp, tool_name, rule, execution_service, allowed_rules, client_name
            )

    for tool_name in config.tools:
        if file_share_service.get_client_shares(tool_name, allowed_rules):
            _register_file_tools(mcp, tool_name, file_share_service, allowed_rules)
            for share in file_share_service.get_client_shares(tool_name, allowed_rules):
                _register_artifact_resource(
                    mcp,
                    tool_name,
                    share["name"],
                    file_share_service,
                    allowed_rules,
                    authenticator,
                )

    return mcp


def _register_rule_tool(
    mcp: MCPServer,
    tool_name: str,
    rule: Rule,
    execution: ExecutionService,
    allowed_rules: set[str] | None,
    client_name: str,
) -> None:
    """Register a single MCP tool for an allowed policy rule."""
    # Build flag-name mappings: python_param_name -> CLI flag string
    value_flag_map: dict[str, str] = {}
    standalone_flag_map: dict[str, str] = {}
    used_param_names = {pos.name for pos in rule.positionals}
    if rule.flags:
        for flag in rule.flags.allowed:
            param_name = _flag_to_param_name(flag, used_param_names)
            value_flag_map[param_name] = flag
        for flag in rule.flags.standalone:
            param_name = _flag_to_param_name(flag, used_param_names)
            standalone_flag_map[param_name] = flag

    # Each registered handler keeps its own rule and argument mappings.
    _rule = rule
    _tool_name = tool_name
    _value_flag_map = dict(value_flag_map)
    _standalone_flag_map = dict(standalone_flag_map)
    _allowed_rules = allowed_rules

    async def handler(**kwargs: Any) -> Annotated[CallToolResult, MCPExecuteResponse]:
        """Dynamically-generated tool handler."""
        # Build argv from structured kwargs
        if _rule.allow_any_args:
            raw_args = kwargs.get("args")
            if raw_args is None:
                argv = []
            elif isinstance(raw_args, list):
                argv = [str(item) for item in raw_args]
            else:
                argv = [str(raw_args)]
        else:
            argv = list(_rule.command)

            # Append value-taking flags
            for param_name, flag_str in _value_flag_map.items():
                val = kwargs.get(param_name)
                if val is not None and val != "":
                    argv.extend([flag_str, str(val)])

            # Append standalone flags
            for param_name, flag_str in _standalone_flag_map.items():
                if kwargs.get(param_name):
                    argv.append(flag_str)

            # Append positionals in declaration order
            for pos in _rule.positionals:
                val = kwargs.get(pos.name)
                if pos.variadic:
                    if val is not None:
                        argv.extend(str(item) for item in val)
                    continue
                if val is not None:
                    argv.append(str(val))

        try:
            response = await execution.execute(
                _tool_name,
                argv,
                client=client_name,
                allowed_rules=_allowed_rules,
            )
        except ExecutionForbidden as exc:
            response = execution_error(str(exc), exc.rule_id)
        return _execution_result(response)

    # --- Build a proper function signature for MCPServer introspection ---
    params: list[inspect.Parameter] = []

    if rule.allow_any_args:
        params.append(
            inspect.Parameter(
                "args",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=list[str],
            )
        )
    else:
        # Positionals (required)
        for pos in rule.positionals:
            annotation = list[str] if pos.variadic else str
            params.append(
                inspect.Parameter(
                    pos.name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=annotation,
                )
            )

        # Value-taking flags (optional, default None)
        for param_name in value_flag_map:
            params.append(
                inspect.Parameter(
                    param_name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=None,
                    annotation=str | None,
                )
            )

        # Standalone flags (optional boolean)
        for param_name in standalone_flag_map:
            params.append(
                inspect.Parameter(
                    param_name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=False,
                    annotation=bool,
                )
            )

    handler.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        params, return_annotation=Annotated[CallToolResult, MCPExecuteResponse]
    )

    # --- Function metadata ---
    func_name = f"{tool_name}__{rule.id}"
    handler.__name__ = func_name
    handler.__qualname__ = func_name

    # Build a human-readable description
    desc_lines = [f"Execute: {tool_name} {' '.join(rule.command)}"]
    if rule.inject_args:
        desc_lines.append(f"Injected args: {' '.join(rule.inject_args)}")
    if rule.allow_any_args:
        desc_lines.append("Parameters:")
        desc_lines.append("  - args...: required raw argv vector")
    if rule.positionals:
        desc_lines.append("Parameters:")
        for pos in rule.positionals:
            constraint = ""
            if pos.enum:
                constraint = f" (one of: {', '.join(pos.enum)})"
            elif pos.pattern:
                constraint = f" (must match: {pos.pattern})"
            label = f"{pos.name}..." if pos.variadic else pos.name
            desc_lines.append(f"  - {label}: required{constraint}")
    if value_flag_map:
        desc_lines.append(f"Optional flags: {', '.join(value_flag_map.values())}")
    if standalone_flag_map:
        desc_lines.append(
            f"Optional standalone flags: {', '.join(standalone_flag_map.values())}"
        )
    handler.__doc__ = "\n".join(desc_lines)

    # Register with MCPServer
    mcp.tool()(handler)


def _register_file_tools(
    mcp: MCPServer,
    tool_name: str,
    file_shares: FileShareService,
    allowed_rules: set[str] | None,
) -> None:
    """Register MCP tools for safe file operations on a wrapped tool."""

    log = get_audit_logger()
    shares = file_shares.get_client_shares(tool_name, allowed_rules)
    share_names = ", ".join(share["name"] for share in shares)

    def _get_share(share: str):
        return file_shares.get_share(tool_name, share, allowed_rules)

    def _success(payload: dict[str, Any]) -> str:
        return json.dumps(payload)

    def _error(exc: Exception) -> str:
        if isinstance(exc, FileShareError):
            return json.dumps({"ok": False, "error": str(exc)})
        log.exception("mcp_file_unexpected_error", tool=tool_name)
        return json.dumps({"ok": False, "error": "Internal server error"})

    def files_list(
        share: str,
        path: str = ".",
        recursive: bool = False,
    ) -> str:
        try:
            share_cfg = _get_share(share)
            payload = file_shares.list_dir(share_cfg, path, recursive=recursive)
            log.info(
                "mcp_file_list",
                tool=tool_name,
                share=share,
                path=path,
                recursive=recursive,
            )
            return _success(payload)
        except Exception as exc:
            return _error(exc)

    def files_stat(share: str, path: str = ".") -> str:
        try:
            share_cfg = _get_share(share)
            payload = file_shares.stat_path(share_cfg, path)
            log.info("mcp_file_stat", tool=tool_name, share=share, path=path)
            return _success(payload)
        except Exception as exc:
            return _error(exc)

    def files_read(
        share: str,
        path: str,
        encoding: str = "auto",
    ) -> str:
        try:
            share_cfg = _get_share(share)
            payload = file_shares.read_file(share_cfg, path, encoding=encoding)
            log.info(
                "mcp_file_read",
                tool=tool_name,
                share=share,
                path=path,
                encoding=encoding,
            )
            return _success(payload)
        except Exception as exc:
            return _error(exc)

    def files_write(
        share: str,
        path: str,
        content: str,
        encoding: str = "utf-8",
        overwrite: bool = True,
    ) -> str:
        try:
            share_cfg = _get_share(share)
            payload = file_shares.write_file(
                share_cfg,
                path,
                content,
                encoding=encoding,
                overwrite=overwrite,
            )
            log.info("mcp_file_write", tool=tool_name, share=share, path=path)
            return _success(payload)
        except Exception as exc:
            return _error(exc)

    def files_mkdir(
        share: str,
        path: str,
        parents: bool = True,
    ) -> str:
        try:
            share_cfg = _get_share(share)
            payload = file_shares.mkdir(share_cfg, path, parents=parents)
            log.info("mcp_file_mkdir", tool=tool_name, share=share, path=path)
            return _success(payload)
        except Exception as exc:
            return _error(exc)

    def files_move(
        share: str,
        source_path: str,
        destination_path: str,
        overwrite: bool = False,
    ) -> str:
        try:
            share_cfg = _get_share(share)
            payload = file_shares.move(
                share_cfg,
                source_path,
                destination_path,
                overwrite=overwrite,
            )
            log.info(
                "mcp_file_move",
                tool=tool_name,
                share=share,
                source_path=source_path,
                destination_path=destination_path,
            )
            return _success(payload)
        except Exception as exc:
            return _error(exc)

    def files_delete(
        share: str,
        path: str,
        recursive: bool = False,
    ) -> str:
        try:
            share_cfg = _get_share(share)
            payload = file_shares.delete(share_cfg, path, recursive=recursive)
            log.info(
                "mcp_file_delete",
                tool=tool_name,
                share=share,
                path=path,
                recursive=recursive,
            )
            return _success(payload)
        except Exception as exc:
            return _error(exc)

    handlers = [
        (
            "files_list",
            files_list,
            f"List files in a configured share for {tool_name}. Shares: {share_names}",
        ),
        (
            "files_stat",
            files_stat,
            f"Stat a file or directory in a configured share for {tool_name}. "
            f"Shares: {share_names}",
        ),
        (
            "files_read",
            files_read,
            f"Read a file from a configured share for {tool_name}. Shares: {share_names}",
        ),
        (
            "files_write",
            files_write,
            f"Write or replace a file in a read_write share for {tool_name}. "
            f"Shares: {share_names}",
        ),
        (
            "files_mkdir",
            files_mkdir,
            f"Create a directory in a read_write share for {tool_name}. "
            f"Shares: {share_names}",
        ),
        (
            "files_move",
            files_move,
            f"Move or rename a path in a read_write share for {tool_name}. "
            f"Shares: {share_names}",
        ),
        (
            "files_delete",
            files_delete,
            f"Delete a path from a read_write share for {tool_name}. "
            f"Shares: {share_names}",
        ),
    ]

    for suffix, handler, description in handlers:
        func_name = f"{tool_name}__{suffix}"
        handler.__name__ = func_name
        handler.__qualname__ = func_name
        handler.__doc__ = description
        mcp.tool(name=func_name, description=description)(handler)


def _flag_to_param_name(flag: str, used: set[str]) -> str:
    """Return a valid, unique Python parameter name for a CLI flag."""
    base = re.sub(r"\W", "_", flag.lstrip("-").replace("-", "_"))
    if not base:
        base = "flag"
    if base[0].isdigit():
        base = f"flag_{base}"
    if keyword.iskeyword(base):
        base = f"{base}_"

    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate
