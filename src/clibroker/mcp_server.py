"""MCP server — exposes clibroker policy rules as MCP tools.

Each allowed policy rule becomes a typed MCP tool with:
- Required parameters for positional arguments (with regex/enum validation)
- Optional parameters for allowed flags
- Full descriptions for LLM discoverability

All tool invocations still pass through the policy engine (defense in depth)
and the hardened subprocess runner.
"""

from __future__ import annotations

import inspect
import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from .audit import get_audit_logger
from .config import Config, Rule, ToolConfig
from .file_sharing import FileShareError, FileShareService
from .policy import PolicyEngine, PolicyError
from .runner import execute as run_command


def create_mcp_server(
    config: Config,
    policy: PolicyEngine,
    *,
    file_share_service: FileShareService | None = None,
    allowed_rules: set[str] | None = None,
) -> FastMCP:
    """Create a FastMCP server with tools derived from the clibroker config.

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
    mcp = FastMCP(
        "clibroker",
        stateless_http=True,
        json_response=True,
    )
    # Set paths so they sit at the root of their mount points
    mcp.settings.streamable_http_path = "/"
    mcp.settings.sse_path = "/"

    if file_share_service is None:
        file_share_service = FileShareService(config)

    for tool_name, tool_cfg in config.tools.items():
        for rule in tool_cfg.rules:
            if rule.effect != "allow":
                continue
            if allowed_rules is not None and rule.id not in allowed_rules:
                continue
            _register_rule_tool(mcp, tool_name, tool_cfg, rule, policy, allowed_rules)

    for tool_name in config.tools:
        if file_share_service.get_client_shares(tool_name, allowed_rules):
            _register_file_tools(mcp, tool_name, file_share_service, allowed_rules)

    return mcp


def _register_rule_tool(
    mcp: FastMCP,
    tool_name: str,
    tool_cfg: ToolConfig,
    rule: Rule,
    policy: PolicyEngine,
    allowed_rules: set[str] | None,
) -> None:
    """Register a single MCP tool for an allowed policy rule."""
    log = get_audit_logger()

    # Build flag-name mappings: python_param_name -> CLI flag string
    value_flag_map: dict[str, str] = {}
    standalone_flag_map: dict[str, str] = {}
    if rule.flags:
        for flag in rule.flags.allowed:
            param_name = flag.lstrip("-").replace("-", "_")
            value_flag_map[param_name] = flag
        for flag in rule.flags.standalone:
            param_name = flag.lstrip("-").replace("-", "_")
            standalone_flag_map[param_name] = flag

    # Capture loop variables in default args to avoid late-binding issues
    _rule = rule
    _tool_name = tool_name
    _tool_cfg = tool_cfg
    _value_flag_map = dict(value_flag_map)
    _standalone_flag_map = dict(standalone_flag_map)
    _allowed_rules = allowed_rules

    async def handler(**kwargs: Any) -> str:
        """Dynamically-generated tool handler."""
        # Build argv from structured kwargs
        argv: list[str] = list(_rule.command)

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

        # Policy evaluation (defense in depth — the tool's existence already
        # implies allow, but we still validate flags, positionals, patterns)
        try:
            result = policy.evaluate(_tool_name, argv)
        except PolicyError as exc:
            log.warning(
                "mcp_policy_error",
                tool=_tool_name,
                rule=_rule.id,
                argv=argv,
                error=str(exc),
            )
            return json.dumps({"ok": False, "error": str(exc)})
        except Exception:
            # Don't leak internal details for unexpected exceptions
            log.exception(
                "mcp_unexpected_error",
                tool=_tool_name,
                rule=_rule.id,
                argv=argv,
            )
            return json.dumps({"ok": False, "error": "Internal server error"})

        # RBAC defense-in-depth: verify the matched rule is authorized
        # for this token's allowlist, even though tool registration already
        # filters.  This catches any bugs in the registration filter.
        if _allowed_rules is not None and result.rule_id not in _allowed_rules:
            log.warning(
                "mcp_rbac_denied",
                tool=_tool_name,
                rule=result.rule_id,
                allowed_rules=sorted(_allowed_rules),
            )
            return json.dumps(
                {
                    "ok": False,
                    "error": f"Not authorized for rule '{result.rule_id}'",
                }
            )

        # Execute
        run_result = await run_command(
            result.full_argv,
            env=_tool_cfg.env or None,
            cwd=_tool_cfg.working_dir,
            timeout_s=_tool_cfg.timeout_s,
            max_output_bytes=_tool_cfg.max_output_bytes,
        )

        log.info(
            "mcp_command_executed",
            tool=_tool_name,
            matched_rule=_rule.id,
            argv=result.full_argv,
            exit_code=run_result.exit_code,
            duration_ms=run_result.duration_ms,
            timed_out=run_result.timed_out,
        )

        # Try to parse stdout as JSON
        stdout: Any = run_result.stdout
        try:
            stdout = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            pass

        return json.dumps(
            {
                "ok": run_result.exit_code == 0 and not run_result.timed_out,
                "exit_code": run_result.exit_code,
                "stdout": stdout,
                "stderr": run_result.stderr,
                "duration_ms": run_result.duration_ms,
                "timed_out": run_result.timed_out,
            }
        )

    # --- Build a proper function signature for FastMCP introspection ---
    params: list[inspect.Parameter] = []

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
        params, return_annotation=str
    )

    # --- Function metadata ---
    func_name = f"{tool_name}__{rule.id}"
    handler.__name__ = func_name
    handler.__qualname__ = func_name

    # Build a human-readable description
    desc_lines = [f"Execute: {tool_name} {' '.join(rule.command)}"]
    if rule.inject_args:
        desc_lines.append(f"Injected args: {' '.join(rule.inject_args)}")
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

    # Register with FastMCP
    mcp.tool()(handler)


def _register_file_tools(
    mcp: FastMCP,
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
