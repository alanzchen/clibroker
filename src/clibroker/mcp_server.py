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
from .policy import PolicyEngine, PolicyError
from .runner import execute as run_command


def create_mcp_server(
    config: Config,
    policy: PolicyEngine,
    *,
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

    for tool_name, tool_cfg in config.tools.items():
        for rule in tool_cfg.rules:
            if rule.effect != "allow":
                continue
            if allowed_rules is not None and rule.id not in allowed_rules:
                continue
            _register_rule_tool(mcp, tool_name, tool_cfg, rule, policy, allowed_rules)

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
