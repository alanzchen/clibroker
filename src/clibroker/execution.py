"""Shared policy, authorization, execution, artifact capture, and audit pipeline."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from pydantic_core import from_json

from .audit import get_audit_logger
from .file_sharing import FileShareError, FileShareService
from .models import ExecuteArtifactSchema, ExecuteResponse
from .policy import PolicyDenied, PolicyEngine, PolicyNoMatch, PolicyValidationError
from .runner import execute as run_command


class ExecutionForbidden(Exception):
    """The caller cannot execute the matched allow rule."""

    def __init__(self, message: str, rule_id: str) -> None:
        super().__init__(message)
        self.rule_id = rule_id


def execution_error(message: str, matched_rule: str = "") -> ExecuteResponse:
    return ExecuteResponse(
        ok=False,
        exit_code=-1,
        stdout="",
        stderr=message,
        duration_ms=0,
        matched_rule=matched_rule,
    )


def _try_parse_json(value: str) -> Any:
    try:
        # The bounded parser rejects unpaired surrogates and stops at 200
        # nesting levels, leaving room for the REST/MCP response envelopes.
        parsed = from_json(value, allow_inf_nan=False)
        # Finite-looking JSON numbers such as 1e999 can still overflow a float.
        json.dumps(parsed, allow_nan=False)
        return parsed
    except ValueError:
        # Preserve the command's exact output when it cannot be represented
        # faithfully in a typed JSON result.
        return value


def _expand_artifact_arg(arg: str, context: dict[str, str]) -> str:
    """Expand only server-configured injected args, never user argv."""
    return (
        arg.replace("{execution_id}", context["execution_id"])
        .replace("{artifact_dir}", context["artifact_dir"])
        .replace("{artifact_rel_dir}", context["artifact_rel_dir"])
    )


class ExecutionService:
    """Execute validated commands for either transport with identical safeguards."""

    def __init__(self, policy: PolicyEngine, file_shares: FileShareService) -> None:
        self.policy = policy
        self.file_shares = file_shares

    async def execute(
        self,
        tool: str,
        argv: list[str],
        *,
        client: str,
        allowed_rules: set[str] | list[str] | None,
    ) -> ExecuteResponse:
        try:
            return await self._execute(
                tool, argv, client=client, allowed_rules=allowed_rules
            )
        except ExecutionForbidden:
            raise
        except Exception:
            # Keep local paths, environment values and other internals out of responses.
            get_audit_logger().exception("execution_failed", client=client, tool=tool)
            return execution_error("Internal server error")

    async def _execute(
        self,
        tool: str,
        argv: list[str],
        *,
        client: str,
        allowed_rules: set[str] | list[str] | None,
    ) -> ExecuteResponse:
        log = get_audit_logger()
        policy = self.policy
        file_shares = self.file_shares
        # Policy evaluation
        try:
            result = policy.evaluate(tool, argv)
        except PolicyDenied as exc:
            log.warning(
                "policy_denied",
                client=client,
                tool=tool,
                argv=argv,
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
                client=client,
                tool=tool,
                argv=argv,
            )
            return ExecuteResponse(
                ok=False,
                exit_code=-1,
                stdout="",
                stderr=f"No matching policy rule for tool '{tool}' with argv {argv}",
                duration_ms=0,
                matched_rule="",
            )
        except PolicyValidationError as exc:
            log.warning(
                "policy_validation_error",
                client=client,
                tool=tool,
                argv=argv,
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

        # Recheck authorization for the actual match, including wildcard/sibling rules.
        if allowed_rules is not None and result.rule_id not in allowed_rules:
            log.warning("rbac_denied", client=client, rule=result.rule_id)
            raise ExecutionForbidden(
                f"Client '{client}' is not authorized for rule '{result.rule_id}'",
                result.rule_id,
            )

        # Prepare per-execution artifact capture when configured
        artifact_context: dict[str, str] = {}
        artifact_share = None
        artifact_rel_dir = None

        if result.rule.artifact_capture is not None:
            execution_id = uuid.uuid4().hex
            capture = result.rule.artifact_capture
            try:
                artifact_share = file_shares.get_share(
                    tool,
                    capture.share,
                    allowed_rules,
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
                    client=client,
                    tool=tool,
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

        full_argv = list(result.full_argv)
        if artifact_context:
            start = result.inject_args_offset
            full_argv[start : start + len(result.rule.inject_args)] = [
                _expand_artifact_arg(arg, artifact_context)
                for arg in result.rule.inject_args
            ]

        # Execute
        tool_cfg = result.tool_config
        run_result = await run_command(
            full_argv,
            env=tool_cfg.env or None,
            cwd=tool_cfg.working_dir,
            timeout_s=tool_cfg.timeout_s,
            max_output_bytes=tool_cfg.max_output_bytes,
        )

        # Audit log (post-execution)
        log.info(
            "command_executed",
            client=client,
            tool=tool,
            matched_rule=result.rule_id,
            argv=full_argv,
            exit_code=run_result.exit_code,
            duration_ms=run_result.duration_ms,
            timed_out=run_result.timed_out,
        )

        # Build response
        artifacts: list[ExecuteArtifactSchema] = []
        capture_error = ""
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
                        tool=tool,
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
                capture_error = f"Failed to collect artifacts: {exc}"
                log.warning(
                    "artifact_capture_failed",
                    client=client,
                    tool=tool,
                    matched_rule=result.rule_id,
                    detail=str(exc),
                )

        return ExecuteResponse(
            ok=run_result.exit_code == 0
            and not run_result.timed_out
            and not capture_error,
            exit_code=run_result.exit_code,
            stdout=_try_parse_json(run_result.stdout),
            stderr="\n".join(
                part for part in (run_result.stderr, capture_error) if part
            ),
            duration_ms=run_result.duration_ms,
            matched_rule=result.rule_id,
            timed_out=run_result.timed_out,
            artifacts=artifacts,
        )
