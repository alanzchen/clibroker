"""Request and response models for the HTTP API and client discovery."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ExecuteRequest(BaseModel):
    """Incoming execution request — tool name + argv vector."""

    tool: str = Field(
        ..., description="Name of the wrapped CLI tool (must match a key in config)"
    )
    argv: list[str] = Field(
        ...,
        description="Argument vector passed to the tool (e.g. ['message', 'move', '42', 'Archive'])",
        min_length=1,
    )


class ExecuteResponse(BaseModel):
    """Structured response returned after command execution."""

    ok: bool
    exit_code: int
    stdout: Any  # str or parsed JSON dict/list
    stderr: str
    duration_ms: float
    matched_rule: str
    timed_out: bool = False


class ClientPositionalSchema(BaseModel):
    """Positional argument schema exposed to token-scoped clients."""

    name: str
    pattern: str | None = None
    enum: list[str] | None = None
    variadic: bool = False


class ClientRuleSchema(BaseModel):
    """An allow rule exposed through the client discovery endpoint."""

    id: str
    command: list[str]
    flags: list[str] = Field(default_factory=list)
    standalone_flags: list[str] = Field(default_factory=list)
    positionals: list[ClientPositionalSchema] = Field(default_factory=list)


class ClientToolSchema(BaseModel):
    """A token-scoped tool schema for the client discovery endpoint."""

    name: str
    rules: list[ClientRuleSchema]


class ClientConfigResponse(BaseModel):
    """Token-scoped configuration consumed by the broker client."""

    version: str
    client_name: str
    execute_url: str
    token_info_url: str
    mcp_url: str
    sse_url: str
    tools: list[ClientToolSchema]
