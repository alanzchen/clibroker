"""Configuration models — YAML config parsed into validated Pydantic models."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class FlagConfig(BaseModel):
    """Allowlist of flags permitted for a rule."""

    allowed: list[str] = Field(default_factory=list)
    standalone: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_disjoint_flag_sets(self) -> "FlagConfig":
        overlap = sorted(set(self.allowed) & set(self.standalone))
        if overlap:
            raise ValueError(
                "flags.allowed and flags.standalone must be disjoint; "
                f"overlap: {overlap}"
            )
        return self


class PositionalArg(BaseModel):
    """Validation constraints for a single positional argument."""

    name: str
    pattern: str | None = None  # regex the value must match
    enum: list[str] | None = None  # allowed literal values
    variadic: bool = False

    @field_validator("pattern")
    @classmethod
    def _compile_pattern(cls, v: str | None) -> str | None:
        if v is not None:
            re.compile(v)  # fail fast on invalid regex
        return v


class GlobalArgPattern(BaseModel):
    """A reorderable global argument matcher for a tool."""

    id: str
    kind: Literal["key_value"] = "key_value"
    key_pattern: str
    value_pattern: str | None = None
    canonical_position: Literal["before_command"] = "before_command"
    allow_positions: list[Literal["before_command", "after_command"]] = Field(
        default_factory=lambda: ["before_command"]
    )
    multiple: bool = False

    @field_validator("key_pattern", "value_pattern")
    @classmethod
    def _compile_global_patterns(cls, v: str | None) -> str | None:
        if v is not None:
            re.compile(v)
        return v

    @model_validator(mode="after")
    def _validate_position_policy(self) -> "GlobalArgPattern":
        if self.canonical_position not in self.allow_positions:
            raise ValueError(
                "canonical_position must be included in allow_positions"
            )
        return self


class ArgvNormalizationConfig(BaseModel):
    """Tool-level argv normalization settings."""

    patterns: list[GlobalArgPattern] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_pattern_ids_unique(self) -> "ArgvNormalizationConfig":
        seen: set[str] = set()
        for pattern in self.patterns:
            if pattern.id in seen:
                raise ValueError(
                    f"Duplicate argv normalization pattern id '{pattern.id}'"
                )
            seen.add(pattern.id)
        return self


class Rule(BaseModel):
    """A single policy rule attached to a command path."""

    id: str
    command: list[str] = Field(..., min_length=1)  # e.g. ["message", "move"]
    effect: Literal["allow", "deny"] = "allow"
    flags: FlagConfig | None = None
    inject_args: list[str] = Field(default_factory=list)
    positionals: list[PositionalArg] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_variadic_positionals(self) -> "Rule":
        variadic_indexes = [
            index
            for index, positional in enumerate(self.positionals)
            if positional.variadic
        ]
        if len(variadic_indexes) > 1:
            raise ValueError("Only one positional may be variadic")
        if variadic_indexes and variadic_indexes[0] != len(self.positionals) - 1:
            raise ValueError("Only the final positional may be variadic")
        return self


class ToolConfig(BaseModel):
    """Configuration for a single wrapped CLI tool."""

    executable: str  # must be absolute path
    default_args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    working_dir: str | None = None
    timeout_s: float = 30.0
    max_output_bytes: int = 1_048_576  # 1 MB
    argv_normalization: ArgvNormalizationConfig | None = None
    rules: list[Rule]

    @field_validator("executable")
    @classmethod
    def _executable_is_absolute(cls, v: str) -> str:
        if not Path(v).is_absolute():
            raise ValueError(f"executable must be an absolute path, got: {v}")
        return v


class TokenConfig(BaseModel):
    """A bearer token with associated RBAC rule allowlist."""

    name: str
    value: str  # literal or "env:VAR_NAME"
    allow_rules: list[str]

    def resolve_value(self) -> str:
        """Return the actual token value, resolving env: indirection."""
        if self.value.startswith("env:"):
            var = self.value[4:]
            resolved = os.environ.get(var)
            if resolved is None:
                raise RuntimeError(
                    f"Token '{self.name}' references env var '{var}' which is not set"
                )
            return resolved
        return self.value


class AuthConfig(BaseModel):
    """Authentication configuration."""

    type: Literal["bearer"] = "bearer"
    tokens: list[TokenConfig] = Field(default_factory=list)


class ServerConfig(BaseModel):
    """Top-level server settings."""

    bind: str = "127.0.0.1:8080"
    auth: AuthConfig = AuthConfig()
    request_timeout_s: float = 30.0
    max_output_bytes: int = 1_048_576


class Config(BaseModel):
    """Root configuration model."""

    server: ServerConfig = ServerConfig()
    tools: dict[str, ToolConfig]

    @model_validator(mode="after")
    def _check_rule_ids_unique(self) -> Config:
        seen: set[str] = set()
        for tool_name, tool in self.tools.items():
            for rule in tool.rules:
                if rule.id in seen:
                    raise ValueError(
                        f"Duplicate rule id '{rule.id}' (found in tool '{tool_name}')"
                    )
                seen.add(rule.id)
        return self

    @model_validator(mode="after")
    def _check_token_rules_exist(self) -> Config:
        all_rule_ids = {rule.id for tool in self.tools.values() for rule in tool.rules}
        for token in self.server.auth.tokens:
            for rule_id in token.allow_rules:
                if rule_id not in all_rule_ids:
                    raise ValueError(
                        f"Token '{token.name}' references unknown rule '{rule_id}'"
                    )
        return self


def load_config(path: str | Path) -> Config:
    """Load and validate configuration from a YAML file."""
    with open(path) as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(
            f"Config file must be a YAML mapping, got {type(raw).__name__}"
        )
    return Config.model_validate(raw)
