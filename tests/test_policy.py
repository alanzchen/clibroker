"""Tests for the policy engine — command tree, deny-by-default, validation."""

from __future__ import annotations

import pytest

import yaml

from clibroker.config import Config
from clibroker.policy import (
    PolicyDenied,
    PolicyEngine,
    PolicyNoMatch,
    PolicyResult,
    PolicyValidationError,
)
from tests.conftest import make_config


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(make_config())


class TestCommandTreeMatching:
    """Test that the command tree routes argv to the correct rule."""

    def test_list_messages_matches(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "list"])
        assert isinstance(result, PolicyResult)
        assert result.rule_id == "list_messages"

    def test_list_messages_with_flags(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(
            "himalaya", ["message", "list", "--account", "work", "--folder", "INBOX"]
        )
        assert result.rule_id == "list_messages"
        assert "--account" in result.full_argv
        assert "work" in result.full_argv

    def test_read_message_with_positional(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "read", "42"])
        assert result.rule_id == "read_message"
        assert "42" in result.full_argv

    def test_move_message_with_positionals(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "move", "42", "Archive"])
        assert result.rule_id == "move_message"
        assert "42" in result.full_argv
        assert "Archive" in result.full_argv

    def test_full_argv_construction(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "list"])
        # executable + default_args + command
        assert result.full_argv[0] == "/usr/bin/echo"
        assert result.full_argv[1:3] == ["--output", "json"]
        assert result.full_argv[3:5] == ["message", "list"]

    def test_injected_args_are_inserted_before_user_args(
        self, engine: PolicyEngine
    ) -> None:
        result = engine.evaluate("himalaya", ["message", "read", "42"])
        assert result.full_argv[3:6] == ["message", "read", "--preview"]
        assert result.full_argv[-1] == "42"


class TestDenyPrecedence:
    """Test that deny rules take precedence and deny-by-default works."""

    def test_explicit_deny(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyDenied) as exc_info:
            engine.evaluate("himalaya", ["message", "delete"])
        assert exc_info.value.rule_id == "deny_delete"

    def test_unknown_tool_denied(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyNoMatch):
            engine.evaluate("unknown_tool", ["anything"])

    def test_unknown_subcommand_denied(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyNoMatch):
            engine.evaluate("himalaya", ["account", "configure"])

    def test_partial_subcommand_no_match(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyNoMatch):
            engine.evaluate("himalaya", ["message"])


class TestFlagValidation:
    """Test that unknown flags are rejected."""

    def test_allowed_flag(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "list", "--account", "work"])
        assert result.rule_id == "list_messages"

    def test_disallowed_flag_rejected(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            engine.evaluate("himalaya", ["message", "list", "--config", "/etc/shadow"])
        assert "not allowed" in str(exc_info.value)

    def test_flag_injection_rejected(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyValidationError):
            engine.evaluate("himalaya", ["message", "list", "--exec", "rm -rf /"])

    def test_standalone_flag_allowed(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "list", "--unread"])
        assert result.rule_id == "list_messages"
        assert "--unread" in result.full_argv

    def test_standalone_flag_with_value_rejected(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            engine.evaluate("himalaya", ["message", "list", "--unread=true"])
        assert "does not take a value" in str(exc_info.value)


class TestPositionalValidation:
    """Test regex and enum constraints on positional arguments."""

    def test_valid_numeric_id(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "read", "123"])
        assert result.rule_id == "read_message"

    def test_invalid_id_pattern(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            engine.evaluate("himalaya", ["message", "read", "not-a-number"])
        assert "pattern" in str(exc_info.value)

    def test_valid_destination_enum(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("himalaya", ["message", "move", "42", "Inbox"])
        assert result.rule_id == "move_message"

    def test_invalid_destination_enum(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            engine.evaluate("himalaya", ["message", "move", "42", "Trash"])
        assert "not in allowed values" in str(exc_info.value)

    def test_wrong_positional_count(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            engine.evaluate("himalaya", ["message", "move", "42"])
        assert "Expected 2" in str(exc_info.value)

    def test_extra_positionals_rejected(self, engine: PolicyEngine) -> None:
        with pytest.raises(PolicyValidationError):
            engine.evaluate("himalaya", ["message", "read", "42", "extra"])


class TestMoveWithFlags:
    """Test combined flags + positionals."""

    def test_flags_and_positionals(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(
            "himalaya",
            ["message", "move", "--account", "work", "42", "Archive"],
        )
        assert result.rule_id == "move_message"
        assert "42" in result.full_argv
        assert "Archive" in result.full_argv
        assert "--account" in result.full_argv
        assert "work" in result.full_argv


class TestVariadicPositionals:
    """Test repeated tail positionals."""

    @pytest.fixture
    def variadic_engine(self) -> PolicyEngine:
        raw = yaml.safe_load(
            """
            server:
              bind: "127.0.0.1:9999"
              auth:
                type: bearer
                tokens: []
            tools:
              himalaya:
                executable: "/usr/bin/echo"
                default_args: []
                rules:
                  - id: search_messages
                    command: ["envelope", "list"]
                    effect: allow
                    flags:
                      allowed: ["--account", "--folder", "--page", "--page-size"]
                    positionals:
                      - name: query
                        pattern: "^[A-Za-z0-9_@.+:-]+$"
                        variadic: true
            """
        )
        return PolicyEngine(Config.model_validate(raw))

    def test_variadic_tail_is_accepted(self, variadic_engine: PolicyEngine) -> None:
        result = variadic_engine.evaluate(
            "himalaya",
            [
                "envelope",
                "list",
                "subject",
                "invoice",
                "and",
                "body",
                "march",
            ],
        )
        assert result.rule_id == "search_messages"
        assert result.full_argv[-5:] == [
            "subject",
            "invoice",
            "and",
            "body",
            "march",
        ]

    def test_variadic_tail_requires_at_least_one_value(
        self, variadic_engine: PolicyEngine
    ) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            variadic_engine.evaluate("himalaya", ["envelope", "list"])
        assert "Expected at least 1 positional arg" in str(exc_info.value)

    def test_variadic_tail_validates_each_token(
        self, variadic_engine: PolicyEngine
    ) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            variadic_engine.evaluate(
                "himalaya", ["envelope", "list", "subject", "bad!"]
            )
        assert "pattern" in str(exc_info.value)


class TestSiblingAllowRuleFallback:
    """Test that sibling allow rules can fall through on validation failure."""

    @pytest.fixture
    def sibling_rule_engine(self) -> PolicyEngine:
        raw = yaml.safe_load(
            """
            server:
              bind: "127.0.0.1:9999"
              auth:
                type: bearer
                tokens: []
            tools:
              himalaya:
                executable: "/usr/bin/echo"
                default_args: []
                rules:
                  - id: list_envelopes_plain
                    command: ["envelope", "list"]
                    effect: allow
                    flags:
                      allowed: ["--account", "--folder", "--page", "--page-size"]
                  - id: list_envelopes
                    command: ["envelope", "list"]
                    effect: allow
                    flags:
                      allowed: ["--account", "--folder", "--page", "--page-size"]
                    positionals:
                      - name: query
                        pattern: "^[A-Za-z0-9_@.+:,-]+$"
                        variadic: true
            """
        )
        return PolicyEngine(Config.model_validate(raw))

    def test_plain_rule_still_handles_no_query(
        self, sibling_rule_engine: PolicyEngine
    ) -> None:
        result = sibling_rule_engine.evaluate(
            "himalaya", ["envelope", "list", "--folder", "INBOX"]
        )
        assert result.rule_id == "list_envelopes_plain"

    def test_query_rule_handles_search_tail_when_plain_rejects(
        self, sibling_rule_engine: PolicyEngine
    ) -> None:
        result = sibling_rule_engine.evaluate(
            "himalaya",
            ["envelope", "list", "subject", "review", "order", "by", "date", "desc"],
        )
        assert result.rule_id == "list_envelopes"
        assert result.full_argv[-6:] == ["subject", "review", "order", "by", "date", "desc"]
