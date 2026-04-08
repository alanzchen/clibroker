"""Policy engine — command-tree matching, deny-by-default, argument validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Config, PositionalArg, Rule, ToolConfig


class PolicyError(Exception):
    """Base class for policy violations."""


class PolicyDenied(PolicyError):
    """Raised when a request matches an explicit deny rule."""

    def __init__(self, rule_id: str, message: str = ""):
        self.rule_id = rule_id
        super().__init__(message or f"Denied by rule '{rule_id}'")


class PolicyNoMatch(PolicyError):
    """Raised when no allow rule matches (deny-by-default)."""

    def __init__(self, tool: str, argv: list[str]):
        self.tool = tool
        self.argv = argv
        super().__init__(f"No matching allow rule for tool '{tool}' with argv {argv}")


class PolicyValidationError(PolicyError):
    """Raised when arguments fail validation against a matched rule."""

    def __init__(self, rule_id: str, detail: str):
        self.rule_id = rule_id
        self.detail = detail
        super().__init__(f"Validation failed for rule '{rule_id}': {detail}")


@dataclass
class PolicyResult:
    """Successful policy evaluation result."""

    rule_id: str
    tool_config: ToolConfig
    full_argv: list[str]  # the complete argv vector to execute


@dataclass
class _TreeNode:
    """Internal node in the command tree."""

    children: dict[str, _TreeNode] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)


class PolicyEngine:
    """Deny-by-default policy engine built from configuration.

    For each tool, rules are organized into a command tree. Evaluation:
    1. Locate the tool config.
    2. Walk the argv to find the deepest matching command path.
    3. Check deny rules first (deny precedence).
    4. If an allow rule matches, validate flags and positionals.
    5. If no rule matches, deny by default.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        # tool_name -> root tree node
        self._trees: dict[str, _TreeNode] = {}
        for tool_name, tool_cfg in config.tools.items():
            root = _TreeNode()
            for rule in tool_cfg.rules:
                node = root
                for part in rule.command:
                    if part not in node.children:
                        node.children[part] = _TreeNode()
                    node = node.children[part]
                node.rules.append(rule)
            self._trees[tool_name] = root

    def evaluate(self, tool: str, argv: list[str]) -> PolicyResult:
        """Evaluate a request against the policy.

        Returns a PolicyResult on success, raises PolicyError subclass on failure.
        """
        if tool not in self._config.tools:
            raise PolicyNoMatch(tool, argv)

        tool_cfg = self._config.tools[tool]
        tree = self._trees[tool]

        # Walk the command tree to find matching node
        node = tree
        consumed = 0
        for part in argv:
            if part in node.children:
                node = node.children[part]
                consumed += 1
            else:
                break

        if not node.rules:
            raise PolicyNoMatch(tool, argv)

        # Remaining argv after command path
        remaining = argv[consumed:]

        # Check deny rules on the matched node AND all ancestor nodes.
        # A deny on ["message", "delete"] cascades to deeper commands
        # like ["message", "delete", "batch"] so that adding a child
        # allow rule cannot silently bypass a parent deny.
        walk = tree
        for depth in range(consumed):
            walk = walk.children[argv[depth]]
            for rule in walk.rules:
                if rule.effect == "deny":
                    raise PolicyDenied(rule.id)

        # Try all allow rules on the matched node. This lets a more specific
        # rule with positionals succeed when a simpler sibling rule rejects the
        # argv due to positional count.
        last_validation_error: PolicyValidationError | None = None
        for rule in node.rules:
            if rule.effect == "allow":
                try:
                    validated_argv = self._validate_rule(rule, remaining)
                except PolicyValidationError as exc:
                    last_validation_error = exc
                    continue
                # Build the full argv: executable + default_args + command + validated remainder
                full_argv = (
                    [tool_cfg.executable]
                    + tool_cfg.default_args
                    + rule.command
                    + rule.inject_args
                    + validated_argv
                )
                return PolicyResult(
                    rule_id=rule.id,
                    tool_config=tool_cfg,
                    full_argv=full_argv,
                )

        if last_validation_error is not None:
            raise last_validation_error

        raise PolicyNoMatch(tool, argv)

    def _validate_rule(self, rule: Rule, remaining: list[str]) -> list[str]:
        """Validate remaining argv against a rule's flag/positional constraints.

        Returns the validated argument list (flags + positionals in order).

        Flag parsing rules:
        - ``--`` marks end-of-options; everything after is a positional.
        - ``--flag=value`` is split into ``--flag`` + ``value``.
        - Every flag in ``flags.allowed`` consumes exactly one subsequent
          argument as its value.
        - Every flag in ``flags.standalone`` is a valueless boolean flag.
        - Any argument starting with ``-`` that is not a recognized allowed
          flag is rejected.
        """
        flags: list[str] = []
        positionals: list[str] = []

        allowed_flags = set(rule.flags.allowed) if rule.flags else set()
        standalone_flags = set(rule.flags.standalone) if rule.flags else set()

        # Normalize: expand --flag=value into two elements
        normalized: list[str] = []
        for arg in remaining:
            if arg == "--":
                normalized.append(arg)
            elif arg.startswith("--") and "=" in arg:
                flag_part, _, val_part = arg.partition("=")
                if flag_part in standalone_flags:
                    raise PolicyValidationError(
                        rule.id,
                        f"Standalone flag '{flag_part}' does not take a value",
                    )
                normalized.append(flag_part)
                normalized.append(val_part)
            else:
                normalized.append(arg)

        i = 0
        end_of_options = False
        while i < len(normalized):
            arg = normalized[i]

            if end_of_options:
                positionals.append(arg)
                i += 1
                continue

            if arg == "--":
                end_of_options = True
                i += 1
                continue

            if arg.startswith("-"):
                # It's a flag
                if arg in standalone_flags:
                    flags.append(arg)
                    i += 1
                    continue

                if arg not in allowed_flags:
                    raise PolicyValidationError(rule.id, f"Flag '{arg}' is not allowed")
                flags.append(arg)
                # Every flag must have a value argument following it
                if i + 1 >= len(normalized) or normalized[i + 1] == "--":
                    raise PolicyValidationError(
                        rule.id,
                        f"Flag '{arg}' requires a value",
                    )
                i += 1
                flags.append(normalized[i])
            else:
                positionals.append(arg)

            i += 1

        expected_positionals = rule.positionals

        variadic_positional = None
        if expected_positionals and expected_positionals[-1].variadic:
            variadic_positional = expected_positionals[-1]

        if variadic_positional is None:
            if len(positionals) != len(expected_positionals):
                raise PolicyValidationError(
                    rule.id,
                    f"Expected {len(expected_positionals)} positional arg(s) "
                    f"({', '.join(p.name for p in expected_positionals)}), "
                    f"got {len(positionals)}",
                )

            for pos_cfg, pos_val in zip(expected_positionals, positionals):
                self._validate_positional_value(rule.id, pos_cfg, pos_val)
            return flags + positionals

        fixed_positionals = expected_positionals[:-1]
        min_positionals = len(fixed_positionals) + 1
        if len(positionals) < min_positionals:
            raise PolicyValidationError(
                rule.id,
                f"Expected at least {min_positionals} positional arg(s) "
                f"({', '.join(p.name for p in expected_positionals)}), "
                f"got {len(positionals)}",
            )

        for pos_cfg, pos_val in zip(
            fixed_positionals, positionals[: len(fixed_positionals)]
        ):
            self._validate_positional_value(rule.id, pos_cfg, pos_val)

        for pos_val in positionals[len(fixed_positionals) :]:
            self._validate_positional_value(rule.id, variadic_positional, pos_val)

        return flags + positionals

    def _validate_positional_value(
        self,
        rule_id: str,
        pos_cfg: PositionalArg,
        pos_val: str,
    ) -> None:
        if pos_cfg.enum is not None and pos_val not in pos_cfg.enum:
            raise PolicyValidationError(
                rule_id,
                f"Positional '{pos_cfg.name}' value '{pos_val}' "
                f"not in allowed values: {pos_cfg.enum}",
            )
        if pos_cfg.pattern is not None and not re.fullmatch(pos_cfg.pattern, pos_val):
            raise PolicyValidationError(
                rule_id,
                f"Positional '{pos_cfg.name}' value '{pos_val}' "
                f"does not match pattern: {pos_cfg.pattern}",
            )
