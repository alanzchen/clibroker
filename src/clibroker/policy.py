"""Policy engine — command-tree matching, deny-by-default, argument validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import (
    ArgvNormalizationConfig,
    Config,
    GlobalArgPattern,
    PositionalArg,
    Rule,
    ToolConfig,
)


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
    rule: Rule
    tool_config: ToolConfig
    full_argv: list[str]  # the complete argv vector to execute
    normalized_argv: list[str]
    inject_args_offset: int


@dataclass
class _TreeNode:
    """Internal node in the command tree."""

    children: dict[str, _TreeNode] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)


@dataclass
class _MatchedGlobalArg:
    """A global arg matched against a tool normalization pattern."""

    pattern: GlobalArgPattern
    arg: str
    key: str
    value: str


@dataclass
class _NormalizedArgv:
    """Normalized argv split into leading globals and command argv."""

    leading_global_args: list[str]
    command_argv: list[str]
    matched_globals: list[_MatchedGlobalArg] = field(default_factory=list)


@dataclass
class _ParsedArguments:
    """One interpretation of argv using a candidate rule's option arities."""

    normalized: _NormalizedArgv
    flags: list[str] = field(default_factory=list)
    positionals: list[str] = field(default_factory=list)
    end_of_options: bool = False


@dataclass
class _CommandPath:
    """A command-tree path that matched a prefix of argv."""

    node: _TreeNode
    consumed: int
    matched_command: list[str]
    specificity: int


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

        normalization = tool_cfg.argv_normalization
        leading = self._split_leading_global_args(normalization, argv)
        leading_global_args = leading.leading_global_args
        command_argv = leading.command_argv

        # Walk the command tree to find matching literal and wildcard paths.
        # A command segment "*" matches exactly one argv token. Literal paths
        # are preferred over wildcard paths at the same depth.
        match, matched_prefix_nodes = self._match_command_path(tree, command_argv)

        if match is None:
            raise PolicyNoMatch(tool, argv)

        # Remaining argv after command path
        remaining = command_argv[match.consumed :]
        # Check deny rules on the matched node AND all ancestor nodes.
        # A deny on ["message", "delete"] cascades to deeper commands
        # like ["message", "delete", "batch"] so that adding a child
        # allow rule cannot silently bypass a parent deny.
        for prefix_node in matched_prefix_nodes:
            for rule in prefix_node.rules:
                if rule.effect == "deny":
                    raise PolicyDenied(rule.id)

        # Try all allow rules on the matched node. This lets a more specific
        # rule with positionals succeed when a simpler sibling rule rejects the
        # argv due to positional count.
        last_validation_error: PolicyValidationError | None = None
        for rule in match.node.rules:
            if rule.effect == "allow":
                try:
                    parsed = self._parse_rule_arguments(rule, remaining, normalization)
                    normalized_after_command = parsed.normalized
                    self._validate_global_arg_matches(
                        leading.matched_globals
                        + normalized_after_command.matched_globals
                    )
                    validated_argv = self._validate_rule(rule, parsed)
                except PolicyValidationError as exc:
                    last_validation_error = exc
                    continue
                # Build the full argv: executable + default_args + command + validated remainder
                full_argv = (
                    [tool_cfg.executable]
                    + tool_cfg.default_args
                    + leading_global_args
                    + normalized_after_command.leading_global_args
                    + match.matched_command
                )
                inject_args_offset = len(full_argv)
                full_argv += rule.inject_args + validated_argv
                return PolicyResult(
                    rule_id=rule.id,
                    rule=rule,
                    tool_config=tool_cfg,
                    full_argv=full_argv,
                    inject_args_offset=inject_args_offset,
                    normalized_argv=leading_global_args
                    + normalized_after_command.leading_global_args
                    + match.matched_command
                    + normalized_after_command.command_argv,
                )

        if last_validation_error is not None:
            raise last_validation_error

        raise PolicyNoMatch(tool, argv)

    def _match_command_path(
        self,
        tree: _TreeNode,
        argv: list[str],
    ) -> tuple[_CommandPath | None, list[_TreeNode]]:
        """Return the best command-path match plus all matching prefix nodes."""
        active = [
            _CommandPath(
                node=tree,
                consumed=0,
                matched_command=[],
                specificity=0,
            )
        ]
        rule_paths: list[_CommandPath] = []
        matched_prefix_nodes: list[_TreeNode] = []

        for part in argv:
            next_paths: list[_CommandPath] = []
            for path in active:
                exact = path.node.children.get(part)
                if exact is not None:
                    next_paths.append(
                        _CommandPath(
                            node=exact,
                            consumed=path.consumed + 1,
                            matched_command=path.matched_command + [part],
                            specificity=path.specificity + 1,
                        )
                    )

                wildcard = path.node.children.get("*")
                # Global options are not subcommands. Letting a wildcard consume
                # one would hide the actual command from literal deny rules.
                # Explicit literal option commands (e.g. --version) still work.
                if wildcard is not None and not part.startswith("-"):
                    next_paths.append(
                        _CommandPath(
                            node=wildcard,
                            consumed=path.consumed + 1,
                            matched_command=path.matched_command + [part],
                            specificity=path.specificity,
                        )
                    )

            if not next_paths:
                if part.startswith("-") and any(path.node.children for path in active):
                    # Options can separate a real CLI's subcommands. Falling
                    # back to an earlier pass-through rule here would hide a
                    # configured descendant (and its deny/RBAC checks).
                    return None, matched_prefix_nodes
                break

            matched_prefix_nodes.extend(path.node for path in next_paths)
            rule_paths.extend(path for path in next_paths if path.node.rules)
            active = next_paths

        if not rule_paths:
            return None, matched_prefix_nodes

        return (
            max(rule_paths, key=lambda path: (path.consumed, path.specificity)),
            matched_prefix_nodes,
        )

    def _split_leading_global_args(
        self,
        normalization: ArgvNormalizationConfig | None,
        argv: list[str],
    ) -> _NormalizedArgv:
        """Split configured global args that appear before the command path."""
        if normalization is None or not normalization.patterns:
            return _NormalizedArgv(leading_global_args=[], command_argv=argv)

        leading_matches: list[_MatchedGlobalArg] = []
        index = 0
        while index < len(argv):
            match = self._match_global_arg(normalization, argv[index])
            if match is None:
                break
            if "before_command" not in match.pattern.allow_positions:
                raise PolicyValidationError(
                    match.pattern.id,
                    f"Global arg '{argv[index]}' is not allowed before the command",
                )
            leading_matches.append(match)
            index += 1

        return _NormalizedArgv(
            leading_global_args=[match.arg for match in leading_matches],
            command_argv=argv[index:],
            matched_globals=leading_matches,
        )

    def _parse_rule_arguments(
        self,
        rule: Rule,
        argv: list[str],
        normalization: ArgvNormalizationConfig | None,
    ) -> _ParsedArguments:
        """Classify flags, their values and globals in a single boundary-aware pass."""
        matched_globals: list[_MatchedGlobalArg] = []
        filtered_argv: list[str] = []
        parsed = _ParsedArguments(
            normalized=_NormalizedArgv([], filtered_argv, matched_globals)
        )
        allowed_flags = set(rule.flags.allowed) if rule.flags else set()
        standalone_flags = set(rule.flags.standalone) if rule.flags else set()

        index = 0
        while index < len(argv):
            arg = argv[index]
            if arg == "--":
                # Everything after the separator is data, including strings
                # that look exactly like a configured global or an option.
                filtered_argv.extend(argv[index:])
                parsed.positionals.extend(argv[index + 1 :])
                parsed.end_of_options = True
                break

            match = (
                self._match_global_arg(normalization, arg) if normalization else None
            )
            if match is not None:
                if "after_command" not in match.pattern.allow_positions:
                    raise PolicyValidationError(
                        match.pattern.id,
                        f"Global arg '{arg}' is not allowed after the command",
                    )
                matched_globals.append(match)
                index += 1
                continue

            if rule.allow_any_args:
                if arg.startswith("-"):
                    # A pass-through rule declares no flag arities. Preserve
                    # the opaque tail instead of guessing which strings are
                    # option values and promoting them to active globals.
                    filtered_argv.extend(argv[index:])
                    break
                filtered_argv.append(arg)
                index += 1
                continue

            if not arg.startswith("-"):
                parsed.positionals.append(arg)
                filtered_argv.append(arg)
                index += 1
                continue

            flag, separator, inline_value = (
                arg.partition("=") if arg.startswith("--") else (arg, "", "")
            )
            if flag in standalone_flags:
                if separator:
                    raise PolicyValidationError(
                        rule.id, f"Standalone flag '{flag}' does not take a value"
                    )
                parsed.flags.append(flag)
                filtered_argv.append(arg)
                index += 1
                continue
            if flag not in allowed_flags:
                raise PolicyValidationError(rule.id, f"Flag '{flag}' is not allowed")

            if separator:
                parsed.flags.extend([flag, inline_value])
                filtered_argv.append(arg)
                index += 1
                continue
            if index + 1 >= len(argv) or argv[index + 1] == "--":
                raise PolicyValidationError(rule.id, f"Flag '{flag}' requires a value")
            # Consume the original value atomically. Never inspect its text
            # for global patterns or split its own --name=value spelling.
            parsed.flags.extend([flag, argv[index + 1]])
            filtered_argv.extend(argv[index : index + 2])
            index += 2

        parsed.normalized.leading_global_args = [match.arg for match in matched_globals]
        return parsed

    def _match_global_arg(
        self,
        normalization: ArgvNormalizationConfig,
        arg: str,
    ) -> "_MatchedGlobalArg | None":
        """Return a matched global-arg descriptor or ``None``."""
        if "=" not in arg:
            return None

        key, _, value = arg.partition("=")
        matched_pattern: GlobalArgPattern | None = None
        for pattern in normalization.patterns:
            if pattern.kind != "key_value":
                continue
            if not re.fullmatch(pattern.key_pattern, key):
                continue
            if pattern.value_pattern is not None and not re.fullmatch(
                pattern.value_pattern, value
            ):
                raise PolicyValidationError(
                    pattern.id,
                    f"Global arg '{arg}' value '{value}' does not match pattern: {pattern.value_pattern}",
                )
            matched_pattern = pattern
            break

        if matched_pattern is None:
            return None

        return _MatchedGlobalArg(pattern=matched_pattern, arg=arg, key=key, value=value)

    def _validate_global_arg_matches(
        self,
        matches: list["_MatchedGlobalArg"],
    ) -> None:
        """Reject ambiguous or conflicting normalized global args."""
        seen_by_pattern: dict[str, _MatchedGlobalArg] = {}
        seen_by_key: dict[str, _MatchedGlobalArg] = {}
        for match in matches:
            prior = seen_by_pattern.get(match.pattern.id)
            prior_key = seen_by_key.get(match.key)
            if prior_key is None:
                seen_by_key[match.key] = match
            elif not match.pattern.multiple and prior_key.value != match.value:
                raise PolicyValidationError(
                    match.pattern.id,
                    f"Conflicting global args '{prior_key.arg}' and '{match.arg}' are not allowed",
                )
            if prior is not None and not match.pattern.multiple:
                raise PolicyValidationError(
                    match.pattern.id,
                    f"Duplicate global arg '{match.arg}' is not allowed; canonical form is '{prior.arg}' before the command",
                )
            if prior is None:
                seen_by_pattern[match.pattern.id] = match

    def _validate_rule(self, rule: Rule, parsed: _ParsedArguments) -> list[str]:
        """Validate positional constraints after the shared argument parsing pass."""
        if rule.allow_any_args:
            return parsed.normalized.command_argv

        flags = parsed.flags
        positionals = parsed.positionals
        end_of_options = parsed.end_of_options

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
            return flags + (["--"] if end_of_options else []) + positionals

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

        return flags + (["--"] if end_of_options else []) + positionals

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
