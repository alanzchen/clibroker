"""CLI entrypoint for the clibroker client."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import defaultdict

from . import (
    ClientBackendError,
    build_backend,
    load_client_config,
    resolve_client_config_path,
)


def main(argv: list[str] | None = None) -> int:
    """Run the client CLI."""

    parser = argparse.ArgumentParser(
        prog="clibroker-client",
        description="Client for a remote clibroker server",
    )
    parser.add_argument(
        "--config",
        "-c",
        help=(
            "Path to the client YAML configuration file. Defaults to "
            "$CLIBROKER_CLIENT_CONFIG, ~/.openclaw/clibroker-client.yaml, "
            "or ${XDG_CONFIG_HOME:-~/.config}/clibroker/client.yaml"
        ),
    )
    parser.add_argument(
        "--backend",
        help="Override the backend name from default_backend",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    tools_parser = subparsers.add_parser(
        "tools", help="List tools exposed by the server"
    )
    tools_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Print the raw discovery document as JSON",
    )

    execute_parser = subparsers.add_parser(
        "execute",
        help="Execute a broker tool with argv forwarded to the server",
    )
    execute_parser.add_argument("tool", help="Wrapped tool name, such as 'himalaya'")
    execute_parser.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="Arguments for the wrapped tool; place them after --",
    )

    config_parser = subparsers.add_parser("config", help="Inspect client config")
    config_subparsers = config_parser.add_subparsers(
        dest="config_command", required=True
    )
    config_subparsers.add_parser("show", help="Show the selected local backend config")
    config_subparsers.add_parser("list", help="List configured backends")

    args = parser.parse_args(argv)

    try:
        return asyncio.run(_run(args))
    except ClientBackendError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (RuntimeError, ValueError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


async def _run(args: argparse.Namespace) -> int:
    config = load_client_config(resolve_client_config_path(args.config))

    if args.command == "config":
        if args.config_command == "show":
            return _show_config(config, args.backend)
        if args.config_command == "list":
            return _list_backends(config)
        raise ValueError(f"Unsupported config command: {args.config_command}")

    if args.command == "tools":
        if args.backend or len(config.backends) == 1:
            backend = build_backend(config, args.backend)
            remote = await backend.fetch_config()
            if args.json:
                print(json.dumps(remote.model_dump(), indent=2))
                return 0

            _print_remote_tools(remote)
            return 0

        remotes = await _fetch_all_remote_configs(config)
        if args.json:
            print(json.dumps(_aggregate_remote_configs(config, remotes), indent=2))
            return 0

        _print_aggregated_tools(config, remotes)
        return 0

    if args.command == "execute":
        forwarded_argv = list(args.argv)
        if forwarded_argv[:1] == ["--"]:
            forwarded_argv = forwarded_argv[1:]

        backend = await _resolve_backend_for_tool(config, args.tool, args.backend)
        result = await backend.execute(args.tool, forwarded_argv)
        print(json.dumps(result.model_dump(), indent=2))
        if result.ok:
            return 0
        return result.exit_code if result.exit_code > 0 else 1

    raise ValueError(f"Unsupported command: {args.command}")


def _show_config(config, backend_name: str | None) -> int:  # noqa: ANN001
    backend_cfg = config.get_backend(backend_name)
    payload = {
        "default_backend": config.default_backend,
        "selected_backend": backend_name or config.default_backend,
        "backend": backend_cfg.redacted_dict(),
    }
    print(json.dumps(payload, indent=2))
    return 0


def _list_backends(config) -> int:  # noqa: ANN001
    payload = {
        "default_backend": config.default_backend,
        "backends": [
            {
                "name": name,
                "is_default": name == config.default_backend,
                "config": backend.redacted_dict(),
            }
            for name, backend in config.list_backends()
        ],
    }
    print(json.dumps(payload, indent=2))
    return 0


async def _fetch_all_remote_configs(config):  # noqa: ANN001
    remotes = []
    for backend_name, _backend_cfg in config.list_backends():
        backend = build_backend(config, backend_name)
        try:
            remote = await backend.fetch_config()
        except ClientBackendError as exc:
            raise ClientBackendError(
                f"Failed to fetch client config for backend '{backend_name}': {exc}"
            ) from exc
        remotes.append((backend_name, backend, remote))
    return remotes


async def _resolve_backend_for_tool(config, tool_name: str, backend_name: str | None):  # noqa: ANN001
    if backend_name or len(config.backends) == 1:
        return build_backend(config, backend_name)

    remotes = await _fetch_all_remote_configs(config)
    matching = [
        (name, backend)
        for name, backend, remote in remotes
        if any(tool.name == tool_name for tool in remote.tools)
    ]

    if not matching:
        available = sorted(
            {
                tool.name
                for _name, _backend, remote in remotes
                for tool in remote.tools
            }
        )
        raise RuntimeError(
            f"Tool '{tool_name}' was not found in any configured backend. "
            f"Available tools: {', '.join(available) if available else 'none'}"
        )

    if len(matching) > 1:
        names = ", ".join(sorted(name for name, _backend in matching))
        raise RuntimeError(
            f"Tool '{tool_name}' exists in multiple backends ({names}). "
            "Specify --backend <name>."
        )

    return matching[0][1]


def _print_remote_tools(remote) -> None:  # noqa: ANN001
    print(f"Client: {remote.client_name}")
    print(f"Execute URL: {remote.execute_url}")
    for tool in remote.tools:
        print(tool.name)
        for rule in tool.rules:
            parts = [f"  {rule.id}: {' '.join(rule.command)}"]
            if rule.flags:
                parts.append(f"flags={', '.join(rule.flags)}")
            if rule.standalone_flags:
                parts.append(f"standalone_flags={', '.join(rule.standalone_flags)}")
            if rule.positionals:
                pos_names = ", ".join(
                    f"{pos.name}..." if pos.variadic else pos.name
                    for pos in rule.positionals
                )
                parts.append(f"positionals={pos_names}")
            print(" ".join(parts))


def _aggregate_remote_configs(config, remotes):  # noqa: ANN001
    tool_index = defaultdict(list)
    backends = []
    for backend_name, _backend, remote in remotes:
        backends.append(
            {
                "name": backend_name,
                "is_default": backend_name == config.default_backend,
                **remote.model_dump(),
            }
        )
        for tool in remote.tools:
            tool_index[tool.name].append(backend_name)

    return {
        "default_backend": config.default_backend,
        "backends": backends,
        "tool_index": [
            {
                "name": tool_name,
                "backends": sorted(backend_names),
                "conflict": len(backend_names) > 1,
            }
            for tool_name, backend_names in sorted(tool_index.items())
        ],
    }


def _print_aggregated_tools(config, remotes) -> None:  # noqa: ANN001
    payload = _aggregate_remote_configs(config, remotes)
    print(f"Default backend: {payload['default_backend']}")
    print("Configured backends:")
    for backend in payload["backends"]:
        suffix = " (default)" if backend["is_default"] else ""
        print(f"- {backend['name']}: {backend['client_name']}{suffix}")
    print("Tools:")
    for tool in payload["tool_index"]:
        suffix = " [conflict: specify --backend]" if tool["conflict"] else ""
        print(f"- {tool['name']} ({', '.join(tool['backends'])}){suffix}")


if __name__ == "__main__":
    sys.exit(main())
