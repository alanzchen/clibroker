"""CLI entrypoint for the clibroker client."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import ClientBackendError, build_backend, load_client_config


def main(argv: list[str] | None = None) -> int:
    """Run the client CLI."""

    parser = argparse.ArgumentParser(
        prog="clibroker-client",
        description="Client for a remote clibroker server",
    )
    parser.add_argument(
        "--config",
        "-c",
        required=True,
        help="Path to the client YAML configuration file",
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
    config = load_client_config(args.config)

    if args.command == "config":
        return _show_config(config, args.backend)

    backend = build_backend(config, args.backend)

    if args.command == "tools":
        remote = await backend.fetch_config()
        if args.json:
            print(json.dumps(remote.model_dump(), indent=2))
            return 0

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
        return 0

    if args.command == "execute":
        forwarded_argv = list(args.argv)
        if forwarded_argv[:1] == ["--"]:
            forwarded_argv = forwarded_argv[1:]

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


if __name__ == "__main__":
    sys.exit(main())
