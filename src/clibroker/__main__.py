"""CLI entry point — load config and start uvicorn."""

from __future__ import annotations

import argparse
import shlex
import sys

import uvicorn

from .app import create_app
from .config import load_config
from .setup import initialize


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "init":
        parser = argparse.ArgumentParser(
            prog="clibroker init",
            description="Create a private local demo and owner dashboard",
        )
        parser.add_argument(
            "--directory",
            default="clibroker-local",
            help="New private setup directory (default: ./clibroker-local)",
        )
        args = parser.parse_args(argv[1:])
        try:
            config_path = initialize(args.directory)
        except (OSError, ValueError) as exc:
            parser.exit(1, f"Setup failed: {exc}\n")
        print(f"Created local demo: {config_path}")
        print(f"Start: clibroker --config {shlex.quote(str(config_path))}")
        print("Open: http://127.0.0.1:8080/dashboard/")
        print(f"Owner sign-in credential: {config_path.parent / 'owner-token.txt'}")
        print(f"Assistant credential: {config_path.parent / 'agent-token.txt'}")
        print(
            "Use the owner credential in the dashboard. Try Check your connection, then Try an approval."
        )
        return
    parser = argparse.ArgumentParser(
        prog="clibroker",
        description="Policy-driven CLI command broker",
        epilog="First time? Run clibroker init --directory ./clibroker-local",
    )
    parser.add_argument(
        "--config",
        "-c",
        required=True,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable auto-reload (development only)",
    )
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"Failed to load config: {exc}", file=sys.stderr)
        sys.exit(1)

    # Parse bind address
    host, _, port_str = config.server.bind.rpartition(":")
    host = host or "127.0.0.1"
    port = int(port_str) if port_str else 8080

    app = create_app(config)
    uvicorn.run(app, host=host, port=port, reload=args.reload)


if __name__ == "__main__":
    main()
