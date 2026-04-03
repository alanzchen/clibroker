"""CLI entry point — load config and start uvicorn."""

from __future__ import annotations

import argparse
import sys

import uvicorn

from .app import create_app
from .config import load_config


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="clibroker",
        description="Policy-driven CLI command broker",
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
