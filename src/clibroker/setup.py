"""Create a private, runnable local demo without overwriting existing files."""

from __future__ import annotations

import os
import secrets
import stat
import sys
from pathlib import Path

import yaml

from .config import Config

_DEMO_SCRIPT = '''"""Harmless clibroker onboarding demo: prints JSON, changes nothing."""
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("action", choices=["inspect", "preview"])
args = parser.parse_args()
print(json.dumps({
    "action": args.action,
    "message": "Your broker is working." if args.action == "inspect" else
               "You approved this demo action. No files or accounts were changed.",
}))
'''


def _write_private_file(path: Path, content: str, created: list[Path]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    created.append(path)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


def initialize(directory: str | Path) -> Path:
    """Return the new config path, or roll back files created during a failure.

    Existing directories must be private and owned by this user on POSIX.
    Existing files, including a previously created database, are never replaced.
    """
    directory = Path(directory).expanduser().absolute()
    made_directory = False
    created: list[Path] = []
    names = (
        "config.yaml",
        "owner-token.txt",
        "agent-token.txt",
        "demo.py",
        "control.sqlite3",
    )
    try:
        if directory.is_symlink():
            raise ValueError("Setup directory must not be a symbolic link")
        try:
            directory.mkdir(mode=0o700)
            made_directory = True
        except FileExistsError:
            pass
        info = directory.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Setup path must be a directory")
        if os.name == "posix" and (
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError(
                "Setup directory must be owned by you with permissions 0700"
            )
        for name in names:
            path = directory / name
            if path.exists() or path.is_symlink():
                raise FileExistsError(f"Refusing to overwrite {path}")

        owner_token = secrets.token_urlsafe(32)
        agent_token = secrets.token_urlsafe(32)
        rules = ["inspect_demo", "preview_demo"]
        data = {
            "server": {
                "bind": "127.0.0.1:8080",
                "control": {"database_path": str(directory / "control.sqlite3")},
                "auth": {
                    "tokens": [
                        {
                            "name": "Local owner",
                            "role": "owner",
                            "value": owner_token,
                            "allow_rules": rules,
                        },
                        {
                            "name": "Demo assistant",
                            "role": "agent",
                            "value": agent_token,
                            "allow_rules": rules,
                        },
                    ]
                },
            },
            "tools": {
                "demo": {
                    "title": "Getting started",
                    "description": "Try automatic access and approvals with a harmless local demo.",
                    "executable": str(Path(sys.executable).absolute()),
                    "default_args": [str(directory / "demo.py")],
                    "file_sharing": {"expose_working_dir": False},
                    "rules": [
                        {
                            "id": rules[0],
                            "command": ["inspect"],
                            "effect": "allow",
                            "title": "Check your connection",
                            "description": "Print a welcome message. This action changes nothing.",
                        },
                        {
                            "id": rules[1],
                            "command": ["preview"],
                            "effect": "allow",
                            "title": "Try an approval",
                            "description": "Ask for approval, then print a confirmation. Nothing is changed.",
                            "require_approval": True,
                        },
                    ],
                },
            },
        }
        Config.model_validate(data)
        _write_private_file(directory / "demo.py", _DEMO_SCRIPT, created)
        _write_private_file(directory / "owner-token.txt", owner_token + "\n", created)
        _write_private_file(directory / "agent-token.txt", agent_token + "\n", created)
        _write_private_file(
            directory / "config.yaml", yaml.safe_dump(data, sort_keys=False), created
        )
        return directory / "config.yaml"
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if made_directory:
            directory.rmdir()
        raise
