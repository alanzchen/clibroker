"""Shared test fixtures."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from clibroker.app import create_app
from clibroker.config import Config


def make_config(
    *,
    executable: str = "/usr/bin/echo",
    token_reader: str = "test-reader-token",
    token_operator: str = "test-operator-token",
    extra_yaml: str = "",
) -> Config:
    """Build a Config for testing with sensible defaults."""
    raw = yaml.safe_load(
        textwrap.dedent(f"""\
        server:
          bind: "127.0.0.1:9999"
          request_timeout_s: 10.0
          auth:
            type: bearer
            tokens:
              - name: reader
                value: "{token_reader}"
                allow_rules:
                  - list_messages
                  - read_message
              - name: operator
                value: "{token_operator}"
                allow_rules:
                  - list_messages
                  - read_message
                  - move_message
        tools:
          himalaya:
            executable: "{executable}"
            default_args: ["--output", "json"]
            env:
              HOME: "/tmp/clibroker-test"
            timeout_s: 5.0
            max_output_bytes: 65536
            rules:
              - id: list_messages
                command: ["message", "list"]
                effect: allow
                flags:
                  allowed: ["--account", "--folder", "--page"]
                  standalone: ["--unread"]
                positionals: []
              - id: read_message
                command: ["message", "read"]
                effect: allow
                inject_args: ["--preview"]
                flags:
                  allowed: ["--account", "--folder"]
                positionals:
                  - name: id
                    pattern: "^[0-9]+$"
              - id: move_message
                command: ["message", "move"]
                effect: allow
                flags:
                  allowed: ["--account", "--folder"]
                positionals:
                  - name: id
                    pattern: "^[0-9]+$"
                  - name: destination
                    enum: ["Inbox", "Archive", "Flagged"]
              - id: deny_delete
                command: ["message", "delete"]
                effect: deny
        {extra_yaml}
        """)
    )
    return Config.model_validate(raw)


@pytest.fixture
def config() -> Config:
    return make_config()


@pytest.fixture
def app(config: Config):
    return create_app(config)
