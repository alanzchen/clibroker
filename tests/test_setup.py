"""First-run setup produces a runnable demo while protecting local credentials."""

from __future__ import annotations

import json
import os
import stat
import subprocess

import pytest

from clibroker import setup
from clibroker.__main__ import main
from clibroker.config import load_config
from clibroker.policy import PolicyEngine


def test_init_creates_valid_private_config_and_runnable_demo(tmp_path, capsys):
    directory = tmp_path / "local broker"
    main(["init", "--directory", str(directory)])
    output = capsys.readouterr().out
    config = load_config(directory / "config.yaml")
    owner, agent = config.server.auth.tokens
    assert owner.role == "owner"
    assert agent.role == "agent"
    assert owner.value != agent.value
    assert len(owner.value) >= 32
    assert len(agent.value) >= 32
    assert owner.value not in output
    assert agent.value not in output
    assert (directory / "owner-token.txt").read_text().strip() == owner.value
    assert (directory / "agent-token.txt").read_text().strip() == agent.value
    assert config.server.control.database_path == str(directory / "control.sqlite3")
    assert "127.0.0.1:8080/dashboard/" in output
    assert "clibroker --config" in output
    assert config.tools["demo"].rules[0].require_approval is False
    assert config.tools["demo"].rules[1].require_approval is True
    policy = PolicyEngine(config)
    for action in ("inspect", "preview"):
        result = policy.evaluate("demo", [action])
        completed = subprocess.run(
            result.full_argv, env={}, capture_output=True, text=True, check=True
        )
        assert json.loads(completed.stdout)["action"] == action
    # Only the setup files exist; running the demo does not create application data.
    assert {p.name for p in directory.iterdir()} == {
        "config.yaml",
        "owner-token.txt",
        "agent-token.txt",
        "demo.py",
    }
    if os.name == "posix":
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        for file in directory.iterdir():
            assert stat.S_IMODE(file.stat().st_mode) == 0o600


def test_init_refuses_to_overwrite_existing_setup(tmp_path):
    directory = tmp_path / "local"
    setup.initialize(directory)
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        setup.initialize(directory)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before


@pytest.mark.parametrize("existing", ["owner-token.txt", "control.sqlite3"])
def test_init_preserves_existing_credentials_or_database(tmp_path, existing):
    directory = tmp_path / "local"
    directory.mkdir(mode=0o700)
    (directory / existing).write_text("existing data")
    with pytest.raises(FileExistsError):
        setup.initialize(directory)
    assert list(directory.iterdir()) == [directory / existing]
    assert (directory / existing).read_text() == "existing data"


@pytest.mark.parametrize("existing_directory", [False, True])
def test_init_rolls_back_partial_creation(tmp_path, monkeypatch, existing_directory):
    directory = tmp_path / "local"
    if existing_directory:
        directory.mkdir(mode=0o700)
    write = setup._write_private_file

    def fail_partway(path, content, created):
        if path.name == "agent-token.txt":
            raise OSError("disk full")
        write(path, content, created)

    monkeypatch.setattr(setup, "_write_private_file", fail_partway)
    with pytest.raises(OSError, match="disk full"):
        setup.initialize(directory)
    assert directory.exists() is existing_directory
    if existing_directory:
        assert not list(directory.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory permissions")
def test_init_rejects_shared_directory(tmp_path):
    directory = tmp_path / "shared"
    directory.mkdir()
    directory.chmod(0o755)
    with pytest.raises(ValueError, match="permissions 0700"):
        setup.initialize(directory)
    assert not list(directory.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="Unprivileged symlink support")
def test_init_rejects_symlink_directory(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory = tmp_path / "local"
    directory.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic link"):
        setup.initialize(directory)
    assert directory.is_symlink()
    assert not list(target.iterdir())


def test_original_server_command_is_preserved(tmp_path, monkeypatch):
    config_path = setup.initialize(tmp_path / "local")
    import clibroker.__main__ as cli

    app = object()
    called = {}
    monkeypatch.setattr(cli, "create_app", lambda config: app)
    monkeypatch.setattr(
        cli.uvicorn,
        "run",
        lambda application, **kwargs: called.update(app=application, **kwargs),
    )
    main(["--config", str(config_path)])
    assert called == {"app": app, "host": "127.0.0.1", "port": 8080, "reload": False}
