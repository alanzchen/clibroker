"""Persistent, owner-managed controls for brokered command requests.

YAML policy and RBAC remain the outer security boundary. Runtime decisions can
only gate commands that already pass those checks. Approval claims are atomic;
a claimed request is never automatically retried, including after interruption.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import HTTPException

from .config import Config
from .models import ExecuteResponse
from .policy import PolicyDenied, PolicyNoMatch, PolicyValidationError

if TYPE_CHECKING:
    from .execution import ExecutionService


def _iso(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat()


class ControlService:
    def __init__(self, config: Config) -> None:
        self.config = config
        settings = config.server.control
        assert settings is not None
        self.path = Path(settings.database_path).expanduser().absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("Control database must not be a symbolic link")
        fd = os.open(
            self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        os.fchmod(fd, 0o600)
        os.close(fd)
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS agents (name TEXT PRIMARY KEY, paused INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS decisions (client TEXT NOT NULL, rule_id TEXT NOT NULL,
                    decision TEXT NOT NULL, PRIMARY KEY(client,rule_id));
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, client TEXT NOT NULL, tool TEXT NOT NULL,
                    argv TEXT NOT NULL, rule_id TEXT NOT NULL, state TEXT NOT NULL,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL,
                    fingerprint TEXT NOT NULL, result TEXT, running_until REAL, decided_by TEXT, decided_at REAL);
                CREATE INDEX IF NOT EXISTS requests_client_created ON requests(client,created_at DESC);
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(requests)")}
            for column, kind in (("decided_by", "TEXT"), ("decided_at", "REAL")):
                if column not in columns:
                    db.execute(f"ALTER TABLE requests ADD COLUMN {column} {kind}")

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def token(self, client: str):
        return next(
            (t for t in self.config.server.auth.tokens if t.name == client), None
        )

    def ensure_active(self, client: str) -> None:
        if self.token(client) is None:
            raise HTTPException(403, "Agent is no longer configured")
        with self.db() as db:
            row = db.execute(
                "SELECT paused FROM agents WHERE name=?", (client,)
            ).fetchone()
        if row and row["paused"]:
            raise HTTPException(403, "Agent is paused")

    def decision(self, client: str, rule) -> str:
        with self.db() as db:
            row = db.execute(
                "SELECT decision FROM decisions WHERE client=? AND rule_id=?",
                (client, rule.id),
            ).fetchone()
        decision = (
            row["decision"] if row else ("ask" if rule.require_approval else "allow")
        )
        # A configuration-level approval requirement is a hard ceiling too.
        return "ask" if rule.require_approval and decision == "allow" else decision

    def fingerprint(self, client: str, tool: str, argv: list[str]) -> str:
        token = self.token(client)
        # Hash (never expose/store) execution configuration including credentials.
        value = {
            "tool": self.config.tools[tool].model_dump(),
            "argv": argv,
            "token": token.model_dump() if token else None,
            "credential": token.resolve_value() if token else None,
        }
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    def expire(self, db) -> None:
        now = time.time()
        db.execute(
            "UPDATE requests SET state='expired' WHERE state='pending' AND expires_at<=?",
            (now,),
        )
        # A lost in-flight operation has an unknown outcome, never retry it.
        db.execute(
            "UPDATE requests SET state='interrupted' WHERE state='running' AND running_until<=?",
            (now,),
        )

    def record(
        self,
        client: str,
        tool: str,
        argv: list[str],
        rule_id: str,
        state: str,
        fingerprint: str = "",
    ) -> str:
        encoded = json.dumps(argv, ensure_ascii=True)
        if len(encoded) > 65536:
            raise HTTPException(
                413, "Command arguments exceed the control history limit"
            )
        request_id = uuid.uuid4().hex
        now = time.time()
        ttl = self.config.server.control.approval_ttl_s
        with self.db() as db:
            self.expire(db)
            if (
                state == "pending"
                and db.execute(
                    "SELECT COUNT(*) FROM requests WHERE client=? AND state='pending'",
                    (client,),
                ).fetchone()[0]
                >= 100
            ):
                raise HTTPException(
                    429, "Too many pending requests; review existing requests first"
                )
            db.execute(
                "INSERT INTO requests(id,client,tool,argv,rule_id,state,created_at,expires_at,fingerprint,running_until) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    client,
                    tool,
                    encoded,
                    rule_id,
                    state,
                    now,
                    now + ttl,
                    fingerprint,
                    now + max(self.config.tools[tool].timeout_s, 1) + 60
                    if tool in self.config.tools
                    else now + 60,
                ),
            )
            # Keep at most 1000 terminal requests; pending/running are never pruned.
            db.execute(
                "DELETE FROM requests WHERE state NOT IN ('pending','running') AND id NOT IN (SELECT id FROM requests WHERE state NOT IN ('pending','running') ORDER BY created_at DESC LIMIT 1000)"
            )
        return request_id

    def finish(
        self, request_id: str, result: ExecuteResponse, state: str | None = None
    ) -> ExecuteResponse:
        state = state or ("succeeded" if result.ok else "failed")
        result = result.model_copy(update={"request_id": request_id, "state": state})
        stored = result.model_dump(mode="json")
        if len(json.dumps(stored)) > 262144:
            stored["stdout"] = (
                "Output too large for saved history. Retrieve the original execution response or artifacts."
            )
            stored["stderr"] = str(stored["stderr"])[:16384]
            stored["artifacts"] = stored["artifacts"][:100]
        with self.db() as db:
            db.execute(
                "UPDATE requests SET state=?,result=? WHERE id=?",
                (state, json.dumps(stored), request_id),
            )
        return result

    def decode(self, row) -> dict:
        value = dict(row)
        value.pop("fingerprint", None)
        value.pop("running_until", None)
        value["argv"] = json.loads(value["argv"])
        value["result"] = json.loads(value["result"]) if value["result"] else None
        value["created_at"] = _iso(value["created_at"])
        value["expires_at"] = _iso(value["expires_at"])
        value["decided_at"] = (
            _iso(value["decided_at"]) if value.get("decided_at") else None
        )
        return value

    def request(self, request_id: str, client) -> dict:
        with self.db() as db:
            self.expire(db)
            row = db.execute(
                "SELECT * FROM requests WHERE id=?", (request_id,)
            ).fetchone()
        if row is None or (client.role != "owner" and row["client"] != client.name):
            raise HTTPException(404, "Request not found")
        return self.decode(row)

    async def execute(
        self,
        execution: ExecutionService,
        tool: str,
        argv: list[str],
        *,
        client: str,
        allowed_rules,
    ) -> ExecuteResponse:
        from .execution import ExecutionForbidden, execution_error

        # Validate first. Never create an approvable request for a denied operation.
        try:
            self.ensure_active(client)
            configured_rules = set(self.token(client).allow_rules)
            allowed_rules = (
                configured_rules
                if allowed_rules is None
                else configured_rules & set(allowed_rules)
            )
            match = execution.policy.evaluate(tool, argv)
            if allowed_rules is not None and match.rule_id not in allowed_rules:
                raise ExecutionForbidden(
                    "Not authorized for this operation", match.rule_id
                )
            decision = self.decision(client, match.rule)
            if decision == "block":
                raise HTTPException(403, "Blocked by the agent's permission settings")
        except (
            HTTPException,
            ExecutionForbidden,
            PolicyDenied,
            PolicyNoMatch,
            PolicyValidationError,
        ) as exc:
            rule_id = getattr(exc, "rule_id", "")
            request_id = self.record(client, tool, argv, rule_id, "blocked")
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            result = self.finish(
                request_id, execution_error(detail, rule_id), "blocked"
            )
            if isinstance(exc, ExecutionForbidden):
                raise
            return result
        state = "pending" if decision == "ask" else "running"
        request_id = self.record(
            client,
            tool,
            argv,
            match.rule_id,
            state,
            self.fingerprint(client, tool, argv),
        )
        if state == "pending":
            return execution_error(
                "Owner approval required. Open approval_url, then poll with clibroker_request_status or GET /control/requests/"
                + request_id,
                match.rule_id,
            ).model_copy(
                update={
                    "request_id": request_id,
                    "state": "pending",
                    "approval_url": f"/dashboard/?request={request_id}",
                }
            )
        return await self.run(execution, request_id, tool, argv, client, allowed_rules)

    async def run(self, execution, request_id, tool, argv, client, allowed_rules):
        from .execution import ExecutionForbidden, execution_error

        try:
            result = await execution._execute(
                tool, argv, client=client, allowed_rules=allowed_rules
            )
        except asyncio.CancelledError:
            self.finish(
                request_id,
                execution_error(
                    "Execution was interrupted; its outcome may be unknown. Do not automatically retry."
                ),
                "interrupted",
            )
            raise
        except ExecutionForbidden as exc:
            result = execution_error(str(exc), exc.rule_id)
        except Exception:  # noqa: BLE001 - return a stable, secret-free execution error
            from .audit import get_audit_logger

            get_audit_logger().exception(
                "controlled_execution_failed", client=client, tool=tool
            )
            result = execution_error("Internal server error")
        return self.finish(request_id, result)

    async def decide(self, execution, request_id: str, decision: str, owner) -> dict:
        from .execution import execution_error

        with self.db() as db:
            self.expire(db)
            row = db.execute(
                "SELECT * FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Request not found")
            if row["state"] != "pending":
                raise HTTPException(409, "Request has already been decided or expired")
            target = "rejected" if decision == "reject" else "running"
            claimed = db.execute(
                "UPDATE requests SET state=?,running_until=?,decided_by=?,decided_at=? WHERE id=? AND state='pending'",
                (
                    target,
                    time.time()
                    + max(
                        self.config.tools.get(row["tool"]).timeout_s
                        if row["tool"] in self.config.tools
                        else 1,
                        1,
                    )
                    + 60,
                    owner.name,
                    time.time(),
                    request_id,
                ),
            ).rowcount
            if not claimed:
                raise HTTPException(409, "Request has already been decided")
        if decision == "reject":
            self.finish(
                request_id,
                execution_error("Rejected by owner", row["rule_id"]),
                "rejected",
            )
        else:
            argv = json.loads(row["argv"])
            token = self.token(row["client"])
            try:
                self.ensure_active(row["client"])
                match = execution.policy.evaluate(row["tool"], argv)
                if (
                    token is None
                    or match.rule_id not in token.allow_rules
                    or self.decision(row["client"], match.rule) == "block"
                ):
                    raise ValueError("The agent no longer has permission")
                if (
                    self.fingerprint(row["client"], row["tool"], argv)
                    != row["fingerprint"]
                ):
                    raise ValueError(
                        "Configuration changed; submit a new request for review"
                    )
            except (
                HTTPException,
                ValueError,
                KeyError,
                PolicyDenied,
                PolicyNoMatch,
                PolicyValidationError,
            ):
                self.finish(
                    request_id,
                    execution_error(
                        "Access or configuration changed; submit a new request for review"
                    ),
                    "blocked",
                )
            else:
                await self.run(
                    execution,
                    request_id,
                    row["tool"],
                    argv,
                    row["client"],
                    token.allow_rules,
                )
        return self.request(request_id, owner)

    def view(self, client) -> dict:
        with self.db() as db:
            self.expire(db)
            where = "" if client.role == "owner" else "WHERE client=?"
            params = () if client.role == "owner" else (client.name,)
            rows = db.execute(
                f"SELECT * FROM requests {where} ORDER BY created_at DESC LIMIT 200",
                params,
            ).fetchall()
            pending_where = "WHERE state='pending'" + (
                "" if client.role == "owner" else " AND client=?"
            )
            pending = db.execute(
                f"SELECT * FROM requests {pending_where} ORDER BY created_at LIMIT 200",
                params,
            ).fetchall()
            pauses = {
                r["name"]: bool(r["paused"]) for r in db.execute("SELECT * FROM agents")
            }
        agents = []
        if client.role == "owner":
            for token in self.config.server.auth.tokens:
                if token.role == "owner":
                    continue
                rules = [
                    {
                        "id": rule.id,
                        "tool": name,
                        "title": rule.title or rule.id,
                        "description": rule.description,
                        "decision": self.decision(token.name, rule),
                        "requires_approval": rule.require_approval,
                    }
                    for name, tool in self.config.tools.items()
                    for rule in tool.rules
                    if rule.effect == "allow" and rule.id in token.allow_rules
                ]
                agents.append(
                    {
                        "name": token.name,
                        "paused": pauses.get(token.name, False),
                        "rules": rules,
                    }
                )
        return {
            "enabled": True,
            "role": client.role,
            "agents": agents,
            "requests": [self.decode(r) for r in pending],
            "activity": [{**self.decode(r), "result": None} for r in rows],
        }

    def set_paused(self, name: str, paused: bool):
        token = self.token(name)
        if token is None or token.role == "owner":
            raise HTTPException(404, "Agent not found")
        with self.db() as db:
            db.execute(
                "INSERT INTO agents(name,paused) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET paused=excluded.paused",
                (name, paused),
            )
        return {"name": name, "paused": paused}

    def set_decision(self, name: str, rule_id: str, decision: str):
        token = self.token(name)
        rule = next(
            (
                r
                for t in self.config.tools.values()
                for r in t.rules
                if r.id == rule_id and r.effect == "allow"
            ),
            None,
        )
        if (
            token is None
            or token.role == "owner"
            or rule is None
            or rule_id not in token.allow_rules
        ):
            raise HTTPException(404, "Agent capability not found")
        if rule.require_approval and decision == "allow":
            raise HTTPException(
                409, "This operation requires approval in server configuration"
            )
        with self.db() as db:
            db.execute(
                "INSERT INTO decisions(client,rule_id,decision) VALUES(?,?,?) ON CONFLICT(client,rule_id) DO UPDATE SET decision=excluded.decision",
                (name, rule_id, decision),
            )
        return {"id": rule_id, "decision": decision}
