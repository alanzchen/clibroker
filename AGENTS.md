# AGENTS

Project-specific guidance for future work in `/home/ubuntu/projects/clibroker`.

## Purpose

This project is a security-focused CLI broker.

It now has two product surfaces:

- server: wraps local CLI tools and enforces policy
- client: connects to the server, fetches token-scoped config, and forwards execution requests

Core invariants:

- Never invoke a shell
- Preserve deny-by-default policy behavior
- Preserve deny precedence, including deny cascading to child command paths
- Preserve per-token RBAC for both REST and MCP
- Never expose raw bearer tokens in URLs
- Keep subprocess environments explicit and minimal

## Architecture

- `src/clibroker/config.py`: Pydantic config models and YAML loading
- `src/clibroker/client/config.py`: client-side YAML config and env token resolution
- `src/clibroker/client/backend_http.py`: direct HTTP backend to the broker server
- `src/clibroker/client/__main__.py`: `clibroker-client` CLI
- `src/clibroker/policy.py`: command tree, allow/deny matching, argv validation
- `src/clibroker/auth.py`: bearer auth, hashed token storage, RBAC checks
- `src/clibroker/runner.py`: hardened subprocess execution with timeout/output caps
- `src/clibroker/routes.py`: REST `POST /execute`
- `src/clibroker/mcp_server.py`: MCP tool generation from allow rules
- `src/clibroker/app.py`: FastAPI app factory, `/health`, `/token-info`, MCP/SSE mounts

## Required Behaviors

- Use `asyncio.create_subprocess_exec`, never shell wrappers
- Keep the client as a thin transport layer; the server remains the source of truth for policy enforcement
- Keep `ToolConfig.executable` absolute-path validated
- Keep `Rule.command` non-empty
- Keep MCP URL slugs derived from `SHA-256(token)[:16]`
- Keep token comparison timing-safe with `hmac.compare_digest`
- Keep `/client-config` token-scoped and free of raw secrets/server internals
- Keep deny rules excluded from MCP tool registration
- Keep MCP handler policy validation in place for defense in depth
- Keep `/health` unauthenticated
- Keep `/token-info` authenticated

## Editing Guidance

- Prefer the smallest correct change
- Prefer `uv` for Python environment and package installation commands in docs and examples
- For system-wide CLI installation docs, prefer `uv tool install`; for local checkout/dev docs, prefer `uv venv` plus `uv pip`
- Do not weaken validation to make tests easier
- Avoid adding compatibility layers unless there is a real caller requirement
- Update docs and tests when changing config, API, auth, policy, or MCP behavior
- If a change affects security semantics, add or update tests first or alongside the code

## Testing Expectations

Before finishing substantial changes, run:

```bash
.venv/bin/python -m pytest tests -v
```

Current test coverage includes:

- REST auth and RBAC
- token-scoped `/client-config` discovery
- client config parsing, HTTP backend, and CLI behavior
- policy evaluation and validation
- subprocess hardening
- MCP registration and transport behavior
- security fixes around slugs, hashing, deny cascading, and flag parsing

## Common Pitfalls

- `httpx` `ASGITransport` does not run lifespan handlers by itself; use `asgi-lifespan` when testing MCP app startup
- mounted MCP endpoints require trailing slash at the mount root
- MCP JSON mode expects `Accept: application/json`
- SSE tests need timeout-bounded probing because the response is long-lived
- subprocess env may contain minimal runtime-specific values even when cleared; tests should check for absence of parent vars like `PATH`

## Documentation Expectations

If behavior changes, update these files when relevant:

- `README.md`
- `config.example.yaml`
- tests under `tests/`

## Current Gaps

Known follow-up work worth considering:

- rate limiting
- graceful subprocess shutdown during app shutdown
- regex/ReDoS hardening guidance or validation
