# clibroker

`clibroker` is a policy-driven broker for wrapping local CLI tools behind a secure HTTP API and MCP server.

It has two surfaces:

- a server that wraps and executes approved CLI commands
- a client that talks to that server, fetches token-scoped configuration, and forwards execution requests

It is designed for cases where you want an LLM or another client to use a CLI tool, but only within a tightly-defined allowlist.

## What It Does

- Runs as a broker server with `clibroker`
- Ships a direct client with `clibroker-client`
- Exposes a single REST endpoint: `POST /execute`
- Exposes a token-scoped client discovery endpoint: `GET /client-config`
- Exposes MCP tools derived from allowed policy rules
- Enforces deny-by-default policy evaluation
- Validates flags and positional arguments before execution
- Applies per-token RBAC
- Executes subprocesses without invoking a shell
- Isolates subprocess environments unless explicit env vars are configured
- Caps output and enforces timeouts
- Emits structured JSON audit logs

## Security Model

- No shell: commands are executed with `asyncio.create_subprocess_exec()`
- Deny by default: if no allow rule matches, the request is rejected
- Deny precedence: deny rules override allows, including child command paths
- RBAC: each bearer token is allowed to invoke only specific rule IDs
- MCP isolation: each token gets its own MCP server view with only authorized tools visible
- Secret-safe MCP URLs: MCP/SSE endpoints use `SHA-256(token)[:16]` slugs instead of raw tokens

## Requirements

- Python `>=3.11`

## Install

Prefer `uv` for Python environment and package installation.

For system-wide CLI installation, prefer `uv tool`.

### System-Wide CLI Install

From the public GitHub repository:

Server command only:

```bash
uv tool install 'git+https://github.com/alanzchen/clibroker'
```

Server + client commands:

```bash
uv tool install 'clibroker[client] @ git+https://github.com/alanzchen/clibroker'
```

This installs the published CLI application into an isolated tool environment and exposes:

- `clibroker`
- `clibroker-client`

### Local Project Install

For local development, editable installs, or working from a checkout, use `uv venv` + `uv pip`.

Server only:

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e .
```

Server + client support:

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e .[client]
```

Development:

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e .[dev]
```

Installed commands:

- `clibroker`: start the broker server
- `clibroker-client`: connect to a broker server

## Configuration

The server and client use separate YAML configs.

### Server Config

Start from `config.example.yaml`:

```bash
cp config.example.yaml config.yaml
```

Main sections:

- `server.bind`: host and port to listen on
- `server.auth.tokens`: bearer tokens and their allowed rule IDs
- `tools.<name>.executable`: absolute path to the wrapped CLI
- `tools.<name>.default_args`: always prepended to the command
- `tools.<name>.env`: explicit subprocess environment variables
- `tools.<name>.rules`: allow/deny policy rules

Example token config:

```yaml
server:
  auth:
    tokens:
      - name: reader
        value: "env:CLIBROKER_TOKEN_READER"
        allow_rules:
          - list_messages
```

Token values may be literal strings or `env:VAR_NAME` references.

### Client Config

Start from `client.example.yaml`:

```bash
cp client.example.yaml client.yaml
```

Example:

```yaml
default_backend: local

backends:
  local:
    type: http
    base_url: http://127.0.0.1:8080
    token: env:CLIBROKER_TOKEN_READER
    timeout_s: 30.0
    verify_tls: true
  review:
    type: http
    base_url: http://127.0.0.1:8081
    token: env:CLIBROKER_TOKEN_REVIEW
    timeout_s: 30.0
    verify_tls: true
```

Current backend types:

- `http`: direct HTTPS/HTTP connection to the broker server

Client tokens also support `env:VAR_NAME` references.

## Running

### Server

```bash
.venv/bin/clibroker --config config.yaml
```

Development mode with reload:

```bash
.venv/bin/clibroker --config config.yaml --reload
```

### Client

List tools visible to the configured token:

```bash
.venv/bin/clibroker-client --config client.yaml tools
```

The client also supports config discovery in this order:

- `--config`
- `CLIBROKER_CLIENT_CONFIG`
- `~/.openclaw/clibroker-client.yaml`
- `${XDG_CONFIG_HOME:-~/.config}/clibroker/client.yaml`

So if your config is already in one of those default locations, you can simply run:

```bash
.venv/bin/clibroker-client tools
```

Select a non-default server backend with `--backend`:

```bash
.venv/bin/clibroker-client --backend review tools
```

If you do not pass `--backend`, the client behaves like this:

- if only one backend is configured, it uses that backend
- if multiple backends are configured and a tool name exists in exactly one backend, `execute` auto-selects that backend
- if the same tool name exists in multiple backends, `execute` fails and tells you to rerun with `--backend <name>`

With multiple configured backends, `tools --json` returns an aggregate view that includes a `tool_index` showing which backends expose each tool and whether the tool name is conflicted.

Forward an execute request to the server:

```bash
.venv/bin/clibroker-client --config client.yaml execute himalaya -- message read 42
```

Show the selected local backend config with secrets redacted:

```bash
.venv/bin/clibroker-client --config client.yaml config show
```

List all configured backends:

```bash
.venv/bin/clibroker-client config list
```

## HTTP API

### Health Check

```bash
curl http://127.0.0.1:8080/health
```

Response:

```json
{"status":"ok","version":"0.1.0"}
```

### Execute a Command

```bash
curl -X POST http://127.0.0.1:8080/execute \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "tool": "himalaya",
    "argv": ["message", "read", "42"]
  }'
```

Request body:

```json
{
  "tool": "himalaya",
  "argv": ["message", "move", "42", "Archive"]
}
```

Response shape:

```json
{
  "ok": true,
  "exit_code": 0,
  "stdout": {},
  "stderr": "",
  "duration_ms": 12.34,
  "matched_rule": "move_message",
  "timed_out": false
}
```

Notes:

- `argv` must contain at least one element
- `stdout` is parsed as JSON when possible; otherwise it is returned as a string
- policy denials and validation failures return `200` with `ok: false`
- auth failures return `401` or `403`

### Client Discovery

The broker client fetches a token-scoped discovery document from the server.

```bash
curl http://127.0.0.1:8080/client-config \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

Example response:

```json
{
  "version": "0.1.0",
  "client_name": "reader",
  "execute_url": "/execute",
  "token_info_url": "/token-info",
  "mcp_url": "/mcp/0123456789abcdef/",
  "sse_url": "/sse/0123456789abcdef/",
  "tools": [
    {
      "name": "himalaya",
      "rules": [
        {
          "id": "list_messages",
          "command": ["message", "list"],
          "flags": ["--account", "--folder", "--page"],
          "standalone_flags": ["--unread"],
          "positionals": []
        }
      ]
    }
  ]
}
```

This response is token-scoped:

- only allow-rules for the authenticated token are returned
- deny rules are omitted
- raw server config and secrets are not returned

## MCP

`clibroker` exposes both streamable HTTP MCP and SSE MCP transports.

Endpoints:

- `POST /mcp/<slug>/`
- `GET /sse/<slug>/`

Where:

- `slug = SHA-256(token)[:16]`

To discover your slug:

```bash
curl http://127.0.0.1:8080/token-info \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

Example response:

```json
{
  "name": "reader",
  "slug": "0123456789abcdef",
  "mcp_url": "/mcp/0123456789abcdef/",
  "sse_url": "/sse/0123456789abcdef/",
  "allow_rules": ["list_messages", "read_message"]
}
```

MCP behavior:

- each token only sees the tools for its allowed rule IDs
- deny rules do not appear in MCP `tools/list`
- MCP tool calls still pass through the policy engine before execution

## Client CLI

The `clibroker-client` command does not execute local subprocesses. It talks to the server using the configured backend and lets the server remain the security boundary.

Current commands:

- `tools`: fetch and print the token-scoped discovery document
- `execute <tool> -- <argv...>`: forward an execution request to the server
- `config show`: show the selected local client backend config with secrets redacted

When a tool declares `argv_normalization`, the server advertises the accepted
reorderable global argument patterns through `/client-config`, `tools`, and
`tools --json`. The server remains the source of truth for normalization, while
the client can reject obviously ambiguous forms such as duplicate global args.

Examples:

```bash
.venv/bin/clibroker-client --config client.yaml tools --json
.venv/bin/clibroker-client --config client.yaml execute himalaya -- message list --account work
.venv/bin/clibroker-client --config client.yaml config show
```

Example tool-level global arg normalization:

```yaml
tools:
  obsidian:
    executable: /usr/local/bin/obsidian
    argv_normalization:
      patterns:
        - id: vault
          kind: key_value
          key_pattern: "^vault$"
          value_pattern: "^[A-Za-z0-9_. -]+$"
          canonical_position: before_command
          allow_positions: ["before_command", "after_command"]
          multiple: false
```

## Policy Rules

Each rule includes:

- `id`: unique rule ID
- `command`: command path, such as `['message', 'read']`
- `effect`: `allow` or `deny`
- `flags.allowed`: allowed flags that require a value
- `flags.standalone`: allowed boolean flags that take no value
- `inject_args`: fixed server-side args always inserted for the rule
- `positionals`: positional argument validators

Example allow rule:

```yaml
- id: read_message
  command: ["message", "read"]
  effect: allow
  inject_args: ["--preview"]
  flags:
    allowed: ["--account", "--folder"]
  positionals:
    - name: id
      pattern: "^[0-9]+$"
```

Example variadic tail rule:

```yaml
- id: search_messages
  command: ["envelope", "list"]
  effect: allow
  flags:
    allowed: ["--account", "--folder", "--page", "--page-size"]
  positionals:
    - name: query
      pattern: "^[A-Za-z0-9_@.+:-]+$"
      variadic: true
```

Example deny rule:

```yaml
- id: deny_delete
  command: ["message", "delete"]
  effect: deny
```

Important validation rules:

- `command` must contain at least one element
- unknown flags are rejected
- `--flag=value` is supported
- `--` marks end-of-options
- `flags.allowed` entries must consume one value argument
- `flags.standalone` entries must not consume a value
- `flags.allowed` and `flags.standalone` must be disjoint
- only the final positional may be marked `variadic: true`
- a variadic positional validates each token in the tail individually
- deny rules cascade to child command paths

Notes:

- `inject_args` are server-controlled and are not exposed as client-supplied parameters in `/client-config` or MCP tool schemas
- execution order is `executable + default_args + command + inject_args + validated user args`

## Testing

Run all tests:

```bash
.venv/bin/python -m pytest tests -v
```

The current suite covers REST, MCP, policy evaluation, subprocess hardening, and security fixes.

## Project Layout

```text
src/clibroker/
  app.py         FastAPI app factory
  auth.py        Bearer auth and RBAC
  client/        Client package and CLI
  config.py      YAML/Pydantic config models
  mcp_server.py  MCP server and tool registration
  middleware.py  Request timeout middleware
  models.py      REST request/response models
  policy.py      Command matching and argv validation
  routes.py      /execute route
  runner.py      Hardened subprocess execution
  audit.py       Structured JSON audit logging
```

## Known Limits

- no rate limiting yet
- no graceful child-process shutdown on app stop yet
- regex patterns come directly from config, so pattern quality matters
- the client currently supports only the direct HTTP backend
