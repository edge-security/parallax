# Parallax

Security evaluation engine for AI agent systems. One binary, one YAML config.

Parallax sits between your AI agent and the tools it calls. It evaluates every event (messages, tool calls, results) against your security rules and can **block**, **redact**, or **detect** threats in microseconds.

## Quick Start

```bash
cargo build --release
./target/release/parallax serve -c config.yaml
```

Try it:

```bash
# Health check
curl http://127.0.0.1:9920/health

# This will be blocked
curl -X POST http://127.0.0.1:9920/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"stage":"tool.before","tool_name":"exec","tool_args":{"command":"rm -rf /"}}'
```

## Configuration

Everything lives in one YAML file:

```yaml
server:
  host: "127.0.0.1"
  port: 9920

reporting:
  log_file: ./logs/audit.jsonl

evaluators:
  - name: secrets-scanner
    type: regex
    stages: [tool.before, tool.after]
    rules:
      - label: "AWS Access Key"
        pattern: "AKIA[0-9A-Z]{16}"
        action: redact

  - name: dangerous-commands
    type: regex
    stages: [tool.before]
    rules:
      - label: "Recursive delete"
        pattern: "rm\\s+-rf\\s+/"
        action: block
        fields: [tool_args.command]

  - name: keyword-filter
    type: pattern
    stages: [message.before, tool.before]
    rules:
      - label: "SQL injection"
        keywords: ["DROP TABLE", "DELETE FROM"]
        action: detect
```

## Evaluators

**regex** -- Compiled regex patterns. Supports multiple patterns per rule (AND/OR), negation, field targeting, and automatic redaction.

**pattern** -- Keyword substring matching. Case-insensitive by default. Use when you don't need regex.

**sigma** -- Sigma-format YAML threat detection rules. Supports field modifiers (`startswith`, `contains`, `endswith`, `re`), complex conditions with `and`/`or`/`not`, and `1 of`/`all of` patterns. Load rules from a directory:

```yaml
- name: sigma-threats
  type: sigma
  stages: [tool.before, tool.after]
  rules_dir: ./rules/sigma
```

**cel** -- Lightweight CEL-like expression engine for policy rules. Supports `==`, `!=`, `&&`, `||`, `.contains()`, `.startsWith()`, `.matches()`:

```yaml
- name: cel-policies
  type: cel
  stages: [tool.before]
  rules_file: ./rules/cel/policies.yaml
```

**sql** -- In-memory SQLite evaluator for stateful, aggregate detection. Use for rate limiting, frequency analysis, and temporal patterns:

```yaml
- name: rate-limits
  type: sql
  stages: [tool.before, tool.after]
  rules:
    - label: "High tool call rate"
      query: >
        SELECT COUNT(*) as cnt FROM events
        WHERE session_id = :session_id
        AND timestamp > :now - 60
      condition: "cnt > 50"
      action: detect
      reason: "Unusually high tool call rate"
```

Evaluators run in cost order (cheapest first) and short-circuit on block.

## Actions

| Action | Behavior |
|--------|----------|
| `block` | Reject the event |
| `redact` | Replace matched content with `[REDACTED]` |
| `detect` | Log and alert, but allow |
| `allow` | Pass through |

## Stages

| Stage | When it fires |
|-------|---------------|
| `message.before` | User message received |
| `tool.before` | Before tool execution |
| `tool.after` | After tool execution |
| `params.before` | Before model parameter forwarding |

## API

**POST /evaluate** -- Evaluate an event against the security chain.

Request:

```json
{
  "stage": "tool.before",
  "session_id": "session-123",
  "user_id": "user@example.com",
  "tool_name": "exec",
  "tool_args": { "command": "rm -rf /" }
}
```

Response:

```json
{
  "action": "block",
  "blocked": true,
  "reasons": ["Regex match: Recursive delete"],
  "results": [{ "evaluator": "dangerous-commands", "action": "block", "confidence": 1.0 }],
  "elapsed_ms": 0.1
}
```

**GET /health** -- Server status.

```json
{ "status": "ok", "mode": "server", "evaluators": 3, "version": "0.1.0" }
```

## Proxy Mode

Parallax can act as a reverse proxy between your agent and the Anthropic API, intercepting and evaluating requests at every stage:

```bash
parallax serve --mode proxy -c config.yaml
```

```
  Agent ──> POST /anthropic/v1/messages ──> Parallax Proxy ──> Anthropic API
                                                │
                                    ┌───────────┼───────────┐
                                    │           │           │
                              message.before  tool.after  tool.before
                                    │           │           │
                               Block request  Block on    Intercept tool_use
                               before sending result     in SSE stream
```

The proxy:
- Evaluates user messages before forwarding (`message.before`)
- Evaluates tool results in the request (`tool.after`)
- Buffers and evaluates tool_use blocks in streaming responses (`tool.before`)
- Replaces blocked tool_use blocks with text explanations
- Rewrites `stop_reason` from `tool_use` to `end_turn` when all tools are blocked
- Passes through non-messages endpoints transparently

### OpenClaw proxy setup

Auto-configure OpenClaw to route traffic through the proxy:

```bash
# Configure OpenClaw to use the proxy
parallax setup-openclaw --host 127.0.0.1 --port 9920 --model claude-sonnet-4-20250514

# Start the proxy
parallax serve --mode proxy -c config.yaml

# Revert to direct Anthropic access
parallax revert-openclaw
```

## Reporting

**Audit log** -- Append-only JSONL file with every evaluation. Set `reporting.log_file`.

**Webhooks** -- POST blocked/redacted events to external systems. Set `reporting.webhook_url` and optionally `reporting.webhook_events`.

## Integrating with OpenClaw

Parallax is designed as the security layer for [OpenClaw](https://github.com/anthropics/openclaw) agent systems. There are two integration methods:

### 1. Proxy mode (recommended)

Use `parallax serve --mode proxy` and `parallax setup-openclaw` to route all API traffic through Parallax. No plugin code needed.

### 2. Shim plugin

For finer control, use a lightweight shim plugin that POSTs to `/evaluate` at each lifecycle hook:

```
                    ┌──────────┐
  User message ───> │ OpenClaw │
                    │  Agent   │
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
        message.before  tool.before  tool.after
              │          │          │
              └──────────┼──────────┘
                         │ HTTP POST /evaluate
                         v
                    ┌──────────┐
                    │ Parallax │ ──> Audit Log
                    │  Server  │ ──> Webhook
                    └──────────┘
                         │
                  action: block / allow / redact / detect
```

Environment variables for the shim:

| Variable | Default | Description |
|----------|---------|-------------|
| `PARALLAX_URL` | `http://127.0.0.1:9920/evaluate` | Evaluation endpoint |
| `PARALLAX_TIMEOUT` | `3000` | Request timeout in ms |

### Generic integration

Any agent system can integrate with Parallax. The only requirement is an HTTP POST to `/evaluate` with these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `stage` | Yes | One of `message.before`, `tool.before`, `tool.after`, `params.before` |
| `session_id` | No | Session identifier for correlation |
| `user_id` | No | User identifier |
| `tool_name` | No | Tool being called (for tool stages) |
| `tool_args` | No | Tool arguments as key-value pairs |
| `tool_result` | No | Tool output (for `tool.after`) |
| `message_text` | No | Message content (for `message.before`) |

Check `blocked` in the response to decide whether to proceed.

## CLI

```
parallax serve [OPTIONS]

  -c, --config <PATH>       Config file path
      --host <HOST>         Override host
      --port <PORT>         Override port
      --mode <MODE>         server or proxy [default: server]
      --log-level <LEVEL>   Log level [default: info]

parallax setup-openclaw [OPTIONS]

      --host <HOST>         Proxy host [default: 127.0.0.1]
      --port <PORT>         Proxy port [default: 9920]
      --model <MODEL>       Claude model ID [default: claude-sonnet-4-20250514]

parallax revert-openclaw [OPTIONS]

      --model <MODEL>       Claude model ID [default: claude-sonnet-4-20250514]
```

## Roadmap

Planned extensions (contributions welcome):

- **Real-time dashboard** -- SSE-powered web UI for live event monitoring
- **Webhook integrations** -- Slack, PagerDuty, and SIEM connectors
- **Rule hot-reload** -- Watch config file for changes without restart

## Development

```bash
cargo build            # Dev build
cargo test             # Run tests (45 tests)
cargo build --release  # Optimized release build
RUST_LOG=debug cargo run -- serve -c config.yaml
```

## License

Apache 2.0
