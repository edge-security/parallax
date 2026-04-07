# Parallax

Security decision engine for AI agent systems. One binary, one YAML config.

Parallax evaluates every AI agent event -- messages, tool calls, and results -- against your security rules and decides to **block**, **redact**, or **allow** in microseconds.

## How It Works

```
  Agent Event ──> Parallax ──> Decision (block / redact / allow)
                     │
                     ├── Audit Log
                     └── Webhook
```

Every event passes through a chain of evaluators. Each evaluator checks the event against its rules and returns a verdict. The chain short-circuits on the first `block` -- no wasted work.

## Quick Start

```bash
cargo build --release
./target/release/parallax serve -c config.yaml
```

```bash
curl http://127.0.0.1:9920/health

curl -X POST http://127.0.0.1:9920/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"stage":"tool.before","tool_name":"exec","tool_args":{"command":"rm -rf /"}}'
# → {"action":"block","blocked":true,"reasons":["Regex match: Recursive delete"]}
```

## Configuration

One YAML file, three sections:

### Server

```yaml
server:
  host: "127.0.0.1"
  port: 9920
```

### Reporting

```yaml
reporting:
  log_file: ./logs/audit.jsonl          # Append-only JSONL audit trail
  webhook_url: https://siem.example.com # POST decisions to external systems
  webhook_events: [block, redact]       # Filter which decisions to send
```

### Evaluators

Evaluators are the decision rules. Each has a `name`, `type`, the `stages` it applies to, and `rules`:

```yaml
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
        fields: [tool_args.command]       # Only check this field
```

See [config.yaml](config.yaml) for a complete working example.

## Evaluator Types

| Type | Description | Config |
|------|-------------|--------|
| **regex** | Compiled regex patterns with AND/OR, negation, field targeting, redaction | `rules` with `pattern` |
| **pattern** | Keyword substring matching, case-insensitive | `rules` with `keywords` |
| **sigma** | Sigma-format YAML threat detection with field modifiers and complex conditions | `rules_dir` pointing to YAML files |
| **cel** | CEL-like expressions (`==`, `!=`, `&&`, `.contains()`, `.startsWith()`, `.matches()`) | `rules_file` pointing to YAML |
| **sql** | In-memory SQLite for rate limiting, frequency analysis, temporal patterns | `rules` with `query` + `condition` |

Evaluators run in cost order (cheapest first) and short-circuit on block.

## Decisions

| Action | Behavior |
|--------|----------|
| `block` | Reject the event |
| `redact` | Replace matched content with `[REDACTED]`, then allow |
| `detect` | Log and alert, but allow |
| `allow` | Pass through |

## Stages

| Stage | When | Can block? |
|-------|------|------------|
| `message.before` | User message received | Yes |
| `tool.before` | Before tool execution | Yes |
| `tool.after` | After tool execution | Yes |
| `params.before` | Before model parameter forwarding | Yes |

## Two Modes

### Server Mode (default)

Exposes a `/evaluate` HTTP endpoint. Your agent calls it at each lifecycle stage and acts on the decision.

```bash
parallax serve -c config.yaml
```

**POST /evaluate**

```json
// Request
{ "stage": "tool.before", "session_id": "s-123", "tool_name": "exec", "tool_args": {"command": "rm -rf /"} }

// Response
{ "action": "block", "blocked": true, "reasons": ["Regex match: Recursive delete"], "elapsed_ms": 0.1 }
```

**GET /health**

```json
{ "status": "ok", "mode": "server", "evaluators": 3, "version": "0.2.0" }
```

### Proxy Mode

Acts as a reverse proxy between your agent and the Anthropic API. All traffic is automatically evaluated -- no integration code needed.

```bash
parallax serve --mode proxy -c config.yaml
```

```
  Agent ──> POST /anthropic/v1/messages ──> Parallax ──> Anthropic API
                                               │
                                    ┌──────────┼──────────┐
                                    │          │          │
                              message.before tool.after tool.before
                                    │          │          │
                               Block before  Scan tool  Intercept tool_use
                               forwarding    results    in SSE stream
```

The proxy:
- Evaluates user messages before forwarding (`message.before`)
- Evaluates tool results in the request (`tool.after`)
- Buffers and evaluates `tool_use` blocks in streaming responses (`tool.before`)
- Replaces blocked tool calls with text explanations
- Passes through non-messages endpoints transparently

## OpenClaw Integration

Parallax is designed as the security layer for [OpenClaw](https://openclaw.ai) agent systems.

### Proxy setup (recommended)

```bash
# 1. Configure OpenClaw to route through Parallax
parallax setup-openclaw

# 2. Start the proxy
parallax serve --mode proxy -c config.yaml

# To revert back to direct Anthropic access
parallax revert-openclaw
```

### Shim plugin

For finer control, use a shim plugin that POSTs to `/evaluate` at each lifecycle hook:

| Variable | Default | Description |
|----------|---------|-------------|
| `PARALLAX_URL` | `http://127.0.0.1:9920/evaluate` | Evaluation endpoint |
| `PARALLAX_TIMEOUT` | `3000` | Request timeout in ms |

### Any agent system

Parallax works with any agent that can make HTTP requests. POST to `/evaluate`:

| Field | Required | Description |
|-------|----------|-------------|
| `stage` | Yes | `message.before`, `tool.before`, `tool.after`, or `params.before` |
| `session_id` | No | Session identifier |
| `tool_name` | No | Tool being called |
| `tool_args` | No | Tool arguments |
| `tool_result` | No | Tool output (for `tool.after`) |
| `message_text` | No | Message content (for `message.before`) |

Check `blocked` in the response to decide whether to proceed.

## CLI Reference

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
