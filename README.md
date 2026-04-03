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

## Reporting

**Audit log** -- Append-only JSONL file with every evaluation. Set `reporting.log_file`.

**Webhooks** -- POST blocked/redacted events to external systems. Set `reporting.webhook_url` and optionally `reporting.webhook_events`.

## Integrating with OpenClaw

Parallax is designed as the security layer for [OpenClaw](https://github.com/anthropics/openclaw) agent systems. Integration works over HTTP -- any agent that can make a POST request can use Parallax.

### How it works

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

OpenClaw fires lifecycle hooks at three points. A lightweight shim plugin intercepts these hooks and forwards them to Parallax for evaluation. The shim receives the verdict and either blocks the tool call or lets it proceed.

### Shim plugin contract

The shim is a thin client that lives in your agent's plugin system. It needs to:

1. **Intercept three hooks**: `before_tool_call`, `after_tool_call`, `message_received`
2. **POST to Parallax** at `http://127.0.0.1:9920/evaluate` with the event payload
3. **Respect the verdict**: block on `{ "blocked": true }`, allow otherwise
4. **Fail open**: on timeout or error, default to allow

Environment variables for the shim:

| Variable | Default | Description |
|----------|---------|-------------|
| `PARALLAX_URL` | `http://127.0.0.1:9920/evaluate` | Evaluation endpoint |
| `PARALLAX_TIMEOUT` | `3000` | Request timeout in ms |

### Hook behavior by stage

| Hook | Can block? | Typical use |
|------|-----------|-------------|
| `before_tool_call` | Yes | Block dangerous commands, redact secrets in args |
| `after_tool_call` | No (fire-and-forget) | Detect secrets in tool output, audit logging |
| `message_received` | No (fire-and-forget) | Scan user messages for injection patterns |

Only `before_tool_call` is synchronous and can prevent execution. The other two hooks are observational -- they report to Parallax but don't wait for a blocking decision.

### Example shim (TypeScript)

```typescript
import type { OpenClawPlugin } from "openclaw";

const PARALLAX_URL = process.env.PARALLAX_URL || "http://127.0.0.1:9920/evaluate";
const TIMEOUT = parseInt(process.env.PARALLAX_TIMEOUT || "3000");

async function evaluate(payload: Record<string, unknown>) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    const res = await fetch(PARALLAX_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    return await res.json();
  } catch {
    return { action: "allow", blocked: false, reasons: [] };
  } finally {
    clearTimeout(timer);
  }
}

export default function plugin(api: OpenClawPlugin) {
  api.on("before_tool_call", 10, async (event) => {
    const verdict = await evaluate({
      stage: "tool.before",
      session_id: event.sessionId,
      tool_name: event.toolName,
      tool_args: event.toolArgs,
    });
    return verdict.blocked ? { block: true, blockReason: verdict.reasons.join("; ") } : {};
  });

  api.on("after_tool_call", 10, async (event) => {
    evaluate({
      stage: "tool.after",
      session_id: event.sessionId,
      tool_name: event.toolName,
      tool_args: event.toolArgs,
      tool_result: event.toolResult,
    });
  });

  api.on("message_received", 10, async (event) => {
    evaluate({
      stage: "message.before",
      session_id: event.sessionId,
      message_text: event.text,
      channel: event.channel,
      user_id: event.userId,
    });
  });
}
```

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
      --log-level <LEVEL>   Log level [default: info]
```

## Roadmap

Planned extensions (contributions welcome):

- **Proxy mode** -- Reverse proxy between OpenClaw and the Anthropic API with full blocking at all stages, including streamed tool_use interception
- **`parallax setup-openclaw`** -- CLI command to auto-configure OpenClaw to route traffic through proxy mode
- **Sigma evaluator** -- SIEM-compatible YAML threat detection rules
- **CEL evaluator** -- Common Expression Language for policy expressions
- **SQL evaluator** -- In-memory event store for rate limiting and temporal patterns
- **Real-time dashboard** -- SSE-powered web UI for live event monitoring

## Development

```bash
cargo build            # Dev build
cargo test             # Run tests (26 tests)
cargo build --release  # Optimized release build
RUST_LOG=debug cargo run -- serve -c config.yaml
```

## License

Apache 2.0
