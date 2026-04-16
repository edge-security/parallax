# Architecture

Parallax is a runtime security engine for AI agent systems. It evaluates agent lifecycle events against configurable rules and returns verdicts (block, redact, detect, allow) in microseconds.

## High-Level Flow

```
                          ┌─────────────────────────────┐
  Agent Event ──────────> │         Parallax             │
  (HTTP POST /evaluate)   │                              │
                          │  ┌────────┐  ┌────────┐     │
                          │  │ Regex  │──│Pattern │──┐  │
                          │  └────────┘  └────────┘  │  │
                          │  ┌────────┐  ┌────────┐  │  │
                          │  │ Sigma  │──│  CEL   │──┤  │──> Decision
                          │  └────────┘  └────────┘  │  │    + Audit Log
                          │  ┌────────┐              │  │    + Webhook
                          │  │  SQL   │──────────────┘  │
                          │  └────────┘                  │
                          └─────────────────────────────┘
```

## Core Components

### Evaluator Chain (`src/engine/chain.rs`)

The evaluator chain is the central orchestrator. It holds an ordered list of evaluators and runs them sequentially against each event context.

**Key behaviors:**
- Evaluators are ordered by computational cost (cheapest first).
- The chain **short-circuits** on the first `block` verdict -- once any evaluator blocks, remaining evaluators are skipped.
- `redact` verdicts modify the event payload but do not stop the chain.
- `detect` verdicts log the match but do not stop the chain.
- All verdict reasons are aggregated into the final result.

### Event Context (`src/engine/context.rs`)

Every evaluation starts with an `EvalContext` struct containing:
- `stage` -- which lifecycle stage (message.before, tool.before, tool.after, params.before)
- `session_id`, `channel`, `user_id` -- identity fields for rate limiting and session tracking
- `tool_name`, `tool_args` -- the tool being called and its arguments
- `tool_result` -- the tool output (for tool.after evaluations)
- `message_text` -- the user message content (for message.before evaluations)
- `timestamp` -- event timestamp for temporal queries

### Evaluators (`src/evaluators/`)

Each evaluator implements the `Evaluator` trait:

```rust
#[async_trait]
pub trait Evaluator: Send + Sync {
    fn name(&self) -> &str;
    fn stages(&self) -> &[String];
    async fn evaluate(&self, ctx: &EvalContext) -> Vec<EvalResult>;
}
```

**Available evaluator types:**

| Type | File | Cost | Description |
|------|------|------|-------------|
| Regex | `regex_eval.rs` | Low | Compiled regex patterns with field targeting and redaction |
| Pattern | `pattern_eval.rs` | Low | Case-insensitive keyword substring matching |
| Sigma | `sigma_eval.rs` | Medium | Sigma-format YAML detection with field modifiers |
| CEL | `cel_eval.rs` | Medium | CEL-like expression evaluation against flattened fields |
| SQL | `sql_eval.rs` | High | In-memory SQLite for temporal/aggregate queries |

### Configuration (`src/config/`)

- `schema.rs` -- Serde structs for the YAML config file (server, proxy, reporting, evaluators)
- `loader.rs` -- Config file discovery, loading, directory-based evaluator merging, and chain construction

### Server (`src/server/`)

- `api.rs` -- Server mode: `/evaluate` and `/health` endpoints
- `proxy.rs` -- Proxy mode: reverse proxy that intercepts LLM API calls and evaluates them inline

### Reporting (`src/reporting/`)

- `audit.rs` -- Append-only JSONL audit log
- `webhook.rs` -- HTTP webhook for forwarding block/redact decisions to SIEM or alerting systems

## Two Operating Modes

### Server Mode

The agent makes explicit `POST /evaluate` calls at each lifecycle stage and acts on the response. The agent is responsible for enforcement.

```
Agent ──> POST /evaluate ──> Parallax ──> { blocked: true/false }
  │                                              │
  └── if blocked, skip tool execution ───────────┘
```

### Proxy Mode

Parallax sits between the agent and the LLM API as a transparent reverse proxy. It evaluates requests and responses automatically.

```
Agent ──> Parallax Proxy ──> LLM API
              │
     ┌────────┼────────┐
     │        │        │
  message  tool.after  tool.before
  .before              (in response)
```

In proxy mode, Parallax:
1. Evaluates user messages in the request body (`message.before`)
2. Evaluates tool results in the request body (`tool.after`)
3. Forwards the request to the upstream LLM API
4. Buffers streaming `tool_use` blocks in the response and evaluates them (`tool.before`)
5. Replaces blocked tool calls with text explanations

## Directory Structure

```
parallax/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Public module exports
│   ├── config/              # Configuration loading and schema
│   ├── engine/              # Evaluator chain, context, result types
│   ├── evaluators/          # Regex, pattern, sigma, CEL, SQL evaluators
│   ├── integrations/        # Agent framework integrations (Rust side)
│   ├── reporting/           # Audit logging and webhook reporting
│   └── server/              # HTTP server (api.rs) and proxy (proxy.rs)
├── integrations/
│   └── openclaw/            # OpenClaw server-mode integration (TypeScript)
├── rules/
│   ├── cel/                 # CEL policy files
│   ├── regex/               # Regex rule files
│   └── sigma/               # Sigma detection rules
├── config.yaml              # Full configuration example
├── Cargo.toml
└── docs/
    ├── ARCHITECTURE.md      # This file
    ├── RULES.md             # Security rules reference
    ├── config.minimal.yaml  # Minimal starter configuration
    └── integrations/        # Framework integration guides
```
