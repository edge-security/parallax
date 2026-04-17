# Parallax

Runtime security engine that protects AI agents from prompt injection, data exfiltration, and dangerous tool calls -- any framework, any LLM.

One binary, one YAML config. Evaluates every agent event in microseconds.

## Why Parallax

- **Single binary, zero runtime dependencies** -- `cargo build --release` produces one static executable. No Python, no JVM, no containers required.
- **Microsecond evaluation** -- the evaluator chain runs in cost order and short-circuits on the first `block`. Typical decisions complete in under 0.2 ms.
- **Framework-agnostic** -- works with any agent system that can make HTTP calls. First-class integrations for OpenClaw; LangChain, CrewAI, and OpenAI Agents SDK on the roadmap.
- **51 rules out of the box** -- ships with rules covering 13 threat categories: prompt injection, reconnaissance, privilege escalation, PII leakage, supply chain attacks, data exfiltration, and more.
- **Five evaluator engines** -- regex, keyword pattern, Sigma, CEL expressions, and SQL-based temporal analysis. Mix and match for layered defense.

## How It Works

```
  Agent Event ──> Parallax ──> Decision (block / redact / allow)
                     │
                     ├── Audit Log (JSONL)
                     └── Webhook (SIEM, Slack, PagerDuty)
```

Every event passes through a chain of evaluators. Each evaluator checks the event against its rules and returns a verdict. The chain short-circuits on the first `block` -- no wasted work.

## Quick Start

### Build from source

```bash
git clone https://github.com/agentic-defense/parallax
cd parallax
sudo snap install --classic rustup
rustup default stable
sudo apt install pkg-config libssl-dev
cargo build --release
```

### Configure with OpenClaw

```bash
# Deploy the OpenClaw integration (server mode)
openclaw plugins install --dangerously-force-unsafe-install --link ./integrations/openclaw
openclaw plugins enable parallax-security
openclaw gateway restart

# Start the Parallax server
./target/release/parallax serve -c config.yaml
```

### Test the evaluation endpoint

```bash
curl http://127.0.0.1:9920/health

curl -X POST http://127.0.0.1:9920/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"stage":"tool.before","tool_name":"exec","tool_args":{"command":"rm -rf /"}}'
# → {"action":"block","blocked":true,"reasons":["Regex match: Recursive delete"]}
```

Your agent calls `POST /evaluate` before and after each tool execution and acts on the decision.

## Supported Threat Categories

| Category | Evaluator | Coverage |
|----------|-----------|----------|
| Prompt injection & jailbreak | Sigma | System prompt extraction, DAN mode, role-play escape |
| Secret leakage | Regex | AWS keys, GitHub tokens, private keys, generic API keys |
| PII exposure | Regex | SSN, credit cards, phone numbers |
| Data exfiltration | Regex | Base64-encoded secrets, hex payloads, data URIs |
| Dangerous commands | Regex + CEL | `rm -rf`, disk format, curl-pipe-bash |
| Privilege escalation | CEL | sudo, su, pkexec, setuid, sudoers |
| Reconnaissance | Sigma | Credential files, cloud metadata endpoints, container configs |
| Shadow IT | Sigma | Docker, Kubernetes, Terraform, cloud CLI |
| Supply chain attacks | Pattern | Custom package indexes, registry hijacking |
| SQL injection | Pattern | DROP TABLE, DELETE FROM, TRUNCATE |
| Model manipulation | CEL | System prompt tampering, temperature override, tool redefinition |
| Resource abuse | SQL | Rate limiting, repeated tool abuse |
| Sensitive file writes | Sigma | Writes to /etc, /usr, .ssh |

See [docs/RULES.md](docs/RULES.md) for the full reference.

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
      - id: regex-sec-001
        title: AWS Access Key
        description: Detects AWS access key IDs starting with AKIA
        pattern: "AKIA[0-9A-Z]{16}"
        action: redact

  - name: dangerous-commands
    type: regex
    stages: [tool.before]
    rules:
      - id: regex-cmd-001
        title: Recursive delete
        description: Blocks recursive deletion of root filesystem
        pattern: "rm\\s+-rf\\s+/"
        action: block
        fields: [tool_args.command]       # Only check this field
```

See [config.yaml](config.yaml) for a complete working example, or [docs/config.minimal.yaml](docs/config.minimal.yaml) for a minimal starter.

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

Acts as a reverse proxy between your agent and the LLM API. All traffic is automatically evaluated -- no integration code needed.

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

## Agent Framework Integrations

### Any agent system (HTTP API)

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

### OpenClaw

Parallax includes a dedicated integration for [OpenClaw](https://openclaw.ai) agent systems. See [docs/integrations/openclaw.md](docs/integrations/openclaw.md) for full setup instructions.

**Proxy setup:**

```bash
parallax setup --framework openclaw
parallax serve --mode proxy -c config.yaml

# To revert
parallax revert --framework openclaw
```

**Server mode:**

```bash
openclaw plugins install --link ./integrations/openclaw
openclaw plugins enable parallax-security
parallax serve -c config.yaml
```

| Variable | Default | Description |
|----------|---------|-------------|
| `PARALLAX_URL` | `http://127.0.0.1:9920/evaluate` | Evaluation endpoint |
| `PARALLAX_TIMEOUT` | `3000` | Request timeout in ms |

## CLI Reference

```
parallax serve [OPTIONS]
  -c, --config <PATH>       Config file path
      --host <HOST>         Override host
      --port <PORT>         Override port
      --mode <MODE>         server or proxy [default: server]
      --log-level <LEVEL>   Log level [default: info]

parallax setup --framework <FRAMEWORK> [OPTIONS]
      --host <HOST>         Proxy host [default: 127.0.0.1]
      --port <PORT>         Proxy port [default: 9920]
      --model <MODEL>       Model ID [default: claude-sonnet-4-20250514]

parallax revert --framework <FRAMEWORK> [OPTIONS]
      --model <MODEL>       Model ID [default: claude-sonnet-4-20250514]
```

Supported frameworks: `openclaw` (more coming in v0.3).

## Roadmap

### v0.3 -- Multi-Framework & Multi-Provider Support
- Generic `parallax setup --framework <name>` for LangChain, CrewAI, OpenAI Agents SDK
- Integration directory structure for framework integrations
- OpenAI-compatible proxy mode (`/v1/chat/completions`) covering OpenAI, Azure OpenAI, and local models (Ollama, LM Studio)
- Configurable upstream provider in `config.yaml`

### v0.4 -- Advanced Evaluators
- Embedding-based semantic prompt injection detection
- Tool argument JSON Schema validation
- Multi-turn escalation detection across conversation history
- Token budget enforcement per session/user

### v0.5 -- Extended Lifecycle Stages
- `response.after` -- evaluate LLM responses before returning to the user
- `memory.before` -- evaluate before writing to agent memory/context
- RAG pipeline stages (`retrieval.before`, `retrieval.after`)
- Rule hot-reload -- watch config file for changes without restart

### v0.6 -- SDKs and Ecosystem
- Python client library (`pip install parallax-client`) with LangChain/CrewAI decorators
- TypeScript client library (`npm install @parallax/client`)
- Webhook integrations -- Slack, PagerDuty, and SIEM connectors
- Dashboard UI for rule management and audit log visualization

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details on the evaluator chain, short-circuit logic, and cost-ordered execution.

## Development

```bash
cargo build            # Dev build
cargo test             # Run tests (45 tests)
cargo build --release  # Optimized release build
RUST_LOG=debug cargo run -- serve -c config.yaml
```

## License

Apache 2.0
