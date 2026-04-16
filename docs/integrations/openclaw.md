# OpenClaw Integration

Parallax includes first-class integration with [OpenClaw](https://openclaw.ai) agent systems. There are two ways to connect them: proxy mode (transparent interception) and server mode (explicit lifecycle hooks).

## Option 1: Proxy Mode

Proxy mode routes all OpenClaw-to-Anthropic traffic through Parallax. No code changes to OpenClaw are needed.

### Setup

```bash
# 1. Configure OpenClaw to route through Parallax
parallax setup --framework openclaw

# 2. Start the proxy
parallax serve --mode proxy -c config.yaml
```

This registers a custom provider in OpenClaw's config that points at the Parallax proxy, copies the Anthropic API key, and disables the server-mode integration to prevent double-evaluation.

### Revert

```bash
parallax revert --framework openclaw
```

This restores OpenClaw to use the Anthropic API directly, removes the custom provider, and re-enables the server-mode integration.

### What the proxy evaluates

| Stage | When | What |
|-------|------|------|
| `message.before` | User message in request | Checks for prompt injection, jailbreaks |
| `tool.after` | Tool results in request | Scans for secrets, PII in tool output |
| `tool.before` | Tool calls in response stream | Blocks dangerous commands before execution |

## Option 2: Server Mode

Server mode installs a lightweight TypeScript integration that forwards OpenClaw lifecycle events to the Parallax evaluation server. OpenClaw enforces the verdicts.

### Setup

```bash
# Install the integration from the integrations directory
openclaw plugins install --link ./integrations/openclaw
openclaw plugins enable parallax-security

# Start Parallax in server mode
parallax serve -c config.yaml
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PARALLAX_URL` | `http://127.0.0.1:9920/evaluate` | Evaluation endpoint |
| `PARALLAX_TIMEOUT` | `3000` | Request timeout in ms |

### What server mode evaluates

| Hook | Stage | Behavior |
|------|-------|----------|
| `before_tool_call` | `tool.before` | Sequential -- can block the tool call |
| `after_tool_call` | `tool.after` | Fire-and-forget -- logs but doesn't block |
| `message_received` | `message.before` | Fire-and-forget -- logs but doesn't block |

## Which mode to choose

| Consideration | Proxy Mode | Server Mode |
|---------------|-----------|-------------|
| Integration effort | Zero code changes | Install integration |
| Blocking capability | Full (all stages) | Only `tool.before` blocks |
| Streaming support | Yes (buffers SSE tool_use blocks) | N/A |
| Latency overhead | Adds proxy hop | Adds HTTP call per event |
| Works without Parallax running | No (requests fail) | Yes (fails open) |

For production deployments, proxy mode provides the strongest security guarantees because it can block at every stage. Server mode is better for gradual rollout since it fails open if Parallax is unavailable.
