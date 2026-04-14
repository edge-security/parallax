# Generic HTTP API Integration

Parallax works with any agent system that can make HTTP requests. This guide covers integrating via the evaluation API (server mode).

## Overview

Your agent sends a `POST /evaluate` request at each lifecycle stage. Parallax evaluates the event against all configured rules and returns a verdict. Your agent enforces the verdict.

```
Agent ──> POST /evaluate ──> Parallax ──> { blocked: true/false }
  │                                              │
  └── if blocked, skip the action ───────────────┘
```

## Endpoint

**POST** `http://127.0.0.1:9920/evaluate`

### Request Body

```json
{
  "stage": "tool.before",
  "session_id": "session-abc-123",
  "tool_name": "exec",
  "tool_args": {
    "command": "ls -la /tmp"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `stage` | string | Yes | `message.before`, `tool.before`, `tool.after`, or `params.before` |
| `session_id` | string | No | Session identifier (used for rate limiting) |
| `channel` | string | No | Channel or conversation identifier |
| `user_id` | string | No | User identifier |
| `tool_name` | string | No | Name of the tool being called |
| `tool_args` | object | No | Tool arguments (key-value pairs) |
| `tool_result` | any | No | Tool output (for `tool.after` stage) |
| `message_text` | string | No | User message content (for `message.before` stage) |
| `model` | string | No | Model identifier |
| `params` | object | No | Model parameters |
| `timestamp` | number | No | Unix timestamp (auto-generated if omitted) |

### Response Body

```json
{
  "action": "block",
  "blocked": true,
  "reasons": ["Regex match: Recursive delete"],
  "results": [...],
  "elapsed_ms": 0.1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | `block`, `redact`, `detect`, or `allow` |
| `blocked` | boolean | Whether the event should be blocked |
| `reasons` | string[] | Human-readable list of matched rules |
| `redacted` | string? | Redacted content (when action is `redact`) |
| `results` | object[] | Detailed per-evaluator results |
| `elapsed_ms` | number | Evaluation time in milliseconds |

## Integration Pattern

### Before tool execution

```python
# Pseudocode -- adapt to your language/framework
def before_tool_call(tool_name, tool_args, session_id):
    resp = http_post("http://localhost:9920/evaluate", {
        "stage": "tool.before",
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_args": tool_args,
    })
    if resp["blocked"]:
        raise BlockedError(resp["reasons"])
```

### After tool execution

```python
def after_tool_call(tool_name, tool_args, tool_result, session_id):
    resp = http_post("http://localhost:9920/evaluate", {
        "stage": "tool.after",
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "tool_result": tool_result,
    })
    if resp["action"] == "redact":
        tool_result = resp["redacted"]
    return tool_result
```

### Before processing user messages

```python
def before_message(message_text, session_id):
    resp = http_post("http://localhost:9920/evaluate", {
        "stage": "message.before",
        "session_id": session_id,
        "message_text": message_text,
    })
    if resp["blocked"]:
        return "This message was blocked by security policy."
```

## Health Check

**GET** `http://127.0.0.1:9920/health`

```json
{
  "status": "ok",
  "mode": "server",
  "evaluators": 10,
  "version": "0.2.0"
}
```

Use this endpoint for readiness probes and monitoring.

## Best Practices

1. **Always check `blocked`** -- even if the action is `redact`, `blocked` is false. Only `block` sets `blocked: true`.
2. **Include `session_id`** -- rate-limiting rules depend on session identification. Without it, SQL-based aggregate rules won't work correctly.
3. **Fail open or closed?** -- decide your failure mode. If Parallax is unreachable, should the agent proceed (fail open) or stop (fail closed)? For production, fail closed is recommended.
4. **Log the `elapsed_ms`** -- track evaluation latency to ensure it stays within your SLA.
