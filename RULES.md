# Security Rules Reference

Parallax ships with a default set of rules covering common AI agent threats. All rules are YAML-based and can be customized, extended, or disabled.

## Sigma Rules

Sigma rules use YAML-based detection logic with field modifiers (`contains`, `startswith`, `endswith`, `re`). They are loaded automatically from `rules/sigma/`.

### Prompt Injection

**File:** `rules/sigma/prompt-injection.yaml`
**Stage:** `message.before`
**Decision:** Block

| ID | Rule | What it detects |
|----|------|-----------------|
| pi-001 | System prompt extraction | "ignore previous instructions", "repeat the above", "show your system prompt" |
| pi-002 | Jailbreak patterns | "you are now", "DAN mode", "developer mode", "no restrictions" |
| pi-003 | Role-play escape | "roleplay as", "you have no restrictions", "bypass your safety" |

### Reconnaissance

**File:** `rules/sigma/reconnaissance.yaml`
**Stage:** `tool.before`
**Decision:** Block (recon-003: Block at critical level)

| ID | Rule | What it detects |
|----|------|-----------------|
| recon-001 | Credential and key access | `.ssh/id_*`, `.pem`, `.aws/credentials`, GCP service accounts |
| recon-002 | System file reads | `/etc/passwd`, `/etc/shadow`, `/proc/self/` |
| recon-003 | Cloud metadata endpoints | `169.254.169.254`, `metadata.google.internal`, `metadata.azure.com` |
| recon-004 | Container config access | `.kube/config`, `.docker/config.json`, docker socket |

### Shadow IT

**File:** `rules/sigma/shadow-it.yaml`
**Stage:** `tool.before`
**Decision:** Block

| ID | Rule | What it detects |
|----|------|-----------------|
| shadow-001 | Container runtime ops | `docker run`, `docker build`, `podman run` |
| shadow-002 | Kubernetes operations | `kubectl apply`, `kubectl create`, `helm install` |
| shadow-003 | Cloud infra provisioning | `terraform apply`, `aws`, `gcloud`, `az` CLI |
| shadow-004 | User account management | `useradd`, `adduser`, `usermod`, `passwd` |

### Dangerous Tools

**File:** `rules/sigma/dangerous-tools.yaml`
**Stage:** `tool.before`, `tool.after`
**Decision:** Block

| ID | Rule | What it detects |
|----|------|-----------------|
| oc-001 | Sensitive file writes | `write_file` to `/etc/`, `/usr/`, `/var/`, `.ssh/` |
| oc-002 | Network exfiltration | Shell commands combining `curl`/`wget`/`nc` with pipes or `base64` |
| oc-003 | Database credential access | Reading `.env`, `credentials`, `database.yml`, `secrets.yaml` |

---

## CEL Rules

CEL rules use expression-based policies evaluated against flattened event fields (dots become underscores: `tool_args.command` becomes `tool_args_command`).

### Privilege Escalation

**File:** `rules/cel/privilege-escalation.yaml`
**Stage:** `tool.before`
**Decision:** Block

| Rule | Expression | What it blocks |
|------|-----------|----------------|
| block-sudo | `tool_args_command.matches("^sudo\\s")` | Any sudo command |
| block-su | `tool_args_command.matches("^su\\s+-\|^su\\s+root")` | Switching to another user |
| block-pkexec | `tool_args_command.contains("pkexec")` | PolicyKit privilege escalation |
| block-doas | `tool_args_command.matches("^doas\\s")` | OpenBSD doas privilege escalation |
| block-chown-root | `tool_args_command.matches("chown\\s+root")` | Changing ownership to root |
| block-setuid | `tool_args_command.contains("chmod u+s")` | Setting the setuid bit |
| block-sudoers-edit | `tool_args_command.contains("visudo")` | Modifying sudoers config |

### Model Manipulation

**File:** `rules/cel/model-manipulation.yaml`
**Stage:** `tool.before`
**Decision:** Block / Detect

| Rule | Expression | What it catches |
|------|-----------|-----------------|
| block-system-prompt-injection | `contains("system_prompt") \|\| contains("system_message")` | Tampering with system prompt |
| block-temperature-override | `contains("temperature") && matches("temperature.*(=\|:)\\s*[0-9]")` | Overriding temperature |
| block-tool-definitions-tampering | `contains("tool_definitions") \|\| contains("\"tools\"")` | Redefining available tools |
| block-max-tokens-override | `contains("max_tokens") && matches(...)` | Overriding max_tokens |

### General Policies

**File:** `rules/cel/policies.yaml`
**Stage:** `tool.before`
**Decision:** Block / Detect

| Rule | What it catches |
|------|-----------------|
| block-rm-rf | Recursive file deletion |
| block-chmod-777 | World-writable permissions |
| warn-sudo | Elevated privilege execution (detect only) |
| block-env-dump | Environment variable dumps |

---

## Regex Rules (config.yaml)

Regex rules are defined inline in `config.yaml`. They support compiled patterns, field targeting, and automatic redaction.

### Secret Scanning

**Evaluator:** `secrets-scanner`
**Stage:** `tool.before`, `tool.after`

| Rule | Pattern | Decision |
|------|---------|----------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | Redact |
| AWS Secret Key | `aws_secret_access_key\s*[=:]...` | Redact |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | Redact |
| GitHub Fine-Grained Token | `github_pat_[A-Za-z0-9_]{82}` | Redact |
| Generic API Key | `(api[_-]?key\|secret[_-]?key)\s*[=:]...` | Redact |
| Private Key Block | `-----BEGIN ... PRIVATE KEY-----` | Block |

### PII Leakage

**Evaluator:** `pii-scanner`
**Stage:** `tool.after`

| Rule | Pattern | Decision |
|------|---------|----------|
| Social Security Number | `\d{3}-\d{2}-\d{4}` | Redact |
| Credit Card - Visa | `4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}` | Redact |
| Credit Card - Mastercard | `5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}` | Redact |
| Credit Card - Amex | `3[47]\d{2}[- ]?\d{6}[- ]?\d{5}` | Redact |
| US Phone Number | `(\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}` | Redact |

### Data Exfiltration

**Evaluator:** `data-exfiltration`
**Stage:** `tool.before`, `tool.after`

| Rule | What it detects | Decision |
|------|-----------------|----------|
| Base64-encoded secret | `password=`, `token=` followed by long base64 string | Detect |
| Hex-encoded data block | 64+ character hex strings | Detect |
| Data URI with base64 | `data:...;base64,` with large payloads | Detect |

### Dangerous Commands

**Evaluator:** `dangerous-commands`
**Stage:** `tool.before`

| Rule | What it blocks | Decision |
|------|----------------|----------|
| Recursive delete root | `rm -rf /` | Block |
| Format disk | `mkfs.*` | Block |
| Disk overwrite | `dd ... of=/dev/` | Block |
| Chmod 777 recursive | `chmod -R 777` | Detect |
| Curl pipe to shell | `curl ... \| bash` | Block |

---

## Pattern Rules (config.yaml)

Pattern rules match keyword substrings (case-insensitive, no regex needed).

### Supply Chain

**Evaluator:** `supply-chain`
**Stage:** `tool.before`
**Decision:** Block

| Rule | Keywords |
|------|----------|
| Pip custom index | `pip install --index-url`, `pip install --extra-index-url` |
| Npm custom registry | `npm install --registry`, `npm config set registry` |
| Wget pipe to shell | `wget -O - \| bash`, `wget -O - \| sh` |
| Gem custom source | `gem install --source http`, `gem sources --add http` |

### SQL Injection

**Evaluator:** `sql-keywords`
**Stage:** `message.before`, `tool.before`
**Decision:** Detect

| Rule | Keywords |
|------|----------|
| SQL destructive keywords | `DROP TABLE`, `DROP DATABASE`, `DELETE FROM`, `TRUNCATE TABLE`, `'; --`, `1=1` |

---

## SQL Rules (config.yaml)

SQL rules use in-memory SQLite to detect patterns over time (rate limiting, frequency analysis).

### Resource Abuse

**Evaluator:** `rate-limits`
**Stage:** `tool.before`, `tool.after`
**Decision:** Detect

| Rule | Query | Threshold |
|------|-------|-----------|
| High tool call rate | Count events per session in last 60s | > 50 calls/min |
| Repeated tool abuse | Count same tool per session in last 300s | > 20 calls/5min |

---

## Writing Custom Rules

### Adding a Sigma rule

Create a `.yaml` file in `rules/sigma/`. It will be auto-loaded:

```yaml
title: My custom rule
id: custom-001
description: What this rule detects
detection:
  selection:
    tool_name: exec
  pattern:
    tool_args.command|contains:
      - "my-dangerous-command"
  condition: selection and pattern
level: high    # high/critical → block, other → detect
```

### Adding a CEL rule

Add to an existing file in `rules/cel/` or create a new file and reference it in `config.yaml`:

```yaml
- label: my-custom-rule
  expr: 'tool_name == "exec" && tool_args_command.contains("dangerous")'
  action: block
  reason: Description of why this is blocked
```

### Adding a regex rule

Add to an evaluator block in `config.yaml`:

```yaml
rules:
  - label: "My pattern"
    pattern: "dangerous-regex-here"
    action: block           # block, redact, detect, allow
    fields: [tool_args.command]  # optional: target specific fields
```

### Adding a SQL rule

Add to the `rate-limits` evaluator in `config.yaml`:

```yaml
rules:
  - label: "My aggregate rule"
    query: >
      SELECT COUNT(*) as cnt FROM events
      WHERE session_id = :session_id AND timestamp > :now - 120
    condition: "cnt > 10"
    action: detect
    reason: "What this means"
```

Available SQL parameters: `:session_id`, `:user_id`, `:channel`, `:tool_name`, `:now`
