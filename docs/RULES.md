# Security Rules Reference

Parallax ships with **51 rules across 13 threat categories**, providing defense-in-depth for AI agent systems. Rules are organized by threat type, not by evaluator engine -- you can customize, extend, or disable any rule.

**Design principles:**

- **Cost-ordered evaluation** -- cheap evaluators (regex, pattern) run before expensive ones (SQL). The chain short-circuits on the first `block`, so most events are resolved in microseconds.
- **Layered defense** -- the same threat may be caught by multiple rule types. A dangerous `rm -rf /` is caught by both a regex rule and a CEL policy. This redundancy is intentional.
- **Tunable severity** -- rules use `block`, `redact`, or `detect` actions. Switch a rule from `block` to `detect` to monitor before enforcing.

---

## Prompt Injection

Detects attempts to extract system prompts, jailbreak the model, or override safety constraints.

**Engine:** Sigma | **File:** `rules/sigma/prompt-injection.yaml` | **Stage:** `message.before`

| ID | Rule | What it detects | Severity | Action |
|----|------|-----------------|----------|--------|
| pi-001 | System prompt extraction | "ignore previous instructions", "repeat the above", "show your system prompt" | High | Block |
| pi-002 | Jailbreak patterns | "you are now", "DAN mode", "developer mode", "no restrictions" | High | Block |
| pi-003 | Role-play escape | "roleplay as", "you have no restrictions", "bypass your safety" | High | Block |

**False-positive notes:** Legitimate discussions about AI safety or prompt engineering may trigger pi-001/pi-002. Consider switching to `detect` in research/educational environments.

---

## Secret Scanning

Redacts or blocks common secret patterns before they leak through tool calls or responses.

**Engine:** Regex | **Evaluator:** `secrets-scanner` | **Stage:** `tool.before`, `tool.after`

| Rule | Pattern | Severity | Action |
|------|---------|----------|--------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | High | Redact |
| AWS Secret Key | `aws_secret_access_key\s*[=:]...` | High | Redact |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | High | Redact |
| GitHub Fine-Grained Token | `github_pat_[A-Za-z0-9_]{82}` | High | Redact |
| Generic API Key | `(api[_-]?key\|secret[_-]?key)\s*[=:]...` | Medium | Redact |
| Private Key Block | `-----BEGIN ... PRIVATE KEY-----` | Critical | Block |

**False-positive notes:** The generic API key pattern may match configuration documentation that contains placeholder keys. Use the `fields` option to restrict matching to specific fields if needed.

---

## PII Exposure

Redacts personally identifiable information from tool outputs before they reach the user or external systems.

**Engine:** Regex | **Evaluator:** `pii-scanner` | **Stage:** `tool.after`

| Rule | Pattern | Severity | Action |
|------|---------|----------|--------|
| Social Security Number | `\d{3}-\d{2}-\d{4}` | High | Redact |
| Credit Card - Visa | `4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}` | High | Redact |
| Credit Card - Mastercard | `5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}` | High | Redact |
| Credit Card - Amex | `3[47]\d{2}[- ]?\d{6}[- ]?\d{5}` | High | Redact |
| US Phone Number | `(\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}` | Medium | Redact |

**False-positive notes:** The SSN pattern will match any `NNN-NN-NNNN` format, including some date formats and version numbers. The phone number pattern may match numeric sequences in technical output.

---

## Data Exfiltration

Detects encoded data and indicators of data being prepared for exfiltration.

**Engine:** Regex | **Evaluator:** `data-exfiltration` | **Stage:** `tool.before`, `tool.after`

| Rule | What it detects | Severity | Action |
|------|-----------------|----------|--------|
| Base64-encoded secret | `password=`, `token=` followed by long base64 string | Medium | Detect |
| Hex-encoded data block | 64+ character hex strings | Low | Detect |
| Data URI with base64 | `data:...;base64,` with large payloads | Medium | Detect |

---

## Dangerous Commands

Blocks dangerous shell commands before they execute. Covered by multiple engines for defense-in-depth.

**Engine:** Regex | **Evaluator:** `dangerous-commands` | **Stage:** `tool.before`

| Rule | What it blocks | Severity | Action |
|------|----------------|----------|--------|
| Recursive delete root | `rm -rf /` | Critical | Block |
| Format disk | `mkfs.*` | Critical | Block |
| Disk overwrite | `dd ... of=/dev/` | Critical | Block |
| Chmod 777 recursive | `chmod -R 777` | High | Detect |
| Curl pipe to shell | `curl ... \| bash` | Critical | Block |

**Engine:** CEL | **File:** `rules/cel/policies.yaml` | **Stage:** `tool.before`

| Rule | What it catches | Severity | Action |
|------|-----------------|----------|--------|
| block-rm-rf | Recursive file deletion | Critical | Block |
| block-chmod-777 | World-writable permissions | High | Block |
| warn-sudo | Elevated privilege execution | Medium | Detect |
| block-env-dump | Environment variable dumps | Medium | Detect |

---

## Privilege Escalation

Detects attempts to gain elevated permissions.

**Engine:** CEL | **File:** `rules/cel/privilege-escalation.yaml` | **Stage:** `tool.before`

| Rule | Expression | Severity | Action |
|------|-----------|----------|--------|
| block-sudo | `tool_args_command.matches("^sudo\\s")` | Critical | Block |
| block-su | `tool_args_command.matches("^su\\s+-\|^su\\s+root")` | Critical | Block |
| block-pkexec | `tool_args_command.contains("pkexec")` | Critical | Block |
| block-doas | `tool_args_command.matches("^doas\\s")` | Critical | Block |
| block-chown-root | `tool_args_command.matches("chown\\s+root")` | High | Block |
| block-setuid | `tool_args_command.contains("chmod u+s")` | Critical | Block |
| block-sudoers-edit | `tool_args_command.contains("visudo")` | Critical | Block |

**False-positive notes:** Agents that legitimately need `sudo` for package installation or system configuration should have the `warn-sudo` detect-only rule from `policies.yaml` rather than the hard `block-sudo`.

---

## Reconnaissance

Detects attempts to access credential files, system configuration, or cloud metadata.

**Engine:** Sigma | **File:** `rules/sigma/reconnaissance.yaml` | **Stage:** `tool.before`

| ID | Rule | What it detects | Severity | Action |
|----|------|-----------------|----------|--------|
| recon-001 | Credential and key access | `.ssh/id_*`, `.pem`, `.aws/credentials`, GCP service accounts | High | Block |
| recon-002 | System file reads | `/etc/passwd`, `/etc/shadow`, `/proc/self/` | High | Block |
| recon-003 | Cloud metadata endpoints | `169.254.169.254`, `metadata.google.internal`, `metadata.azure.com` | Critical | Block |
| recon-004 | Container config access | `.kube/config`, `.docker/config.json`, docker socket | High | Block |

---

## Sensitive File Writes

Detects tool calls that write to critical system directories.

**Engine:** Sigma | **File:** `rules/sigma/dangerous-tools.yaml` | **Stage:** `tool.before`, `tool.after`

| ID | Rule | What it detects | Severity | Action |
|----|------|-----------------|----------|--------|
| dt-001 | Sensitive file writes | `write_file` to `/etc/`, `/usr/`, `/var/`, `.ssh/` | High | Block |
| dt-002 | Network exfiltration | Shell commands combining `curl`/`wget`/`nc` with pipes or `base64` | Critical | Block |
| dt-003 | Database credential access | Reading `.env`, `credentials`, `database.yml`, `secrets.yaml` | High | Block |

---

## Shadow IT

Detects agents creating infrastructure or modifying system resources without approval.

**Engine:** Sigma | **File:** `rules/sigma/shadow-it.yaml` | **Stage:** `tool.before`

| ID | Rule | What it detects | Severity | Action |
|----|------|-----------------|----------|--------|
| shadow-001 | Container runtime ops | `docker run`, `docker build`, `podman run` | High | Block |
| shadow-002 | Kubernetes operations | `kubectl apply`, `kubectl create`, `helm install` | High | Block |
| shadow-003 | Cloud infra provisioning | `terraform apply`, `aws`, `gcloud`, `az` CLI | High | Block |
| shadow-004 | User account management | `useradd`, `adduser`, `usermod`, `passwd` | High | Block |

**False-positive notes:** DevOps agents that legitimately manage infrastructure should selectively disable shadow-001 through shadow-003 while keeping shadow-004 active.

---

## Model Manipulation

Detects attempts to tamper with model parameters or redefine tool behavior.

**Engine:** CEL | **File:** `rules/cel/model-manipulation.yaml` | **Stage:** `tool.before`

| Rule | What it catches | Severity | Action |
|------|-----------------|----------|--------|
| block-system-prompt-injection | Tampering with system prompt via tool args | Critical | Block |
| block-temperature-override | Overriding temperature parameter | Medium | Detect |
| block-tool-definitions-tampering | Redefining available tools | High | Detect |
| block-max-tokens-override | Overriding max_tokens parameter | Medium | Detect |

---

## Supply Chain

Blocks untrusted package installs and dependency confusion attacks.

**Engine:** Pattern | **Evaluator:** `supply-chain` | **Stage:** `tool.before`

| Rule | Keywords | Severity | Action |
|------|----------|----------|--------|
| Pip custom index | `pip install --index-url`, `pip install --extra-index-url` | High | Block |
| Npm custom registry | `npm install --registry`, `npm config set registry` | High | Block |
| Wget pipe to shell | `wget -O - \| bash`, `wget -O - \| sh` | Critical | Block |
| Gem custom source | `gem install --source http`, `gem sources --add http` | High | Block |

---

## SQL Injection

Detects common SQL injection patterns in messages and tool arguments.

**Engine:** Pattern | **Evaluator:** `sql-keywords` | **Stage:** `message.before`, `tool.before`

| Rule | Keywords | Severity | Action |
|------|----------|----------|--------|
| SQL destructive keywords | `DROP TABLE`, `DROP DATABASE`, `DELETE FROM`, `TRUNCATE TABLE`, `'; --`, `1=1` | High | Detect |

**False-positive notes:** Database administration agents will regularly trigger this rule. Switch to `allow` for trusted database management workflows.

---

## Resource Abuse

Detects abnormal tool usage rates that may indicate automated abuse or infinite loops.

**Engine:** SQL | **Evaluator:** `rate-limits` | **Stage:** `tool.before`, `tool.after`

| Rule | Threshold | Severity | Action |
|------|-----------|----------|--------|
| High tool call rate | > 50 calls/min per session | Medium | Detect |
| Repeated tool abuse | > 20 calls to same tool in 5 min | Medium | Detect |

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
level: high    # high/critical -> block, other -> detect
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
