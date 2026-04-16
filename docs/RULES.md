# Security Rules Reference

Parallax ships with **51 rules across 13 threat categories**, providing defense-in-depth for AI agent systems. Rules are organized by threat type, not by evaluator engine -- you can customize, extend, or disable any rule.

**Design principles:**

- **Cost-ordered evaluation** -- cheap evaluators (regex, pattern) run before expensive ones (SQL). The chain short-circuits on the first `block`, so most events are resolved in microseconds.
- **Layered defense** -- the same threat may be caught by multiple rule types. A dangerous `rm -rf /` is caught by both a regex rule and a CEL policy. This redundancy is intentional.
- **Tunable severity** -- rules use `block`, `redact`, or `detect` actions. Switch a rule from `block` to `detect` to monitor before enforcing.
- **Normalized metadata** -- all rule types share the same core metadata fields: `id`, `title`, and `description`. This enables consistent filtering, reporting, and auditing across evaluator engines.

---

## Rule Metadata

Every rule, regardless of evaluator engine, has three standard metadata fields:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier for the rule (e.g. `cel-pe-001`, `regex-sec-003`, `pi-001`) |
| `title` | Yes | Short human-readable name |
| `description` | Yes | Longer explanation of what the rule detects and why |

When a rule triggers, `id`, `title`, and `description` are included in the evaluation result metadata alongside engine-specific fields.

**ID conventions by engine:**

| Engine | Prefix | Example |
|--------|--------|---------|
| Sigma | category-specific | `dt-001`, `pi-002`, `recon-003`, `shadow-001` |
| CEL | `cel-{category}-NNN` | `cel-pol-001`, `cel-pe-003`, `cel-mm-002` |
| Regex | `regex-{category}-NNN` | `regex-sec-001`, `regex-pii-003`, `regex-cmd-002` |
| Pattern | `pat-{category}-NNN` | `pat-sql-001`, `pat-sc-002` |
| SQL | `sql-{category}-NNN` | `sql-rl-001`, `sql-rl-002` |

---

## Prompt Injection

Detects attempts to extract system prompts, jailbreak the model, or override safety constraints.

**Engine:** Sigma | **File:** `rules/sigma/prompt-injection.yaml` | **Stage:** `message.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| pi-001 | System prompt extraction attempt | Detects messages attempting to extract the system prompt or initial instructions | Block |
| pi-002 | Jailbreak pattern detected | Detects common jailbreak and guardrail bypass attempts | Block |
| pi-003 | Role-play escape attempt | Detects attempts to redefine the agent role or bypass constraints via role-play | Block |

**False-positive notes:** Legitimate discussions about AI safety or prompt engineering may trigger pi-001/pi-002. Consider switching to `detect` in research/educational environments.

---

## Secret Scanning

Redacts or blocks common secret patterns before they leak through tool calls or responses.

**Engine:** Regex | **Evaluator:** `secrets-scanner` | **Stage:** `tool.before`, `tool.after`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| regex-sec-001 | AWS Access Key | Detects AWS access key IDs starting with AKIA | Redact |
| regex-sec-002 | AWS Secret Key | Detects AWS secret access keys in configuration or environment variables | Redact |
| regex-sec-003 | GitHub Personal Access Token | Detects GitHub personal access tokens (classic format) | Redact |
| regex-sec-004 | GitHub Fine-Grained Token | Detects GitHub fine-grained personal access tokens | Redact |
| regex-sec-005 | Generic API Key | Detects generic API keys and secret keys in assignments | Redact |
| regex-sec-006 | Private Key Block | Detects PEM-encoded private key blocks | Block |

**False-positive notes:** The generic API key pattern may match configuration documentation that contains placeholder keys. Use the `fields` option to restrict matching to specific fields if needed.

---

## PII Exposure

Redacts personally identifiable information from tool outputs before they reach the user or external systems.

**Engine:** Regex | **Evaluator:** `pii-scanner` | **Stage:** `tool.after`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| regex-pii-001 | Social Security Number | Detects US Social Security Numbers in NNN-NN-NNNN format | Redact |
| regex-pii-002 | Credit Card - Visa | Detects Visa credit card numbers | Redact |
| regex-pii-003 | Credit Card - Mastercard | Detects Mastercard credit card numbers | Redact |
| regex-pii-004 | Credit Card - Amex | Detects American Express credit card numbers | Redact |
| regex-pii-005 | US Phone Number | Detects US phone numbers in various formats | Redact |

**False-positive notes:** The SSN pattern will match any `NNN-NN-NNNN` format, including some date formats and version numbers. The phone number pattern may match numeric sequences in technical output.

---

## Data Exfiltration

Detects encoded data and indicators of data being prepared for exfiltration.

**Engine:** Regex | **Evaluator:** `data-exfiltration` | **Stage:** `tool.before`, `tool.after`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| regex-exfil-001 | Base64-encoded secret indicator | Detects base64-encoded values following secret-like key names | Detect |
| regex-exfil-002 | Long hex-encoded data block | Detects long hex-encoded strings that may indicate data exfiltration | Detect |
| regex-exfil-003 | Data URI with base64 | Detects data URIs with large base64 payloads | Detect |

---

## Dangerous Commands

Blocks dangerous shell commands before they execute. Covered by multiple engines for defense-in-depth.

**Engine:** Regex | **Evaluator:** `dangerous-commands` | **Stage:** `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| regex-cmd-001 | Recursive delete root | Blocks recursive deletion of root filesystem | Block |
| regex-cmd-002 | Format disk | Blocks filesystem formatting commands | Block |
| regex-cmd-003 | Disk overwrite | Blocks raw disk writes via dd to device files | Block |
| regex-cmd-004 | Chmod 777 recursive | Detects recursive permission changes to world-writable | Detect |
| regex-cmd-005 | Curl pipe to shell | Blocks piping curl output directly to a shell interpreter | Block |

**Engine:** CEL | **File:** `rules/cel/policies.yaml` | **Stage:** `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| cel-pol-001 | Block recursive file deletion | Prevents recursive file deletion via rm -r commands | Block |
| cel-pol-002 | Block world-writable permissions | Prevents setting chmod 777 which makes files world-writable | Block |
| cel-pol-003 | Warn on sudo usage | Detects elevated privilege execution via sudo | Detect |
| cel-pol-004 | Block environment variable dump | Detects environment variable dumps that may expose secrets | Detect |

---

## Privilege Escalation

Detects attempts to gain elevated permissions.

**Engine:** CEL | **File:** `rules/cel/privilege-escalation.yaml` | **Stage:** `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| cel-pe-001 | Block sudo privilege escalation | Blocks privilege escalation via sudo command | Block |
| cel-pe-002 | Block user switching | Blocks switching to another user via su command | Block |
| cel-pe-003 | Block pkexec privilege escalation | Blocks privilege escalation via pkexec | Block |
| cel-pe-004 | Block doas privilege escalation | Blocks privilege escalation via doas command | Block |
| cel-pe-005 | Block chown to root | Blocks changing file ownership to root | Block |
| cel-pe-006 | Block setuid bit | Blocks setting the setuid bit on files | Block |
| cel-pe-007 | Block sudoers modification | Blocks modifying the sudoers configuration | Block |

**False-positive notes:** Agents that legitimately need `sudo` for package installation or system configuration should have the `warn-sudo` detect-only rule from `policies.yaml` rather than the hard `block-sudo`.

---

## Reconnaissance

Detects attempts to access credential files, system configuration, or cloud metadata.

**Engine:** Sigma | **File:** `rules/sigma/reconnaissance.yaml` | **Stage:** `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| recon-001 | Sensitive file read - credentials and keys | Detects tool calls reading credential files, SSH keys, or secret stores | Block |
| recon-002 | System file reconnaissance | Detects reads of system files commonly targeted for information gathering | Block |
| recon-003 | Cloud metadata endpoint access | Detects access to cloud instance metadata services used for credential theft | Block |
| recon-004 | Container and orchestration config access | Detects reads of Kubernetes, Docker, and container configuration files | Block |

---

## Sensitive File Writes

Detects tool calls that write to critical system directories.

**Engine:** Sigma | **File:** `rules/sigma/dangerous-tools.yaml` | **Stage:** `tool.before`, `tool.after`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| dt-001 | Suspicious file write outside workspace | Detects tool calls that write files to sensitive system directories | Block |
| dt-002 | Shell command with network exfiltration indicators | Detects exec tool calls that combine data access with network transfer | Block |
| dt-003 | Database credential access via tool | Detects tool calls that read database configuration or credential files | Block |

---

## Shadow IT

Detects agents creating infrastructure or modifying system resources without approval.

**Engine:** Sigma | **File:** `rules/sigma/shadow-it.yaml` | **Stage:** `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| shadow-001 | Container runtime operations | Detects agent creating, running, or building containers without approval | Block |
| shadow-002 | Kubernetes cluster operations | Detects agent deploying or modifying Kubernetes resources | Block |
| shadow-003 | Cloud infrastructure provisioning | Detects agent provisioning or modifying cloud infrastructure | Block |
| shadow-004 | User account management | Detects agent creating or modifying system user accounts | Block |

**False-positive notes:** DevOps agents that legitimately manage infrastructure should selectively disable shadow-001 through shadow-003 while keeping shadow-004 active.

---

## Model Manipulation

Detects attempts to tamper with model parameters or redefine tool behavior.

**Engine:** CEL | **File:** `rules/cel/model-manipulation.yaml` | **Stage:** `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| cel-mm-001 | Block system prompt injection via tools | Detects attempts to modify the system prompt through tool calls | Block |
| cel-mm-002 | Detect temperature override attempt | Detects attempts to modify the model temperature parameter | Detect |
| cel-mm-003 | Detect tool definitions tampering | Detects attempts to modify or redefine available tool definitions | Detect |
| cel-mm-004 | Detect max_tokens override attempt | Detects attempts to modify the max_tokens parameter | Detect |

---

## Supply Chain

Blocks untrusted package installs and dependency confusion attacks.

**Engine:** Pattern | **Evaluator:** `supply-chain` | **Stage:** `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| pat-sc-001 | Pip install from custom index | Blocks pip installs from non-default package indexes | Block |
| pat-sc-002 | Npm install from custom registry | Blocks npm installs from non-default registries | Block |
| pat-sc-003 | Wget pipe to shell | Blocks piping wget output directly to a shell interpreter | Block |
| pat-sc-004 | Gem install from custom source | Blocks gem installs from non-default sources | Block |

---

## SQL Injection

Detects common SQL injection patterns in messages and tool arguments.

**Engine:** Pattern | **Evaluator:** `sql-keywords` | **Stage:** `message.before`, `tool.before`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| pat-sql-001 | SQL destructive keywords | Detects common SQL injection and destructive query patterns | Detect |

**False-positive notes:** Database administration agents will regularly trigger this rule. Switch to `allow` for trusted database management workflows.

---

## Resource Abuse

Detects abnormal tool usage rates that may indicate automated abuse or infinite loops.

**Engine:** SQL | **Evaluator:** `rate-limits` | **Stage:** `tool.before`, `tool.after`

| ID | Title | Description | Action |
|----|-------|-------------|--------|
| sql-rl-001 | High tool call rate | Detects unusually high tool call rates per session | Detect |
| sql-rl-002 | Repeated tool abuse | Detects repeated calls to the same tool in a short window | Detect |

---

## Writing Custom Rules

All custom rules should include the three standard metadata fields: `id`, `title`, and `description`.

### Adding a Sigma rule

Create a `.yaml` file in `rules/sigma/`. It will be auto-loaded:

```yaml
title: My custom rule
id: custom-001
description: What this rule detects and why it matters
detection:
  selection:
    tool_name: exec
  pattern:
    tool_args.command|contains:
      - "my-dangerous-command"
  condition: selection and pattern
action: block    # block, detect, redact, or allow
```

### Adding a CEL rule

Add to an existing file in `rules/cel/` or create a new file and reference it in `config.yaml`:

```yaml
- id: cel-custom-001
  title: My custom CEL rule
  description: Description of what this rule detects
  expr: 'tool_name == "exec" && tool_args_command.contains("dangerous")'
  action: block
  reason: Description of why this is blocked
```

### Adding a regex rule

Add to an evaluator block in `config.yaml`:

```yaml
rules:
  - id: regex-custom-001
    title: My pattern
    description: Detects a dangerous regex pattern in tool arguments
    pattern: "dangerous-regex-here"
    action: block           # block, redact, detect, allow
    fields: [tool_args.command]  # optional: target specific fields
```

### Adding a pattern rule

Add to a pattern evaluator block in `config.yaml`:

```yaml
rules:
  - id: pat-custom-001
    title: My keyword rule
    description: Detects dangerous keywords in tool arguments
    keywords: ["dangerous-keyword"]
    action: block
```

### Adding a SQL rule

Add to the `rate-limits` evaluator in `config.yaml`:

```yaml
rules:
  - id: sql-custom-001
    title: My aggregate rule
    description: Detects abnormal event patterns using SQL aggregation
    query: >
      SELECT COUNT(*) as cnt FROM events
      WHERE session_id = :session_id AND timestamp > :now - 120
    condition: "cnt > 10"
    action: detect
    reason: "What this means"
```

Available SQL parameters: `:session_id`, `:user_id`, `:channel`, `:tool_name`, `:now`
