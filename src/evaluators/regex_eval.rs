use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use regex::Regex;
use tracing::warn;

use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::{Action, EvalResult};
use crate::evaluators::Evaluator;

/// A single compiled pattern with optional negation and field targeting.
struct PatternEntry {
    regex: Regex,
    negate: bool,
    field: Option<String>,
}

/// A rule consisting of one or more patterns with a match mode.
struct RegexRule {
    label: String,
    action: Action,
    fields: Option<Vec<String>>,
    patterns: Vec<PatternEntry>,
    match_mode: MatchMode,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MatchMode {
    Any,
    All,
}

impl RegexRule {
    fn from_config(raw: &serde_yaml::Value) -> Option<Self> {
        let map = raw.as_mapping()?;
        let label = map
            .get(serde_yaml::Value::String("label".into()))?
            .as_str()?
            .to_string();
        let action_str = map
            .get(serde_yaml::Value::String("action".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("block");
        let action = match action_str {
            "block" => Action::Block,
            "detect" => Action::Detect,
            "redact" => Action::Redact,
            "allow" => Action::Allow,
            _ => {
                warn!(label, action = action_str, "Unknown action, defaulting to block");
                Action::Block
            }
        };

        let fields = map
            .get(serde_yaml::Value::String("fields".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        let match_mode = map
            .get(serde_yaml::Value::String("match".into()))
            .and_then(|v| v.as_str())
            .map(|s| {
                if s == "all" {
                    MatchMode::All
                } else {
                    MatchMode::Any
                }
            })
            .unwrap_or(MatchMode::Any);

        let mut patterns = Vec::new();

        // Single pattern shorthand
        if let Some(p) = map
            .get(serde_yaml::Value::String("pattern".into()))
            .and_then(|v| v.as_str())
        {
            match Regex::new(p) {
                Ok(re) => patterns.push(PatternEntry {
                    regex: re,
                    negate: false,
                    field: None,
                }),
                Err(e) => {
                    warn!(label, pattern = p, error = %e, "Invalid regex pattern, skipping rule");
                    return None;
                }
            }
        }

        // Multiple patterns
        if let Some(seq) = map
            .get(serde_yaml::Value::String("patterns".into()))
            .and_then(|v| v.as_sequence())
        {
            for entry in seq {
                if let Some(s) = entry.as_str() {
                    match Regex::new(s) {
                        Ok(re) => patterns.push(PatternEntry {
                            regex: re,
                            negate: false,
                            field: None,
                        }),
                        Err(e) => {
                            warn!(label, pattern = s, error = %e, "Invalid regex, skipping pattern");
                        }
                    }
                } else if let Some(m) = entry.as_mapping() {
                    let pat = m
                        .get(serde_yaml::Value::String("pattern".into()))
                        .and_then(|v| v.as_str());
                    let negate = m
                        .get(serde_yaml::Value::String("negate".into()))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let field = m
                        .get(serde_yaml::Value::String("field".into()))
                        .and_then(|v| v.as_str())
                        .map(String::from);

                    if let Some(pat_str) = pat {
                        match Regex::new(pat_str) {
                            Ok(re) => patterns.push(PatternEntry {
                                regex: re,
                                negate,
                                field,
                            }),
                            Err(e) => {
                                warn!(label, pattern = pat_str, error = %e, "Invalid regex, skipping");
                            }
                        }
                    }
                }
            }
        }

        if patterns.is_empty() {
            warn!(label, "No valid patterns in rule, skipping");
            return None;
        }

        Some(RegexRule {
            label,
            action,
            fields,
            patterns,
            match_mode,
        })
    }
}

/// Evaluator that matches events against compiled regex patterns.
///
/// Supports:
/// - Single or multiple patterns per rule
/// - AND / OR match modes
/// - Pattern negation
/// - Per-pattern field targeting
/// - Redaction of matched content
pub struct RegexEvaluator {
    name: String,
    stages: HashSet<Stage>,
    rules: Vec<RegexRule>,
}

impl RegexEvaluator {
    pub fn new(name: String, config: &serde_yaml::Value) -> Self {
        let map = config.as_mapping().cloned().unwrap_or_default();

        let stages = map
            .get(serde_yaml::Value::String("stages".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| {
                        let s = v.as_str()?;
                        serde_yaml::from_str(s).ok()
                    })
                    .collect()
            })
            .unwrap_or_else(|| [Stage::ToolBefore, Stage::ToolAfter].into_iter().collect());

        let rules = map
            .get(serde_yaml::Value::String("rules".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| seq.iter().filter_map(RegexRule::from_config).collect())
            .unwrap_or_default();

        Self {
            name,
            stages,
            rules,
        }
    }

    fn check_rule(
        rule: &RegexRule,
        target: &str,
        flat: &HashMap<String, String>,
    ) -> (bool, Option<String>) {
        let mut first_match: Option<String> = None;
        let mut results = Vec::new();

        for p in &rule.patterns {
            let text = if let Some(ref field) = p.field {
                flat.get(field).map(|s| s.as_str()).unwrap_or("")
            } else {
                target
            };

            let m = p.regex.find(text);
            let hit = if p.negate { m.is_none() } else { m.is_some() };

            if !p.negate {
                if let Some(mat) = m {
                    if first_match.is_none() {
                        first_match = Some(mat.as_str().to_string());
                    }
                }
            }

            results.push(hit);
        }

        if results.is_empty() {
            return (false, None);
        }

        let matched = match rule.match_mode {
            MatchMode::All => results.iter().all(|&r| r),
            MatchMode::Any => results.iter().any(|&r| r),
        };

        (matched, first_match)
    }
}

#[async_trait]
impl Evaluator for RegexEvaluator {
    fn name(&self) -> &str {
        &self.name
    }

    fn eval_type(&self) -> &str {
        "regex"
    }

    fn stages(&self) -> &HashSet<Stage> {
        &self.stages
    }

    async fn evaluate(&self, ctx: &EvalContext) -> EvalResult {
        let flat = ctx.flat_fields();
        let full_text = ctx.searchable_text();

        for rule in &self.rules {
            let targets: Vec<&str> = if let Some(ref fields) = rule.fields {
                fields
                    .iter()
                    .filter_map(|f| flat.get(f).map(|s| s.as_str()))
                    .collect()
            } else {
                vec![full_text.as_str()]
            };

            for target in targets {
                let (matched, first_match) = Self::check_rule(rule, target, &flat);
                if matched {
                    let redacted = if rule.action == Action::Redact {
                        let mut text = target.to_string();
                        for p in &rule.patterns {
                            if !p.negate {
                                text = p.regex.replace_all(&text, "[REDACTED]").to_string();
                            }
                        }
                        Some(text)
                    } else {
                        None
                    };

                    let match_preview = first_match
                        .as_deref()
                        .map(|s| if s.len() > 200 { &s[..200] } else { s })
                        .unwrap_or("");

                    return EvalResult {
                        evaluator: self.name.clone(),
                        action: rule.action,
                        confidence: 1.0,
                        reason: format!("Regex match: {}", rule.label),
                        redacted,
                        metadata: [
                            (
                                "rule".to_string(),
                                serde_json::json!(rule.label),
                            ),
                            (
                                "match".to_string(),
                                serde_json::json!(match_preview),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    };
                }
            }
        }

        EvalResult::allow(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evaluator(yaml: &str) -> RegexEvaluator {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        RegexEvaluator::new("test-regex".into(), &config)
    }

    fn tool_ctx(command: &str) -> EvalContext {
        EvalContext {
            stage: Stage::ToolBefore,
            session_id: String::new(),
            channel: String::new(),
            user_id: String::new(),
            timestamp: 0.0,
            message_text: None,
            tool_name: Some("exec".into()),
            tool_args: [("command".into(), serde_json::json!(command))]
                .into_iter()
                .collect(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_simple_block() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "dangerous rm"
    pattern: "rm\\s+-rf\\s+/"
    action: block
"#,
        );
        let ctx = tool_ctx("rm -rf /");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Block);
        assert!(result.reason.contains("dangerous rm"));
    }

    #[tokio::test]
    async fn test_no_match_allows() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "dangerous rm"
    pattern: "rm\\s+-rf\\s+/"
    action: block
"#,
        );
        let ctx = tool_ctx("ls -la");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Allow);
    }

    #[tokio::test]
    async fn test_redact() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "AWS key"
    pattern: "AKIA[0-9A-Z]{16}"
    action: redact
"#,
        );
        let ctx = tool_ctx("key is AKIAIOSFODNN7EXAMPLE");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Redact);
        assert!(result.redacted.unwrap().contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_field_targeting() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "rm in command field"
    pattern: "rm\\s+-rf"
    action: block
    fields: [tool_args.command]
"#,
        );
        let ctx = tool_ctx("rm -rf /tmp");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Block);
    }

    #[tokio::test]
    async fn test_multi_pattern_all() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "must match both"
    action: block
    match: all
    patterns:
      - "rm"
      - "-rf"
"#,
        );
        let ctx = tool_ctx("rm -rf /");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Block);

        let ctx2 = tool_ctx("rm file.txt");
        let result2 = eval.evaluate(&ctx2).await;
        assert_eq!(result2.action, Action::Allow);
    }

    #[tokio::test]
    async fn test_negate_pattern() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "rm without safe flag"
    action: block
    match: all
    patterns:
      - "rm\\s+"
      - pattern: "--interactive"
        negate: true
"#,
        );
        // rm without --interactive should block
        let ctx = tool_ctx("rm -rf /");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Block);

        // rm with --interactive should allow
        let ctx2 = tool_ctx("rm --interactive file.txt");
        let result2 = eval.evaluate(&ctx2).await;
        assert_eq!(result2.action, Action::Allow);
    }
}
