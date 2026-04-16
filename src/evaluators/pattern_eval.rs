use std::collections::HashSet;

use async_trait::async_trait;
use tracing::warn;

use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::{Action, EvalResult};
use crate::evaluators::Evaluator;

/// A simple keyword / substring rule.
struct PatternRule {
    label: String,
    action: Action,
    keywords: Vec<String>,
    case_sensitive: bool,
}

/// Evaluator that checks for keyword / substring matches.
///
/// Simpler and faster than regex for exact substring detection.
/// Use this when you don't need regex power — just "does this text contain X?".
pub struct PatternEvaluator {
    name: String,
    stages: HashSet<Stage>,
    rules: Vec<PatternRule>,
}

impl PatternEvaluator {
    /// Create a new pattern evaluator from its YAML config block.
    pub fn new(name: String, config: &serde_yaml::Value) -> Self {
        let map = config.as_mapping().cloned().unwrap_or_default();

        let stages = map
            .get(serde_yaml::Value::String("stages".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| serde_yaml::from_str(v.as_str()?).ok())
                    .collect()
            })
            .unwrap_or_else(|| [Stage::ToolBefore, Stage::ToolAfter].into_iter().collect());

        let rules = map
            .get(serde_yaml::Value::String("rules".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|entry| {
                        let m = entry.as_mapping()?;
                        let label = m
                            .get(serde_yaml::Value::String("label".into()))?
                            .as_str()?
                            .to_string();
                        let action_str = m
                            .get(serde_yaml::Value::String("action".into()))
                            .and_then(|v| v.as_str())
                            .unwrap_or("detect");
                        let action = match action_str {
                            "block" => Action::Block,
                            "redact" => Action::Redact,
                            "detect" => Action::Detect,
                            "allow" => Action::Allow,
                            _ => {
                                warn!(label, action = action_str, "Unknown action");
                                Action::Detect
                            }
                        };
                        let keywords: Vec<String> = m
                            .get(serde_yaml::Value::String("keywords".into()))
                            .and_then(|v| v.as_sequence())
                            .map(|seq| {
                                seq.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let case_sensitive = m
                            .get(serde_yaml::Value::String("case_sensitive".into()))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        if keywords.is_empty() {
                            warn!(label, "No keywords in pattern rule, skipping");
                            return None;
                        }

                        Some(PatternRule {
                            label,
                            action,
                            keywords,
                            case_sensitive,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            name,
            stages,
            rules,
        }
    }
}

#[async_trait]
impl Evaluator for PatternEvaluator {
    fn name(&self) -> &str {
        &self.name
    }

    fn eval_type(&self) -> &str {
        "pattern"
    }

    fn stages(&self) -> &HashSet<Stage> {
        &self.stages
    }

    async fn evaluate(&self, ctx: &EvalContext) -> EvalResult {
        let text = ctx.searchable_text();

        for rule in &self.rules {
            for keyword in &rule.keywords {
                let matched = if rule.case_sensitive {
                    text.contains(keyword.as_str())
                } else {
                    text.to_lowercase()
                        .contains(&keyword.to_lowercase())
                };

                if matched {
                    return EvalResult {
                        evaluator: self.name.clone(),
                        action: rule.action,
                        confidence: 1.0,
                        reason: format!("Pattern match: {}", rule.label),
                        redacted: None,
                        metadata: [
                            ("rule".to_string(), serde_json::json!(rule.label)),
                            ("keyword".to_string(), serde_json::json!(keyword)),
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
    use std::collections::HashMap;

    fn make_evaluator(yaml: &str) -> PatternEvaluator {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        PatternEvaluator::new("test-pattern".into(), &config)
    }

    fn msg_ctx(text: &str) -> EvalContext {
        EvalContext {
            stage: Stage::ToolBefore,
            session_id: String::new(),
            channel: String::new(),
            user_id: String::new(),
            timestamp: 0.0,
            message_text: Some(text.into()),
            tool_name: None,
            tool_args: HashMap::new(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_keyword_match_case_insensitive() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "sql danger"
    keywords: ["DROP TABLE", "DELETE FROM"]
    action: detect
"#,
        );
        let ctx = msg_ctx("please drop table users");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Detect);
    }

    #[tokio::test]
    async fn test_keyword_no_match() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "sql danger"
    keywords: ["DROP TABLE"]
    action: block
"#,
        );
        let ctx = msg_ctx("SELECT * FROM users");
        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Allow);
    }

    #[tokio::test]
    async fn test_case_sensitive() {
        let eval = make_evaluator(
            r#"
stages: [tool.before]
rules:
  - label: "exact match"
    keywords: ["SECRET"]
    action: block
    case_sensitive: true
"#,
        );
        let ctx_lower = msg_ctx("this is a secret");
        assert_eq!(eval.evaluate(&ctx_lower).await.action, Action::Allow);

        let ctx_upper = msg_ctx("this is a SECRET");
        assert_eq!(eval.evaluate(&ctx_upper).await.action, Action::Block);
    }
}
