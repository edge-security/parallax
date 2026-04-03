use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Enforcement action to take on an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
    Detect,
    Redact,
}

impl Action {
    /// Priority for aggregation: higher wins.
    pub fn priority(self) -> u8 {
        match self {
            Action::Allow => 0,
            Action::Detect => 1,
            Action::Redact => 2,
            Action::Block => 3,
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Action::Allow => "allow",
            Action::Block => "block",
            Action::Detect => "detect",
            Action::Redact => "redact",
        };
        f.write_str(s)
    }
}

/// Result from a single evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub evaluator: String,
    pub action: Action,
    pub confidence: f64,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl EvalResult {
    pub fn allow(evaluator: &str) -> Self {
        Self {
            evaluator: evaluator.to_string(),
            action: Action::Allow,
            confidence: 1.0,
            reason: String::new(),
            redacted: None,
            metadata: HashMap::new(),
        }
    }
}

/// Aggregated result from the full evaluator chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedResult {
    pub action: Action,
    pub results: Vec<EvalResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<String>,
}

impl AggregatedResult {
    /// True if the final action is block.
    pub fn blocked(&self) -> bool {
        self.action == Action::Block
    }

    /// Collect non-empty reasons from evaluators that triggered (non-allow).
    pub fn reasons(&self) -> Vec<String> {
        self.results
            .iter()
            .filter(|r| r.action != Action::Allow && !r.reason.is_empty())
            .map(|r| r.reason.clone())
            .collect()
    }
}

impl Default for AggregatedResult {
    fn default() -> Self {
        Self {
            action: Action::Allow,
            results: Vec::new(),
            redacted: None,
        }
    }
}

/// Aggregate evaluator results by priority: Block > Redact > Detect > Allow.
pub fn aggregate(results: Vec<EvalResult>) -> AggregatedResult {
    if results.is_empty() {
        return AggregatedResult::default();
    }

    let mut final_action = Action::Allow;
    let mut final_redacted: Option<String> = None;

    for r in &results {
        if r.action.priority() > final_action.priority() {
            final_action = r.action;
        }
        if r.action == Action::Redact {
            if let Some(ref text) = r.redacted {
                final_redacted = Some(text.clone());
            }
        }
    }

    AggregatedResult {
        action: final_action,
        results,
        redacted: final_redacted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_priority() {
        assert!(Action::Block.priority() > Action::Redact.priority());
        assert!(Action::Redact.priority() > Action::Detect.priority());
        assert!(Action::Detect.priority() > Action::Allow.priority());
    }

    #[test]
    fn test_aggregate_empty() {
        let agg = aggregate(vec![]);
        assert_eq!(agg.action, Action::Allow);
        assert!(agg.results.is_empty());
    }

    #[test]
    fn test_aggregate_block_wins() {
        let results = vec![
            EvalResult {
                evaluator: "a".into(),
                action: Action::Detect,
                confidence: 1.0,
                reason: "found something".into(),
                redacted: None,
                metadata: HashMap::new(),
            },
            EvalResult {
                evaluator: "b".into(),
                action: Action::Block,
                confidence: 1.0,
                reason: "blocked".into(),
                redacted: None,
                metadata: HashMap::new(),
            },
        ];
        let agg = aggregate(results);
        assert_eq!(agg.action, Action::Block);
        assert!(agg.blocked());
        assert_eq!(agg.reasons().len(), 2);
    }

    #[test]
    fn test_aggregate_redact_preserves_text() {
        let results = vec![EvalResult {
            evaluator: "r".into(),
            action: Action::Redact,
            confidence: 1.0,
            reason: "secret".into(),
            redacted: Some("[REDACTED]".into()),
            metadata: HashMap::new(),
        }];
        let agg = aggregate(results);
        assert_eq!(agg.action, Action::Redact);
        assert_eq!(agg.redacted.unwrap(), "[REDACTED]");
    }
}
