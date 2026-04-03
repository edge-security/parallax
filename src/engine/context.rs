use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Evaluation stage — when in the agent lifecycle this event occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Stage {
    #[serde(rename = "message.before")]
    MessageBefore,
    #[serde(rename = "params.before")]
    ParamsBefore,
    #[serde(rename = "tool.before")]
    ToolBefore,
    #[serde(rename = "tool.after")]
    ToolAfter,
}

impl Stage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::MessageBefore => "message.before",
            Stage::ParamsBefore => "params.before",
            Stage::ToolBefore => "tool.before",
            Stage::ToolAfter => "tool.after",
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalized event context passed to every evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalContext {
    pub stage: Stage,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default = "now")]
    pub timestamp: f64,
    #[serde(default)]
    pub message_text: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_args: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub tool_result: Option<serde_json::Value>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub raw: HashMap<String, serde_json::Value>,
}

fn now() -> f64 {
    chrono::Utc::now().timestamp_millis() as f64 / 1000.0
}

impl EvalContext {
    /// Return a flattened dict of fields for pattern matching (Sigma, CEL, field-targeted regex).
    pub fn flat_fields(&self) -> HashMap<String, String> {
        let mut flat = HashMap::new();
        flat.insert("stage".into(), self.stage.as_str().to_string());
        flat.insert("session_id".into(), self.session_id.clone());
        flat.insert("channel".into(), self.channel.clone());
        flat.insert("user_id".into(), self.user_id.clone());
        flat.insert("timestamp".into(), self.timestamp.to_string());

        if let Some(ref text) = self.message_text {
            flat.insert("message_text".into(), text.clone());
        }
        if let Some(ref name) = self.tool_name {
            flat.insert("tool_name".into(), name.clone());
            for (k, v) in &self.tool_args {
                let val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                flat.insert(format!("tool_args.{k}"), val);
            }
        }
        if let Some(ref result) = self.tool_result {
            let val = match result {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            flat.insert("tool_result".into(), val);
        }
        if let Some(ref model) = self.model {
            flat.insert("model".into(), model.clone());
        }
        flat
    }

    /// Concatenate all text-bearing fields into a single searchable string.
    pub fn searchable_text(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref text) = self.message_text {
            parts.push(text.as_str());
        }
        for v in self.tool_args.values() {
            if let serde_json::Value::String(s) = v {
                parts.push(s.as_str());
            }
        }
        if let Some(serde_json::Value::String(ref s)) = self.tool_result {
            parts.push(s.as_str());
        }
        parts.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_serde_roundtrip() {
        let json = serde_json::to_string(&Stage::ToolBefore).unwrap();
        assert_eq!(json, "\"tool.before\"");
        let back: Stage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Stage::ToolBefore);
    }

    #[test]
    fn test_flat_fields_includes_tool_args() {
        let ctx = EvalContext {
            stage: Stage::ToolBefore,
            session_id: "s1".into(),
            channel: String::new(),
            user_id: "admin".into(),
            timestamp: 1000.0,
            message_text: None,
            tool_name: Some("exec".into()),
            tool_args: [("command".to_string(), serde_json::json!("ls -la"))]
                .into_iter()
                .collect(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        };
        let flat = ctx.flat_fields();
        assert_eq!(flat.get("tool_name").unwrap(), "exec");
        assert_eq!(flat.get("tool_args.command").unwrap(), "ls -la");
    }

    #[test]
    fn test_searchable_text() {
        let ctx = EvalContext {
            stage: Stage::ToolBefore,
            session_id: String::new(),
            channel: String::new(),
            user_id: String::new(),
            timestamp: 0.0,
            message_text: Some("hello".into()),
            tool_name: Some("exec".into()),
            tool_args: [("cmd".to_string(), serde_json::json!("world"))]
                .into_iter()
                .collect(),
            tool_result: Some(serde_json::json!("done")),
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        };
        let text = ctx.searchable_text();
        assert!(text.contains("hello"));
        assert!(text.contains("world"));
        assert!(text.contains("done"));
    }
}
