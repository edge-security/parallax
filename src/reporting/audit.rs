use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use tracing::error;

use crate::engine::context::EvalContext;
use crate::engine::result::AggregatedResult;

/// Append-only JSON-lines audit logger.
pub struct AuditLogger {
    writer: Mutex<BufWriter<File>>,
}

impl AuditLogger {
    /// Create a new audit logger, creating parent directories as needed.
    pub fn new(log_file: &str) -> Result<Self, String> {
        let path = PathBuf::from(log_file);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create log directory: {e}"))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("Failed to open audit log: {e}"))?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Write a single evaluation event to the audit log.
    pub fn log(&self, ctx: &EvalContext, result: &AggregatedResult) {
        let entry = serde_json::json!({
            "timestamp": ctx.timestamp,
            "stage": ctx.stage.as_str(),
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            "channel": ctx.channel,
            "tool_name": ctx.tool_name,
            "action": result.action.to_string(),
            "blocked": result.blocked(),
            "reasons": result.reasons(),
            "evaluator_results": result.results.iter().map(|r| {
                serde_json::json!({
                    "evaluator": r.evaluator,
                    "action": r.action.to_string(),
                    "confidence": r.confidence,
                    "reason": r.reason,
                    "elapsed_ms": r.metadata.get("elapsed_ms"),
                })
            }).collect::<Vec<_>>(),
        });

        if let Ok(mut writer) = self.writer.lock() {
            if let Err(e) = writeln!(writer, "{}", serde_json::to_string(&entry).unwrap_or_default())
            {
                error!(error = %e, "Failed to write audit log entry");
            }
            let _ = writer.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::context::Stage;
    use crate::engine::result::{Action, EvalResult};
    use std::collections::HashMap;

    #[test]
    fn test_audit_logger_writes() {
        let dir = std::env::temp_dir().join("parallax-test-audit");
        let log_path = dir.join("test.jsonl");
        let _ = fs::remove_file(&log_path);

        let logger = AuditLogger::new(log_path.to_str().unwrap()).unwrap();
        let ctx = EvalContext {
            stage: Stage::ToolBefore,
            session_id: "s1".into(),
            channel: String::new(),
            user_id: "u1".into(),
            timestamp: 1000.0,
            message_text: None,
            tool_name: Some("exec".into()),
            tool_args: HashMap::new(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        };
        let result = AggregatedResult {
            action: Action::Block,
            results: vec![EvalResult {
                evaluator: "test".into(),
                action: Action::Block,
                confidence: 1.0,
                reason: "blocked".into(),
                redacted: None,
                metadata: HashMap::new(),
            }],
            redacted: None,
        };

        logger.log(&ctx, &result);

        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("\"action\":\"block\""));
        assert!(content.contains("\"session_id\":\"s1\""));

        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_dir(&dir);
    }
}
