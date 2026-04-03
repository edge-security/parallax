use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use rusqlite::{params, Connection};
use tracing::warn;

use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::{Action, EvalResult};
use crate::evaluators::Evaluator;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    stage TEXT NOT NULL,
    session_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    user_id TEXT NOT NULL,
    tool_name TEXT,
    tool_args TEXT,
    tool_result TEXT,
    message_text TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name);
";

const MAX_EVENT_AGE_SECONDS: f64 = 3600.0;
const MAX_EVENTS: i64 = 10_000;

struct SQLRule {
    label: String,
    query: String,
    condition: String,
    action: Action,
    reason: String,
}

/// SQL evaluator — stateful detection using in-memory SQLite.
///
/// Stores recent events and runs SQL queries to detect temporal/aggregate
/// patterns like rate limiting and burst detection.
pub struct SQLEvaluator {
    name: String,
    stages: HashSet<Stage>,
    rules: Vec<SQLRule>,
    db: Mutex<Connection>,
    event_count: Mutex<u64>,
}

impl SQLEvaluator {
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

        let db = Connection::open_in_memory().expect("Failed to create in-memory SQLite database");
        db.execute_batch(SCHEMA)
            .expect("Failed to create events table");

        let mut rules = Vec::new();
        if let Some(seq) = map
            .get(serde_yaml::Value::String("rules".into()))
            .and_then(|v| v.as_sequence())
        {
            for item in seq {
                let m = match item.as_mapping() {
                    Some(m) => m,
                    None => continue,
                };
                let label = m
                    .get(serde_yaml::Value::String("label".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed")
                    .to_string();
                let query = match m
                    .get(serde_yaml::Value::String("query".into()))
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        warn!(label, "SQL rule missing 'query', skipping");
                        continue;
                    }
                };
                let condition = match m
                    .get(serde_yaml::Value::String("condition".into()))
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        warn!(label, "SQL rule missing 'condition', skipping");
                        continue;
                    }
                };
                let action_str = m
                    .get(serde_yaml::Value::String("action".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("block");
                let action = match action_str {
                    "block" => Action::Block,
                    "detect" => Action::Detect,
                    "redact" => Action::Redact,
                    "allow" => Action::Allow,
                    _ => Action::Block,
                };
                let reason = m
                    .get(serde_yaml::Value::String("reason".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                rules.push(SQLRule {
                    label,
                    query,
                    condition,
                    action,
                    reason,
                });
            }
        }

        Self {
            name,
            stages,
            rules,
            db: Mutex::new(db),
            event_count: Mutex::new(0),
        }
    }

    fn record_event(&self, ctx: &EvalContext) {
        let db = self.db.lock().unwrap();
        let tool_args = if ctx.tool_args.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&ctx.tool_args).unwrap_or_default())
        };
        let tool_result = ctx.tool_result.as_ref().map(|v| {
            let s = v.to_string();
            if s.len() > 4096 { s[..4096].to_string() } else { s }
        });

        let _ = db.execute(
            "INSERT INTO events (timestamp, stage, session_id, channel, user_id, tool_name, tool_args, tool_result, message_text)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                ctx.timestamp,
                ctx.stage.as_str(),
                ctx.session_id,
                ctx.channel,
                ctx.user_id,
                ctx.tool_name,
                tool_args,
                tool_result,
                ctx.message_text,
            ],
        );

        let mut count = self.event_count.lock().unwrap();
        *count += 1;
        if *count % 100 == 0 {
            self.purge_locked(&db);
        }
    }

    fn purge_locked(&self, db: &Connection) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let cutoff = now - MAX_EVENT_AGE_SECONDS;
        let _ = db.execute("DELETE FROM events WHERE timestamp < ?1", params![cutoff]);

        if let Ok(count) = db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
        {
            if count > MAX_EVENTS {
                let _ = db.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY timestamp ASC LIMIT ?1)",
                    params![count - MAX_EVENTS],
                );
            }
        }
    }

    fn check_condition(row: &HashMap<String, f64>, condition: &str) -> bool {
        let parts: Vec<&str> = condition.split_whitespace().collect();
        if parts.len() != 3 {
            return false;
        }
        let field = parts[0];
        let op = parts[1];
        let expected: f64 = match parts[2].parse() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let actual = *row.get(field).unwrap_or(&0.0);

        match op {
            ">" => actual > expected,
            ">=" => actual >= expected,
            "<" => actual < expected,
            "<=" => actual <= expected,
            "==" | "=" => actual == expected,
            "!=" => actual != expected,
            _ => false,
        }
    }
}

#[async_trait]
impl Evaluator for SQLEvaluator {
    fn name(&self) -> &str {
        &self.name
    }
    fn eval_type(&self) -> &str {
        "sql"
    }
    fn stages(&self) -> &HashSet<Stage> {
        &self.stages
    }

    async fn evaluate(&self, ctx: &EvalContext) -> EvalResult {
        self.record_event(ctx);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let db = self.db.lock().unwrap();

        for rule in &self.rules {
            match db.prepare(&rule.query) {
                Ok(mut stmt) => {
                    // Bind named parameters
                    let param_names = [
                        (":session_id", ctx.session_id.as_str()),
                        (":user_id", ctx.user_id.as_str()),
                        (":channel", ctx.channel.as_str()),
                        (":tool_name", ctx.tool_name.as_deref().unwrap_or("")),
                    ];

                    // Build parameter slice for named params
                    let mut bound_params: Vec<(&str, &dyn rusqlite::types::ToSql)> = Vec::new();
                    let now_val = now;
                    for (name, val) in &param_names {
                        if rule.query.contains(name) {
                            bound_params.push((name, val));
                        }
                    }
                    if rule.query.contains(":now") {
                        bound_params.push((":now", &now_val));
                    }

                    let result = stmt.query_row(
                        bound_params.as_slice(),
                        |row| {
                            let col_count = row.as_ref().column_count();
                            let mut map = HashMap::new();
                            for i in 0..col_count {
                                let name = row.as_ref().column_name(i).unwrap_or("").to_string();
                                let val: f64 = row.get(i).unwrap_or(0.0);
                                map.insert(name, val);
                            }
                            Ok(map)
                        },
                    );

                    match result {
                        Ok(row_map) => {
                            if Self::check_condition(&row_map, &rule.condition) {
                                let reason = if rule.reason.is_empty() {
                                    format!("SQL rule triggered: {}", rule.label)
                                } else {
                                    rule.reason.clone()
                                };
                                return EvalResult {
                                    evaluator: self.name.clone(),
                                    action: rule.action,
                                    confidence: 1.0,
                                    reason,
                                    redacted: None,
                                    metadata: [
                                        ("rule".to_string(), serde_json::json!(rule.label)),
                                    ]
                                    .into_iter()
                                    .collect(),
                                };
                            }
                        }
                        Err(e) => {
                            warn!(rule = %rule.label, error = %e, "SQL query failed");
                        }
                    }
                }
                Err(e) => {
                    warn!(rule = %rule.label, error = %e, "Failed to prepare SQL query");
                }
            }
        }

        EvalResult::allow(&self.name)
    }
}

// SQLEvaluator uses Mutex internally, so it's safe to send across threads
// even though rusqlite::Connection is not Send.
unsafe impl Send for SQLEvaluator {}
unsafe impl Sync for SQLEvaluator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_condition() {
        let row: HashMap<String, f64> = [("cnt".to_string(), 15.0)].into_iter().collect();
        assert!(SQLEvaluator::check_condition(&row, "cnt > 10"));
        assert!(!SQLEvaluator::check_condition(&row, "cnt > 20"));
        assert!(SQLEvaluator::check_condition(&row, "cnt >= 15"));
        assert!(SQLEvaluator::check_condition(&row, "cnt == 15"));
        assert!(SQLEvaluator::check_condition(&row, "cnt != 10"));
    }

    #[tokio::test]
    async fn test_sql_evaluator_rate_limit() {
        let config: serde_yaml::Value = serde_yaml::from_str(r#"
stages: [tool.before]
rules:
  - label: burst-detect
    query: "SELECT COUNT(*) as cnt FROM events WHERE session_id = :session_id"
    condition: "cnt > 3"
    action: block
    reason: Too many events
"#).unwrap();

        let eval = SQLEvaluator::new("test-sql".into(), &config);

        let make_ctx = || EvalContext {
            stage: Stage::ToolBefore,
            session_id: "sess1".into(),
            channel: String::new(),
            user_id: String::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            message_text: None,
            tool_name: Some("exec".into()),
            tool_args: HashMap::new(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        };

        // First 3 events should be allowed (count is 1, 2, 3 after recording)
        for _ in 0..3 {
            let result = eval.evaluate(&make_ctx()).await;
            assert_eq!(result.action, Action::Allow);
        }

        // 4th event should be blocked (count is now 4 > 3)
        let result = eval.evaluate(&make_ctx()).await;
        assert_eq!(result.action, Action::Block);
    }
}
