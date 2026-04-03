use std::collections::HashSet;
use std::time::Duration;

use reqwest::Client;
use tracing::{error, warn};

use crate::engine::context::EvalContext;
use crate::engine::result::AggregatedResult;

/// Async webhook reporter — POSTs evaluation events to an external endpoint.
pub struct WebhookReporter {
    url: String,
    pub events: HashSet<String>,
    client: Client,
}

impl WebhookReporter {
    pub fn new(url: String, events: Vec<String>) -> Self {
        let events: HashSet<String> = if events.is_empty() {
            ["block".into(), "redact".into()].into_iter().collect()
        } else {
            events.into_iter().collect()
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            url,
            events,
            client,
        }
    }

    /// Returns true if this result's action is in the configured event set.
    pub fn should_send(&self, result: &AggregatedResult) -> bool {
        self.events.contains(&result.action.to_string())
    }

    /// POST the evaluation result to the webhook URL.
    pub async fn send(&self, ctx: &EvalContext, result: &AggregatedResult) {
        let payload = serde_json::json!({
            "timestamp": ctx.timestamp,
            "stage": ctx.stage.as_str(),
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            "channel": ctx.channel,
            "tool_name": ctx.tool_name,
            "action": result.action.to_string(),
            "reasons": result.reasons(),
            "evaluator_count": result.results.len(),
        });

        match self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_client_error() || resp.status().is_server_error() => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(
                    status = %status,
                    body = &body[..body.len().min(200)],
                    "Webhook returned error"
                );
            }
            Err(e) => {
                error!(url = %self.url, error = %e, "Failed to send webhook");
            }
            _ => {}
        }
    }
}
