use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};

use crate::engine::chain::EvaluatorChain;
use crate::engine::context::{EvalContext, Stage};
use crate::reporting::audit::AuditLogger;
use crate::reporting::webhook::WebhookReporter;

/// Shared application state for the evaluation API server.
pub struct AppState {
    pub chain: EvaluatorChain,
    pub audit: Option<AuditLogger>,
    pub webhook: Option<WebhookReporter>,
    /// `"server"` or `"proxy"` — included in `/health` responses.
    pub mode: String,
}

/// POST /evaluate request body.
#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub stage: Stage,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub timestamp: Option<f64>,
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

/// POST /evaluate response body.
#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub action: String,
    pub blocked: bool,
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<String>,
    pub results: Vec<serde_json::Value>,
    pub elapsed_ms: f64,
}

/// GET /health response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub mode: String,
    pub evaluators: usize,
    pub version: String,
}

/// Build the axum router with all routes.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/evaluate", post(evaluate))
        .route("/health", get(health))
        .with_state(state)
}

async fn evaluate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvaluateRequest>,
) -> Json<EvaluateResponse> {
    let timestamp = req.timestamp.unwrap_or_else(|| {
        chrono::Utc::now().timestamp_millis() as f64 / 1000.0
    });

    let ctx = EvalContext {
        stage: req.stage,
        session_id: req.session_id,
        channel: req.channel,
        user_id: req.user_id,
        timestamp,
        message_text: req.message_text,
        tool_name: req.tool_name,
        tool_args: req.tool_args,
        tool_result: req.tool_result,
        model: req.model,
        params: req.params,
        raw: req.raw,
    };

    let t0 = Instant::now();
    let result = state.chain.run(&ctx).await;
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // Side effects: audit log and webhook
    if let Some(ref audit) = state.audit {
        audit.log(&ctx, &result);
    }
    if let Some(ref webhook) = state.webhook {
        if webhook.should_send(&result) {
            webhook.send(&ctx, &result).await;
        }
    }

    let response = EvaluateResponse {
        action: result.action.to_string(),
        blocked: result.blocked(),
        reasons: result.reasons(),
        redacted: result.redacted.clone(),
        results: result
            .results
            .iter()
            .map(|r| serde_json::to_value(r).unwrap_or_default())
            .collect(),
        elapsed_ms: (elapsed_ms * 10.0).round() / 10.0,
    };

    Json(response)
}

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        mode: state.mode.clone(),
        evaluators: state.chain.len(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Error handler for malformed JSON requests.
pub async fn handle_rejection(
    err: axum::extract::rejection::JsonRejection,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": err.to_string(),
        })),
    )
}
