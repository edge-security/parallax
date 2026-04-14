use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;
use reqwest::Client;
use serde_json::Value;
use tracing::{error, warn};

use crate::engine::chain::EvaluatorChain;
use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::AggregatedResult;
use crate::reporting::audit::AuditLogger;
use crate::reporting::webhook::WebhookReporter;

pub struct ProxyState {
    pub chain: Arc<EvaluatorChain>,
    pub audit: Option<Arc<AuditLogger>>,
    pub webhook: Option<Arc<WebhookReporter>>,
    pub client: Client,
    pub upstream_base: String,
}

/// Build the proxy router.
pub fn proxy_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/health", get(proxy_health))
        .route("/anthropic/v1/messages", post(proxy_messages))
        .route("/anthropic/v1/{*path}", any(proxy_passthrough))
        .with_state(state)
}

async fn proxy_health(
    State(state): State<Arc<ProxyState>>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "mode": "proxy",
        "evaluators": state.chain.len(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn evaluate(
    chain: &EvaluatorChain,
    _stage: Stage,
    ctx: EvalContext,
) -> AggregatedResult {
    chain.run(&ctx).await
}

fn extract_user_messages(body: &Value) -> Vec<String> {
    let mut texts = Vec::new();
    let messages = match body.get("messages").and_then(|v| v.as_array()) {
        Some(m) => m,
        None => return texts,
    };

    // Find the last user message
    let last_user = messages.iter().rev().find(|m| {
        m.get("role").and_then(|r| r.as_str()) == Some("user")
    });

    let last_user = match last_user {
        Some(m) => m,
        None => return texts,
    };

    match last_user.get("content") {
        Some(Value::String(s)) => texts.push(s.clone()),
        Some(Value::Array(blocks)) => {
            for block in blocks {
                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                    if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                        texts.push(text.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    texts
}

fn extract_tool_results(body: &Value) -> Vec<Value> {
    let messages = match body.get("messages").and_then(|v| v.as_array()) {
        Some(m) => m,
        None => return vec![],
    };

    let last_user = match messages.iter().rev().find(|m| {
        m.get("role").and_then(|r| r.as_str()) == Some("user")
    }) {
        Some(m) => m,
        None => return vec![],
    };

    match last_user.get("content").and_then(|c| c.as_array()) {
        Some(blocks) => blocks
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result"))
            .cloned()
            .collect(),
        None => vec![],
    }
}

fn _extract_tool_uses(body: &Value) -> Vec<Value> {
    match body.get("content").and_then(|c| c.as_array()) {
        Some(blocks) => blocks
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
            .cloned()
            .collect(),
        None => vec![],
    }
}

fn get_session_id(body: &Value) -> String {
    body.get("metadata")
        .and_then(|m| m.get("session_id"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string()
}

async fn check_messages(chain: &EvaluatorChain, body: &Value) -> Option<AggregatedResult> {
    let texts = extract_user_messages(body);
    if texts.is_empty() {
        return None;
    }
    let combined = texts.join("\n");
    let ctx = EvalContext {
        stage: Stage::MessageBefore,
        session_id: get_session_id(body),
        message_text: Some(combined),
        ..default_ctx()
    };
    let result = evaluate(chain, Stage::MessageBefore, ctx).await;
    if result.blocked() {
        Some(result)
    } else {
        None
    }
}

async fn check_tool_results(chain: &EvaluatorChain, body: &Value) -> Option<AggregatedResult> {
    let tool_results = extract_tool_results(body);
    if tool_results.is_empty() {
        return None;
    }

    // Build tool_use_id -> tool_name map from assistant messages
    let mut tool_id_to_name: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Some(messages) = body.get("messages").and_then(|v| v.as_array()) {
        for msg in messages {
            if msg.get("role").and_then(|r| r.as_str()) != Some("assistant") {
                continue;
            }
            if let Some(blocks) = msg.get("content").and_then(|c| c.as_array()) {
                for block in blocks {
                    if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                        let id = block.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                        let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                        tool_id_to_name.insert(id, name);
                    }
                }
            }
        }
    }

    for tr in &tool_results {
        let content = match tr.get("content") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter_map(|b| {
                    if b.get("type").and_then(|t| t.as_str()) == Some("text") {
                        b.get("text").and_then(|t| t.as_str()).map(String::from)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
            _ => continue,
        };
        if content.is_empty() {
            continue;
        }

        let tool_use_id = tr.get("tool_use_id").and_then(|i| i.as_str()).unwrap_or("");
        let tool_name = tool_id_to_name
            .get(tool_use_id)
            .cloned()
            .unwrap_or_else(|| tool_use_id.to_string());

        let ctx = EvalContext {
            stage: Stage::ToolAfter,
            tool_name: Some(tool_name),
            tool_result: Some(Value::String(content)),
            session_id: get_session_id(body),
            ..default_ctx()
        };
        let result = evaluate(chain, Stage::ToolAfter, ctx).await;
        if result.blocked() {
            return Some(result);
        }
    }
    None
}

async fn check_tool_uses(
    chain: &EvaluatorChain,
    response_body: &Value,
) -> (Vec<Value>, Vec<String>) {
    let content = match response_body.get("content").and_then(|c| c.as_array()) {
        Some(c) => c.clone(),
        None => return (vec![], vec![]),
    };

    let mut kept = Vec::new();
    let mut all_reasons = Vec::new();

    for block in content {
        if block.get("type").and_then(|t| t.as_str()) != Some("tool_use") {
            kept.push(block);
            continue;
        }

        let tool_name = block.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let tool_args = block
            .get("input")
            .cloned()
            .and_then(|v| {
                if let Value::Object(map) = v {
                    Some(map.into_iter().map(|(k, v)| (k, v)).collect())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let ctx = EvalContext {
            stage: Stage::ToolBefore,
            tool_name: Some(tool_name.clone()),
            tool_args,
            ..default_ctx()
        };
        let result = evaluate(chain, Stage::ToolBefore, ctx).await;

        if result.blocked() {
            let reason = if result.reasons().is_empty() {
                "Blocked by security policy".to_string()
            } else {
                result.reasons().join("; ")
            };
            all_reasons.push(format!("Blocked tool '{}': {}", tool_name, reason));
            kept.push(serde_json::json!({
                "type": "text",
                "text": format!("[SECURITY] Tool call '{}' was blocked: {}", tool_name, reason),
            }));
        } else {
            kept.push(block);
        }
    }

    (kept, all_reasons)
}

fn default_ctx() -> EvalContext {
    EvalContext {
        stage: Stage::ToolBefore,
        session_id: String::new(),
        channel: String::new(),
        user_id: String::new(),
        timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
        message_text: None,
        tool_name: None,
        tool_args: std::collections::HashMap::new(),
        tool_result: None,
        model: None,
        params: std::collections::HashMap::new(),
        raw: std::collections::HashMap::new(),
    }
}

fn blocked_response(result: &AggregatedResult, stage: &str, streaming: bool) -> Response {
    let reason = if result.reasons().is_empty() {
        "Blocked by security policy".to_string()
    } else {
        result.reasons().join("; ")
    };
    let block_text = format!("[SECURITY BLOCK -- {}] {}", stage, reason);

    if !streaming {
        let body = serde_json::json!({
            "id": "msg_blocked",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": block_text}],
            "model": "security-proxy",
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        });
        return (StatusCode::OK, axum::Json(body)).into_response();
    }

    // Well-formed SSE stream
    let sse_body = format!(
        "data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_blocked\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"security-proxy\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{{\"input_tokens\":0,\"output_tokens\":0}}}}}}\n\n\
         data: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n\
         data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n\
         data: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n\
         data: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\",\"stop_sequence\":null}},\"usage\":{{\"output_tokens\":0}}}}\n\n\
         data: {{\"type\":\"message_stop\"}}\n\n",
        serde_json::to_string(&block_text).unwrap_or_default()
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .body(Body::from(sse_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn build_upstream_headers(headers: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut upstream = reqwest::header::HeaderMap::new();
    upstream.insert("content-type", "application/json".parse().unwrap());

    let forward_keys = ["x-api-key", "authorization", "anthropic-version", "anthropic-beta"];
    for key in forward_keys {
        if let Some(val) = headers.get(key) {
            if let Ok(parsed) = val.to_str() {
                if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                    if let Ok(header_val) = reqwest::header::HeaderValue::from_str(parsed) {
                        upstream.insert(header_name, header_val);
                    }
                }
            }
        }
    }

    if !upstream.contains_key("anthropic-version") {
        upstream.insert("anthropic-version", "2023-06-01".parse().unwrap());
    }

    upstream
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async fn proxy_messages(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body_json: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let is_streaming = body_json.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

    // Stage 1: Evaluate user messages (message.before)
    if let Some(result) = check_messages(&state.chain, &body_json).await {
        warn!(reasons = ?result.reasons(), "Proxy blocked at message.before");
        return blocked_response(&result, "message.before", is_streaming);
    }

    // Stage 2: Evaluate tool results (tool.after)
    if let Some(result) = check_tool_results(&state.chain, &body_json).await {
        warn!(reasons = ?result.reasons(), "Proxy blocked at tool.after");
        return blocked_response(&result, "tool.after", is_streaming);
    }

    // Forward to Anthropic
    let upstream_headers = build_upstream_headers(&headers);
    let upstream_url = format!("{}/v1/messages", state.upstream_base);

    if is_streaming {
        return proxy_streaming(&state, &body, upstream_headers, &upstream_url).await;
    }

    // Non-streaming
    match state
        .client
        .post(&upstream_url)
        .headers(upstream_headers)
        .body(body.clone())
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(text) => {
                    if status != reqwest::StatusCode::OK {
                        let val: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                        return (StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY), axum::Json(val)).into_response();
                    }

                    let mut response_body: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => return (StatusCode::BAD_GATEWAY, text).into_response(),
                    };

                    // Stage 3: Evaluate tool_use blocks (tool.before)
                    let (kept_content, block_reasons) =
                        check_tool_uses(&state.chain, &response_body).await;
                    if !block_reasons.is_empty() {
                        warn!(reasons = ?block_reasons, "Proxy modified response at tool.before");
                        response_body["content"] = Value::Array(kept_content);
                        let has_tool_use = response_body["content"]
                            .as_array()
                            .map(|arr| {
                                arr.iter().any(|b| {
                                    b.get("type").and_then(|t| t.as_str()) == Some("tool_use")
                                })
                            })
                            .unwrap_or(false);
                        if !has_tool_use
                            && response_body.get("stop_reason").and_then(|s| s.as_str())
                                == Some("tool_use")
                        {
                            response_body["stop_reason"] = Value::String("end_turn".into());
                        }
                    }

                    (StatusCode::OK, axum::Json(response_body)).into_response()
                }
                Err(e) => {
                    error!(error = %e, "Failed to read upstream response");
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to forward to upstream");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn proxy_streaming(
    state: &Arc<ProxyState>,
    body: &str,
    upstream_headers: reqwest::header::HeaderMap,
    upstream_url: &str,
) -> Response {
    let resp = match state
        .client
        .post(upstream_url)
        .headers(upstream_headers)
        .body(body.to_string())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Proxy streaming: failed to connect upstream");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    if resp.status() != reqwest::StatusCode::OK {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let err: Value = serde_json::from_str(&text).unwrap_or(serde_json::json!({"error": text}));
        let sse = format!("data: {}\n\n", serde_json::to_string(&err).unwrap_or_default());
        return Response::builder()
            .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY))
            .header("content-type", "text/event-stream")
            .body(Body::from(sse))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
    }

    let chain = state.chain.clone();
    let mut byte_stream = resp.bytes_stream();

    let stream = async_stream::stream! {
        use futures_util::StreamExt;

        let mut buf = Vec::<u8>::new();
        let mut current_tool_index: Option<String> = None;
        let mut current_tool_name = String::new();
        let mut current_tool_json = String::new();
        let mut buffered_records: Vec<Vec<u8>> = Vec::new();
        let mut any_tool_allowed = false;

        while let Some(chunk) = byte_stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    let err = format!("data: {{\"type\":\"error\",\"error\":{{\"type\":\"proxy_error\",\"message\":\"{}\"}}}}\n\n", e);
                    yield Ok::<_, std::convert::Infallible>(err.into_bytes());
                    break;
                }
            };

            buf.extend_from_slice(&chunk);

            // Process complete SSE records (separated by \n\n)
            while let Some(pos) = find_double_newline(&buf) {
                let record: Vec<u8> = buf.drain(..pos + 2).collect();

                // Parse the data: line
                let parsed_evt = parse_sse_data(&record);
                let event_type = parsed_evt
                    .as_ref()
                    .and_then(|v| v.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                if current_tool_index.is_none() {
                    // Not buffering a tool — check if we should start
                    if event_type == "content_block_start" {
                        let is_tool = parsed_evt
                            .as_ref()
                            .and_then(|v| v.get("content_block"))
                            .and_then(|cb| cb.get("type"))
                            .and_then(|t| t.as_str())
                            == Some("tool_use");

                        if is_tool {
                            current_tool_index = parsed_evt
                                .as_ref()
                                .and_then(|v| v.get("index"))
                                .and_then(|i| i.as_u64())
                                .map(|i| i.to_string());
                            current_tool_name = parsed_evt
                                .as_ref()
                                .and_then(|v| v.get("content_block"))
                                .and_then(|cb| cb.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            current_tool_json.clear();
                            buffered_records = vec![record];
                            continue;
                        }
                    }

                    // Regular record — forward
                    yield Ok(record);
                    continue;
                }

                // Buffering a tool_use block
                buffered_records.push(record);

                if event_type == "content_block_delta" {
                    if let Some(delta) = parsed_evt.as_ref().and_then(|v| v.get("delta")) {
                        if delta.get("type").and_then(|t| t.as_str()) == Some("input_json_delta") {
                            if let Some(json_part) = delta.get("partial_json").and_then(|j| j.as_str()) {
                                current_tool_json.push_str(json_part);
                            }
                        }
                    }
                } else if event_type == "content_block_stop" {
                    // Tool block complete — evaluate
                    let tool_input: Value = serde_json::from_str(&current_tool_json)
                        .unwrap_or(Value::Object(serde_json::Map::new()));
                    let tool_args = match tool_input {
                        Value::Object(map) => map.into_iter().collect(),
                        _ => std::collections::HashMap::new(),
                    };

                    let ctx = EvalContext {
                        stage: Stage::ToolBefore,
                        tool_name: Some(current_tool_name.clone()),
                        tool_args,
                        ..default_ctx()
                    };
                    let result = chain.run(&ctx).await;

                    if result.blocked() {
                        let reason = if result.reasons().is_empty() {
                            "Blocked by security policy".to_string()
                        } else {
                            result.reasons().join("; ")
                        };
                        let block_text = format!("[SECURITY] Tool '{}' blocked: {}", current_tool_name, reason);
                        let idx = current_tool_index.as_deref().unwrap_or("0");
                        let replacement = format!(
                            "data: {{\"type\":\"content_block_start\",\"index\":{idx},\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n\
                             data: {{\"type\":\"content_block_delta\",\"index\":{idx},\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n\
                             data: {{\"type\":\"content_block_stop\",\"index\":{idx}}}\n\n",
                            serde_json::to_string(&block_text).unwrap_or_default()
                        );
                        yield Ok(replacement.into_bytes());
                    } else {
                        any_tool_allowed = true;
                        for rec in &buffered_records {
                            yield Ok(rec.clone());
                        }
                    }

                    current_tool_index = None;
                    current_tool_name.clear();
                    current_tool_json.clear();
                    buffered_records.clear();
                }
            }
        }

        // Flush remaining buffer
        if !buf.is_empty() && current_tool_index.is_none() {
            if !any_tool_allowed {
                let buf_str = String::from_utf8_lossy(&buf);
                let rewritten = buf_str
                    .replace("\"stop_reason\":\"tool_use\"", "\"stop_reason\":\"end_turn\"")
                    .replace("\"stop_reason\": \"tool_use\"", "\"stop_reason\": \"end_turn\"");
                yield Ok(rewritten.into_bytes());
            } else {
                yield Ok(buf);
            }
        }
    };

    use futures_util::StreamExt;
    let body_stream = stream.map(|r: Result<Vec<u8>, std::convert::Infallible>| {
        r.map(axum::body::Bytes::from)
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .body(Body::from_stream(body_stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn find_double_newline(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n")
}

fn parse_sse_data(record: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(record).ok()?;
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            return serde_json::from_str(data).ok();
        }
    }
    None
}

async fn proxy_passthrough(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    axum::extract::Path(path): axum::extract::Path<String>,
    body: String,
) -> Response {
    let mut upstream_headers = reqwest::header::HeaderMap::new();
    for (k, v) in headers.iter() {
        if k.as_str() == "host" {
            continue;
        }
        if let Ok(val) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()) {
                upstream_headers.insert(name, val);
            }
        }
    }

    let url = format!("{}/v1/{}", state.upstream_base, path);
    match state
        .client
        .post(&url)
        .headers(upstream_headers)
        .body(body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let text = resp.text().await.unwrap_or_default();
            let val: Value = serde_json::from_str(&text).unwrap_or(serde_json::json!({"raw": text}));
            (status, axum::Json(val)).into_response()
        }
        Err(e) => {
            error!(error = %e, "Proxy passthrough failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}
