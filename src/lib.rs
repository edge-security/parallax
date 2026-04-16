//! # Parallax
//!
//! Runtime security engine for AI agents — blocks prompt injection, data
//! exfiltration, and dangerous tool calls across any framework and LLM.
//!
//! Parallax sits between your agent and the outside world, evaluating every
//! event (messages, tool calls, tool results) against a configurable chain
//! of security evaluators. Each evaluator returns an [`engine::result::Action`]:
//! **allow**, **detect**, **redact**, or **block**.
//!
//! ## Architecture
//!
//! ```text
//! Agent ──▶ EvalContext ──▶ EvaluatorChain ──▶ AggregatedResult
//!                            ├─ RegexEvaluator
//!                            ├─ PatternEvaluator
//!                            ├─ SigmaEvaluator
//!                            ├─ CELEvaluator
//!                            └─ SQLEvaluator
//! ```
//!
//! ## Quick start
//!
//! ```no_run
//! use parallax::config::loader::{load_config, build_chain};
//! use parallax::engine::context::{EvalContext, Stage};
//!
//! # #[tokio::main] async fn main() {
//! let config = load_config(Some("config.yaml")).unwrap();
//! let chain = build_chain(&config);
//!
//! // Build a context from an incoming agent event
//! let ctx = EvalContext {
//!     stage: Stage::ToolBefore,
//!     tool_name: Some("exec".into()),
//!     // ...other fields...
//!     # session_id: String::new(), channel: String::new(), user_id: String::new(),
//!     # timestamp: 0.0, message_text: None, tool_args: Default::default(),
//!     # tool_result: None, model: None, params: Default::default(), raw: Default::default(),
//! };
//!
//! let result = chain.run(&ctx).await;
//! if result.blocked() {
//!     eprintln!("Blocked: {:?}", result.reasons());
//! }
//! # }
//! ```
//!
//! ## Deployment modes
//!
//! - **Server mode** — standalone HTTP API that your agent calls via `POST /evaluate`.
//! - **Proxy mode** — transparent reverse proxy that intercepts LLM API traffic
//!   and evaluates requests/responses in-flight.

pub mod config;
pub mod engine;
pub mod evaluators;
pub mod integrations;
pub mod reporting;
pub mod server;

pub use engine::chain::EvaluatorChain;
pub use engine::context::{EvalContext, Stage};
pub use engine::result::{Action, AggregatedResult, EvalResult};
pub use evaluators::Evaluator;
