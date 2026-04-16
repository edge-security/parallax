//! HTTP server and reverse proxy entry points.
//!
//! - [`api`] — standalone evaluation API (`POST /evaluate`, `GET /health`).
//! - [`proxy`] — transparent LLM reverse proxy that evaluates requests and
//!   responses in-flight, supporting both streaming and non-streaming modes.

pub mod api;
pub mod proxy;
