//! Observability sinks: audit logging and webhook notifications.
//!
//! Both reporters are optional and configured via [`crate::config::schema::ReportingConfig`].

pub mod audit;
pub mod webhook;
