//! Core evaluation engine: context normalization, chain execution, and result aggregation.
//!
//! The engine receives an [`context::EvalContext`] from the server or proxy layer,
//! runs it through the [`chain::EvaluatorChain`], and produces an
//! [`result::AggregatedResult`] with the final enforcement action.

pub mod chain;
pub mod context;
pub mod result;
