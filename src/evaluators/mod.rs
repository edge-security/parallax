//! Security evaluators — pluggable detection backends.
//!
//! Every evaluator implements the [`Evaluator`] trait and is driven by YAML
//! configuration. Available types:
//!
//! | Type      | Module            | Description                              |
//! |-----------|-------------------|------------------------------------------|
//! | `regex`   | [`regex_eval`]    | Compiled regex patterns with negation    |
//! | `pattern` | [`pattern_eval`]  | Fast keyword / substring matching        |
//! | `sigma`   | [`sigma_eval`]    | Structured Sigma-style YAML rules        |
//! | `cel`     | [`cel_eval`]      | CEL-like expression policies             |
//! | `sql`     | [`sql_eval`]      | Stateful SQLite queries (rate limiting)  |

pub mod cel_eval;
pub mod pattern_eval;
pub mod regex_eval;
pub mod sigma_eval;
pub mod sql_eval;

use std::collections::HashSet;

use async_trait::async_trait;

use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::EvalResult;

/// Trait that all security evaluators must implement.
///
/// Implementors are constructed from YAML config and registered into an
/// [`crate::engine::chain::EvaluatorChain`]. The chain calls [`Evaluator::evaluate`]
/// for every context whose stage matches.
#[async_trait]
pub trait Evaluator: Send + Sync {
    /// Unique name of this evaluator instance (from config).
    fn name(&self) -> &str;

    /// Evaluator type identifier (e.g. `"regex"`, `"sigma"`).
    fn eval_type(&self) -> &str;

    /// Set of stages this evaluator subscribes to.
    fn stages(&self) -> &HashSet<Stage>;

    /// Returns `true` if this evaluator should run for the given context.
    /// Default: checks if the context's stage is in [`Self::stages()`].
    fn should_run(&self, ctx: &EvalContext) -> bool {
        self.stages().contains(&ctx.stage)
    }

    /// Evaluate the context and return a result.
    ///
    /// Implementations must not panic — the chain catches panics but converts
    /// them to `Detect` results with zero confidence.
    async fn evaluate(&self, ctx: &EvalContext) -> EvalResult;
}
