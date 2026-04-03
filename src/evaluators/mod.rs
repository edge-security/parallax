pub mod cel_eval;
pub mod pattern_eval;
pub mod regex_eval;
pub mod sigma_eval;
pub mod sql_eval;

use std::collections::HashSet;

use async_trait::async_trait;

use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::EvalResult;

/// Trait that all evaluators must implement.
#[async_trait]
pub trait Evaluator: Send + Sync {
    /// Unique name of this evaluator instance.
    fn name(&self) -> &str;

    /// Evaluator type identifier (e.g., "regex", "pattern").
    fn eval_type(&self) -> &str;

    /// Stages this evaluator runs on.
    fn stages(&self) -> &HashSet<Stage>;

    /// Returns true if this evaluator should run for the given context.
    fn should_run(&self, ctx: &EvalContext) -> bool {
        self.stages().contains(&ctx.stage)
    }

    /// Evaluate the context and return a result. Must not panic.
    async fn evaluate(&self, ctx: &EvalContext) -> EvalResult;
}
