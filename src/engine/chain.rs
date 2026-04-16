use std::collections::HashMap;
use std::time::Instant;

use tracing::{error, info};

use crate::engine::context::EvalContext;
use crate::engine::result::{aggregate, Action, AggregatedResult, EvalResult};
use crate::evaluators::Evaluator;

/// Cost ordering for evaluator types — cheaper evaluators run first.
fn eval_type_cost(eval_type: &str) -> u32 {
    match eval_type {
        "regex" => 0,
        "pattern" => 1,
        "sigma" => 2,
        "cel" => 3,
        "sql" => 4,
        "ml" => 5,
        "llm" => 6,
        _ => 99,
    }
}

/// Ordered chain of evaluators.
///
/// Evaluators run in ascending cost order (regex before LLM) and
/// short-circuit on `Block` — remaining evaluators are skipped.
/// Panicking evaluators are caught and converted to `Detect` results.
pub struct EvaluatorChain {
    evaluators: Vec<Box<dyn Evaluator>>,
}

impl EvaluatorChain {
    pub fn new() -> Self {
        Self {
            evaluators: Vec::new(),
        }
    }

    pub fn add(&mut self, evaluator: Box<dyn Evaluator>) {
        self.evaluators.push(evaluator);
        self.sort();
    }

    pub fn len(&self) -> usize {
        self.evaluators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evaluators.is_empty()
    }

    fn sort(&mut self) {
        self.evaluators
            .sort_by_key(|e| eval_type_cost(e.eval_type()));
    }

    /// Run all applicable evaluators against the context.
    ///
    /// - Evaluators execute in cost order (cheapest first).
    /// - Each evaluator is timed; elapsed_ms is stored in result metadata.
    /// - On block, remaining evaluators are skipped (short-circuit).
    /// - Exceptions are caught and converted to detect results.
    pub async fn run(&self, ctx: &EvalContext) -> AggregatedResult {
        let mut results: Vec<EvalResult> = Vec::new();

        for evaluator in &self.evaluators {
            if !evaluator.should_run(ctx) {
                continue;
            }

            let t0 = Instant::now();
            let mut result = match std::panic::AssertUnwindSafe(evaluator.evaluate(ctx))
                .catch_unwind()
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    error!(evaluator = evaluator.name(), "Evaluator panicked");
                    EvalResult {
                        evaluator: evaluator.name().to_string(),
                        action: Action::Detect,
                        confidence: 0.0,
                        reason: format!(
                            "Evaluator {} failed with an internal error",
                            evaluator.name()
                        ),
                        redacted: None,
                        metadata: HashMap::new(),
                    }
                }
            };
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            result
                .metadata
                .insert("elapsed_ms".into(), serde_json::json!(elapsed_ms));

            info!(
                evaluator = evaluator.name(),
                action = %result.action,
                elapsed_ms = format!("{elapsed_ms:.1}"),
                "Evaluator completed"
            );

            let should_break = result.action == Action::Block;
            results.push(result);

            if should_break {
                break;
            }
        }

        aggregate(results)
    }
}

impl Default for EvaluatorChain {
    fn default() -> Self {
        Self::new()
    }
}

// catch_unwind requires futures to be UnwindSafe
use std::future::Future;
use std::panic::UnwindSafe;
use std::pin::Pin;
use std::task::{Context, Poll};

trait CatchUnwind: Future + Sized {
    fn catch_unwind(self) -> CatchUnwindFuture<Self>;
}

impl<F: Future> CatchUnwind for std::panic::AssertUnwindSafe<F> {
    fn catch_unwind(self) -> CatchUnwindFuture<Self> {
        CatchUnwindFuture { inner: self }
    }
}

struct CatchUnwindFuture<F> {
    inner: F,
}

impl<F: Future + UnwindSafe> Future for CatchUnwindFuture<F> {
    type Output = Result<F::Output, Box<dyn std::any::Any + Send>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Safety: we are not moving the inner future
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(Poll::Ready(val)) => Poll::Ready(Ok(val)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::context::Stage;
    use async_trait::async_trait;
    use std::collections::HashSet;

    struct MockEvaluator {
        name: String,
        eval_type: String,
        action: Action,
        stages: HashSet<Stage>,
    }

    #[async_trait]
    impl Evaluator for MockEvaluator {
        fn name(&self) -> &str {
            &self.name
        }
        fn eval_type(&self) -> &str {
            &self.eval_type
        }
        fn stages(&self) -> &HashSet<Stage> {
            &self.stages
        }
        fn should_run(&self, ctx: &EvalContext) -> bool {
            self.stages.contains(&ctx.stage)
        }
        async fn evaluate(&self, _ctx: &EvalContext) -> EvalResult {
            EvalResult {
                evaluator: self.name.clone(),
                action: self.action,
                confidence: 1.0,
                reason: format!("{} triggered", self.name),
                redacted: None,
                metadata: HashMap::new(),
            }
        }
    }

    fn mock(name: &str, eval_type: &str, action: Action) -> Box<dyn Evaluator> {
        Box::new(MockEvaluator {
            name: name.into(),
            eval_type: eval_type.into(),
            action,
            stages: [Stage::ToolBefore].into_iter().collect(),
        })
    }

    fn test_ctx() -> EvalContext {
        EvalContext {
            stage: Stage::ToolBefore,
            session_id: String::new(),
            channel: String::new(),
            user_id: String::new(),
            timestamp: 0.0,
            message_text: None,
            tool_name: Some("test".into()),
            tool_args: HashMap::new(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_chain_cost_order() {
        let mut chain = EvaluatorChain::new();
        chain.add(mock("llm-eval", "llm", Action::Allow));
        chain.add(mock("regex-eval", "regex", Action::Allow));
        chain.add(mock("pattern-eval", "pattern", Action::Allow));

        // After sorting, regex should be first
        assert_eq!(chain.evaluators[0].eval_type(), "regex");
        assert_eq!(chain.evaluators[1].eval_type(), "pattern");
        assert_eq!(chain.evaluators[2].eval_type(), "llm");
    }

    #[tokio::test]
    async fn test_chain_short_circuit_on_block() {
        let mut chain = EvaluatorChain::new();
        chain.add(mock("blocker", "regex", Action::Block));
        chain.add(mock("detector", "pattern", Action::Detect));

        let result = chain.run(&test_ctx()).await;
        assert!(result.blocked());
        // Only the blocker should have run
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].evaluator, "blocker");
    }

    #[tokio::test]
    async fn test_chain_runs_all_when_no_block() {
        let mut chain = EvaluatorChain::new();
        chain.add(mock("a", "regex", Action::Detect));
        chain.add(mock("b", "pattern", Action::Allow));

        let result = chain.run(&test_ctx()).await;
        assert_eq!(result.action, Action::Detect);
        assert_eq!(result.results.len(), 2);
    }
}
