use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use regex::Regex;
use tracing::warn;

use crate::engine::context::{EvalContext, Stage};
use crate::engine::result::{Action, EvalResult};
use crate::evaluators::Evaluator;

// ---------------------------------------------------------------------------
// Lightweight CEL-like expression parser and evaluator
// ---------------------------------------------------------------------------

/// AST node for a CEL-like expression.
#[derive(Debug, Clone)]
enum Expr {
    BoolLit(bool),
    StringLit(String),
    Ident(String),
    BinOp {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    MethodCall {
        object: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    Not(Box<Expr>),
    Group(Box<Expr>),
}

#[derive(Debug, Clone, Copy)]
enum BinOp {
    Eq,
    Ne,
    And,
    Or,
}

/// Tokenizer for CEL-like expressions.
#[derive(Debug, Clone)]
enum Token {
    Ident(String),
    StringLit(String),
    True,
    False,
    Eq,        // ==
    Ne,        // !=
    And,       // &&
    Or,        // ||
    Not,       // !
    Dot,       // .
    LParen,    // (
    RParen,    // )
    Comma,     // ,
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '(' => { tokens.push(Token::LParen); i += 1; }
            ')' => { tokens.push(Token::RParen); i += 1; }
            ',' => { tokens.push(Token::Comma); i += 1; }
            '.' => { tokens.push(Token::Dot); i += 1; }
            '!' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::Ne); i += 2;
            }
            '!' => { tokens.push(Token::Not); i += 1; }
            '=' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::Eq); i += 2;
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                tokens.push(Token::And); i += 2;
            }
            '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                tokens.push(Token::Or); i += 2;
            }
            '"' | '\'' => {
                let quote = chars[i];
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        match chars[i] {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            '\\' => s.push('\\'),
                            c => { s.push('\\'); s.push(c); }
                        }
                    } else {
                        s.push(chars[i]);
                    }
                    i += 1;
                }
                i += 1; // skip closing quote
                tokens.push(Token::StringLit(s));
            }
            c if c.is_alphanumeric() || c == '_' => {
                let mut s = String::new();
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    s.push(chars[i]);
                    i += 1;
                }
                match s.as_str() {
                    "true" => tokens.push(Token::True),
                    "false" => tokens.push(Token::False),
                    _ => tokens.push(Token::Ident(s)),
                }
            }
            _ => i += 1, // skip unknown
        }
    }

    tokens
}

/// Recursive descent parser for CEL-like expressions.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let tok = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        tok
    }

    fn parse_expr(&mut self) -> Option<Expr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Option<Expr> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::BinOp {
                op: BinOp::Or,
                lhs: Box::new(left),
                rhs: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<Expr> {
        let mut left = self.parse_comparison()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.advance();
            let right = self.parse_comparison()?;
            left = Expr::BinOp {
                op: BinOp::And,
                lhs: Box::new(left),
                rhs: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_comparison(&mut self) -> Option<Expr> {
        let mut left = self.parse_unary()?;

        // Handle method calls: expr.method(args)
        while matches!(self.peek(), Some(Token::Dot)) {
            self.advance(); // consume dot
            let method = match self.advance()? {
                Token::Ident(s) => s,
                _ => return None,
            };
            // Expect '('
            match self.peek() {
                Some(Token::LParen) => {
                    self.advance();
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Some(Token::RParen)) {
                        args.push(self.parse_expr()?);
                        while matches!(self.peek(), Some(Token::Comma)) {
                            self.advance();
                            args.push(self.parse_expr()?);
                        }
                    }
                    self.advance(); // consume ')'
                    left = Expr::MethodCall {
                        object: Box::new(left),
                        method,
                        args,
                    };
                }
                _ => return None,
            }
        }

        match self.peek() {
            Some(Token::Eq) => {
                self.advance();
                let right = self.parse_unary()?;
                Some(Expr::BinOp {
                    op: BinOp::Eq,
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                })
            }
            Some(Token::Ne) => {
                self.advance();
                let right = self.parse_unary()?;
                Some(Expr::BinOp {
                    op: BinOp::Ne,
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                })
            }
            _ => Some(left),
        }
    }

    fn parse_unary(&mut self) -> Option<Expr> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.advance();
            let expr = self.parse_unary()?;
            return Some(Expr::Not(Box::new(expr)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        match self.peek()?.clone() {
            Token::True => { self.advance(); Some(Expr::BoolLit(true)) }
            Token::False => { self.advance(); Some(Expr::BoolLit(false)) }
            Token::StringLit(s) => { self.advance(); Some(Expr::StringLit(s)) }
            Token::Ident(s) => { self.advance(); Some(Expr::Ident(s)) }
            Token::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.advance(); // consume ')'
                Some(Expr::Group(Box::new(expr)))
            }
            _ => None,
        }
    }
}

fn parse_cel(input: &str) -> Option<Expr> {
    let tokens = tokenize(input);
    let mut parser = Parser::new(tokens);
    parser.parse_expr()
}

/// Evaluate a CEL expression against a string activation map.
fn eval_expr(expr: &Expr, activation: &HashMap<String, String>) -> Result<CelValue, ()> {
    match expr {
        Expr::BoolLit(b) => Ok(CelValue::Bool(*b)),
        Expr::StringLit(s) => Ok(CelValue::Str(s.clone())),
        Expr::Ident(name) => {
            activation
                .get(name)
                .map(|s| CelValue::Str(s.clone()))
                .ok_or(())
        }
        Expr::Group(inner) => eval_expr(inner, activation),
        Expr::Not(inner) => {
            let val = eval_expr(inner, activation)?;
            Ok(CelValue::Bool(!val.as_bool()))
        }
        Expr::BinOp { op, lhs, rhs } => {
            match op {
                BinOp::And => {
                    let l = eval_expr(lhs, activation)?;
                    if !l.as_bool() {
                        return Ok(CelValue::Bool(false));
                    }
                    let r = eval_expr(rhs, activation)?;
                    Ok(CelValue::Bool(r.as_bool()))
                }
                BinOp::Or => {
                    let l = eval_expr(lhs, activation)?;
                    if l.as_bool() {
                        return Ok(CelValue::Bool(true));
                    }
                    let r = eval_expr(rhs, activation)?;
                    Ok(CelValue::Bool(r.as_bool()))
                }
                BinOp::Eq => {
                    let l = eval_expr(lhs, activation)?;
                    let r = eval_expr(rhs, activation)?;
                    Ok(CelValue::Bool(l.as_str() == r.as_str()))
                }
                BinOp::Ne => {
                    let l = eval_expr(lhs, activation)?;
                    let r = eval_expr(rhs, activation)?;
                    Ok(CelValue::Bool(l.as_str() != r.as_str()))
                }
            }
        }
        Expr::MethodCall { object, method, args } => {
            let obj = eval_expr(object, activation)?;
            let obj_str = obj.as_str();
            match method.as_str() {
                "contains" => {
                    let arg = args.first().ok_or(())?;
                    let arg_val = eval_expr(arg, activation)?;
                    Ok(CelValue::Bool(obj_str.contains(&arg_val.as_str())))
                }
                "startsWith" => {
                    let arg = args.first().ok_or(())?;
                    let arg_val = eval_expr(arg, activation)?;
                    Ok(CelValue::Bool(obj_str.starts_with(&arg_val.as_str())))
                }
                "endsWith" => {
                    let arg = args.first().ok_or(())?;
                    let arg_val = eval_expr(arg, activation)?;
                    Ok(CelValue::Bool(obj_str.ends_with(&arg_val.as_str())))
                }
                "matches" => {
                    let arg = args.first().ok_or(())?;
                    let arg_val = eval_expr(arg, activation)?;
                    let re = Regex::new(&arg_val.as_str()).map_err(|_| ())?;
                    Ok(CelValue::Bool(re.is_match(&obj_str)))
                }
                _ => Err(()),
            }
        }
    }
}

#[derive(Debug, Clone)]
enum CelValue {
    Bool(bool),
    Str(String),
}

impl CelValue {
    fn as_bool(&self) -> bool {
        match self {
            CelValue::Bool(b) => *b,
            CelValue::Str(s) => !s.is_empty(),
        }
    }
    fn as_str(&self) -> String {
        match self {
            CelValue::Bool(b) => b.to_string(),
            CelValue::Str(s) => s.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// CEL Evaluator
// ---------------------------------------------------------------------------

struct CELRule {
    id: String,
    title: String,
    description: String,
    expr: Expr,
    action: Action,
    reason: String,
}

/// CEL evaluator — Common Expression Language policy rules.
///
/// Evaluates CEL-like expressions against flattened event context.
/// Field names use underscores instead of dots (e.g. `tool_args_command`).
pub struct CELEvaluator {
    name: String,
    stages: HashSet<Stage>,
    rules: Vec<CELRule>,
}

impl CELEvaluator {
    /// Create a new CEL evaluator from its YAML config block.
    ///
    /// Expressions are parsed at construction time; invalid expressions are
    /// logged and skipped.
    pub fn new(name: String, config: &serde_yaml::Value) -> Self {
        let map = config.as_mapping().cloned().unwrap_or_default();

        let stages = map
            .get(serde_yaml::Value::String("stages".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| serde_yaml::from_str(v.as_str()?).ok())
                    .collect()
            })
            .unwrap_or_else(|| [Stage::ToolBefore, Stage::ToolAfter].into_iter().collect());

        let mut rules = Vec::new();

        if let Some(seq) = map
            .get(serde_yaml::Value::String("rules".into()))
            .and_then(|v| v.as_sequence())
        {
            for item in seq {
                let m = match item.as_mapping() {
                    Some(m) => m,
                    None => continue,
                };
                let id = m
                    .get(serde_yaml::Value::String("id".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed")
                    .to_string();
                let title = m
                    .get(serde_yaml::Value::String("title".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&id)
                    .to_string();
                let description = m
                    .get(serde_yaml::Value::String("description".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let expr_str = match m
                    .get(serde_yaml::Value::String("expr".into()))
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s,
                    None => {
                        warn!(id, "CEL rule missing 'expr', skipping");
                        continue;
                    }
                };
                let action_str = m
                    .get(serde_yaml::Value::String("action".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("block");
                let action = match action_str {
                    "block" => Action::Block,
                    "detect" => Action::Detect,
                    "redact" => Action::Redact,
                    "allow" => Action::Allow,
                    _ => Action::Block,
                };
                let reason = m
                    .get(serde_yaml::Value::String("reason".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                match parse_cel(expr_str) {
                    Some(expr) => rules.push(CELRule {
                        id,
                        title,
                        description,
                        expr,
                        action,
                        reason,
                    }),
                    None => {
                        warn!(id, expr = expr_str, "Failed to parse CEL expression");
                    }
                }
            }
        }

        Self {
            name,
            stages,
            rules,
        }
    }
}

#[async_trait]
impl Evaluator for CELEvaluator {
    fn name(&self) -> &str {
        &self.name
    }
    fn eval_type(&self) -> &str {
        "cel"
    }
    fn stages(&self) -> &HashSet<Stage> {
        &self.stages
    }

    async fn evaluate(&self, ctx: &EvalContext) -> EvalResult {
        let flat = ctx.flat_fields();
        // Convert dots to underscores in keys
        let activation: HashMap<String, String> = flat
            .into_iter()
            .map(|(k, v)| (k.replace('.', "_"), v))
            .collect();

        for rule in &self.rules {
            match eval_expr(&rule.expr, &activation) {
                Ok(CelValue::Bool(true)) => {
                    let reason = if rule.reason.is_empty() {
                        format!("CEL policy triggered: {}", rule.title)
                    } else {
                        rule.reason.clone()
                    };
                    return EvalResult {
                        evaluator: self.name.clone(),
                        action: rule.action,
                        confidence: 1.0,
                        reason,
                        redacted: None,
                        metadata: [
                            ("id".to_string(), serde_json::json!(rule.id)),
                            ("title".to_string(), serde_json::json!(rule.title)),
                            ("description".to_string(), serde_json::json!(rule.description)),
                        ]
                        .into_iter()
                        .collect(),
                    };
                }
                Err(()) => continue, // Missing field — skip rule
                _ => continue,
            }
        }

        EvalResult::allow(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_activation(fields: &[(&str, &str)]) -> HashMap<String, String> {
        fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_parse_simple_eq() {
        let expr = parse_cel(r#"tool_name == "exec""#).unwrap();
        let act = make_activation(&[("tool_name", "exec")]);
        assert!(eval_expr(&expr, &act).unwrap().as_bool());
    }

    #[test]
    fn test_parse_and() {
        let expr = parse_cel(r#"tool_name == "exec" && user_id != "admin""#).unwrap();
        let act = make_activation(&[("tool_name", "exec"), ("user_id", "guest")]);
        assert!(eval_expr(&expr, &act).unwrap().as_bool());

        let act2 = make_activation(&[("tool_name", "exec"), ("user_id", "admin")]);
        assert!(!eval_expr(&expr, &act2).unwrap().as_bool());
    }

    #[test]
    fn test_contains_method() {
        let expr = parse_cel(r#"tool_args_command.contains("curl")"#).unwrap();
        let act = make_activation(&[("tool_args_command", "curl http://example.com")]);
        assert!(eval_expr(&expr, &act).unwrap().as_bool());

        let act2 = make_activation(&[("tool_args_command", "ls -la")]);
        assert!(!eval_expr(&expr, &act2).unwrap().as_bool());
    }

    #[test]
    fn test_starts_with_method() {
        let expr = parse_cel(r#"tool_args_command.startsWith("sudo")"#).unwrap();
        let act = make_activation(&[("tool_args_command", "sudo rm -rf /")]);
        assert!(eval_expr(&expr, &act).unwrap().as_bool());
    }

    #[test]
    fn test_matches_method() {
        let expr = parse_cel(r#"tool_args_command.matches("rm\\s+-r")"#).unwrap();
        let act = make_activation(&[("tool_args_command", "rm -rf /")]);
        assert!(eval_expr(&expr, &act).unwrap().as_bool());
    }

    #[test]
    fn test_missing_field_returns_err() {
        let expr = parse_cel(r#"nonexistent_field == "foo""#).unwrap();
        let act = make_activation(&[]);
        assert!(eval_expr(&expr, &act).is_err());
    }

    #[test]
    fn test_or_expression() {
        let expr = parse_cel(
            r#"tool_args_command == "env" || tool_args_command == "printenv""#,
        ).unwrap();
        let act = make_activation(&[("tool_args_command", "printenv")]);
        assert!(eval_expr(&expr, &act).unwrap().as_bool());
    }

    #[test]
    fn test_parenthesized_group() {
        let expr = parse_cel(
            r#"tool_name == "exec" && (tool_args_command == "env" || tool_args_command.contains("export"))"#,
        ).unwrap();
        let act = make_activation(&[("tool_name", "exec"), ("tool_args_command", "export FOO=bar")]);
        assert!(eval_expr(&expr, &act).unwrap().as_bool());

        let act2 = make_activation(&[("tool_name", "read_file"), ("tool_args_command", "export FOO=bar")]);
        assert!(!eval_expr(&expr, &act2).unwrap().as_bool());
    }

    #[tokio::test]
    async fn test_cel_evaluator() {
        let config: serde_yaml::Value = serde_yaml::from_str(r#"
stages: [tool.before]
rules:
  - id: cel-test-001
    title: Block sudo
    description: Blocks privilege escalation via sudo
    expr: 'tool_name == "exec" && tool_args_command.startsWith("sudo")'
    action: block
    reason: No sudo allowed
"#).unwrap();

        let eval = CELEvaluator::new("test-cel".into(), &config);
        let ctx = EvalContext {
            stage: Stage::ToolBefore,
            session_id: String::new(),
            channel: String::new(),
            user_id: String::new(),
            timestamp: 0.0,
            message_text: None,
            tool_name: Some("exec".into()),
            tool_args: [("command".into(), serde_json::json!("sudo rm -rf /"))].into_iter().collect(),
            tool_result: None,
            model: None,
            params: HashMap::new(),
            raw: HashMap::new(),
        };

        let result = eval.evaluate(&ctx).await;
        assert_eq!(result.action, Action::Block);
        assert_eq!(result.reason, "No sudo allowed");
    }
}
