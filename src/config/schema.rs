use serde::{Deserialize, Serialize};

/// Top-level platform configuration, typically loaded from `parallax.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub reporting: ReportingConfig,
    /// Inline evaluator definitions.
    #[serde(default)]
    pub evaluators: Vec<EvaluatorConfig>,
    /// Optional directory to load additional evaluator YAML files from.
    #[serde(default)]
    pub evaluators_dir: Option<String>,
}

/// HTTP server bind address. Defaults to `127.0.0.1:9920`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    9920
}

/// Proxy mode configuration -- controls which upstream LLM provider to proxy to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Upstream provider: "anthropic", "openai", "gemini", or "custom"
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Custom upstream base URL (used when provider is "custom", or to override defaults)
    #[serde(default)]
    pub upstream_url: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            upstream_url: None,
        }
    }
}

impl ProxyConfig {
    /// Resolve the base URL for the upstream LLM provider.
    ///
    /// Returns the explicit `upstream_url` if set, otherwise infers from `provider`.
    pub fn upstream_base_url(&self) -> &str {
        if let Some(ref url) = self.upstream_url {
            return url.as_str();
        }
        match self.provider.as_str() {
            "openai" => "https://api.openai.com",
            "gemini" => "https://generativelanguage.googleapis.com",
            _ => "https://api.anthropic.com",
        }
    }
}

fn default_provider() -> String {
    "anthropic".to_string()
}

/// Reporting / observability configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Path to append-only JSON-lines audit log. Disabled when `None`.
    #[serde(default)]
    pub log_file: Option<String>,
    /// URL to POST evaluation events to. Disabled when `None`.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Action types that trigger a webhook (`"block"`, `"redact"`, etc.).
    #[serde(default = "default_webhook_events")]
    pub webhook_events: Vec<String>,
}

fn default_webhook_events() -> Vec<String> {
    vec!["block".into(), "redact".into()]
}

/// Configuration for a single evaluator instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatorConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub eval_type: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_stages")]
    pub stages: Vec<String>,
    #[serde(default)]
    pub rules: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub rules_dir: Option<String>,
    /// Catch-all for evaluator-specific fields (action, threshold, etc.)
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_yaml::Value>,
}

fn default_enabled() -> bool {
    true
}

fn default_stages() -> Vec<String> {
    vec!["tool.before".into(), "tool.after".into()]
}

impl EvaluatorConfig {
    /// Convert to a serde_yaml::Value suitable for passing to evaluator constructors.
    pub fn to_evaluator_value(&self) -> serde_yaml::Value {
        // Rebuild a mapping with all relevant fields
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("name".into()),
            serde_yaml::Value::String(self.name.clone()),
        );
        map.insert(
            serde_yaml::Value::String("type".into()),
            serde_yaml::Value::String(self.eval_type.clone()),
        );
        map.insert(
            serde_yaml::Value::String("stages".into()),
            serde_yaml::to_value(&self.stages).unwrap_or_default(),
        );
        map.insert(
            serde_yaml::Value::String("rules".into()),
            serde_yaml::to_value(&self.rules).unwrap_or_default(),
        );
        if let Some(ref dir) = self.rules_dir {
            map.insert(
                serde_yaml::Value::String("rules_dir".into()),
                serde_yaml::Value::String(dir.clone()),
            );
        }
        for (k, v) in &self.extra {
            map.insert(serde_yaml::Value::String(k.clone()), v.clone());
        }
        serde_yaml::Value::Mapping(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_minimal_config() {
        let yaml = r#"
server:
  port: 8080
evaluators:
  - name: test
    type: regex
    rules: []
"#;
        let config: PlatformConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.evaluators.len(), 1);
        assert_eq!(config.evaluators[0].name, "test");
        assert!(config.evaluators[0].enabled);
    }

    #[test]
    fn test_default_config() {
        let yaml = "{}";
        let config: PlatformConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9920);
        assert!(config.evaluators.is_empty());
    }

    #[test]
    fn test_evaluator_to_value() {
        let ec = EvaluatorConfig {
            name: "test".into(),
            eval_type: "regex".into(),
            enabled: true,
            stages: vec!["tool.before".into()],
            rules: vec![],
            rules_dir: None,
            extra: std::collections::HashMap::new(),
        };
        let val = ec.to_evaluator_value();
        assert!(val.as_mapping().is_some());
    }
}
