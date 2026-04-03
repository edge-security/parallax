use serde::{Deserialize, Serialize};

/// Top-level platform configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub reporting: ReportingConfig,
    #[serde(default)]
    pub evaluators: Vec<EvaluatorConfig>,
    #[serde(default)]
    pub evaluators_dir: Option<String>,
}

/// HTTP server configuration.
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

/// Reporting / observability configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportingConfig {
    #[serde(default)]
    pub log_file: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
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
    /// Catch-all for evaluator-specific fields (action, label, threshold, etc.)
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
