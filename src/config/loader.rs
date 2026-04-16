use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{error, info, warn};

use crate::config::schema::{EvaluatorConfig, PlatformConfig};
use crate::engine::chain::EvaluatorChain;
use crate::evaluators::cel_eval::CELEvaluator;
use crate::evaluators::pattern_eval::PatternEvaluator;
use crate::evaluators::regex_eval::RegexEvaluator;
use crate::evaluators::sigma_eval::SigmaEvaluator;
use crate::evaluators::sql_eval::SQLEvaluator;

const DEFAULT_CONFIG_PATHS: &[&str] = &[
    "parallax.yaml",
    "parallax.yml",
    "config.yaml",
    "config.yml",
];

/// Find a config file. If `path` is provided, use it directly.
/// Otherwise, search the default locations.
pub fn find_config(path: Option<&str>) -> Result<PathBuf, String> {
    if let Some(p) = path {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(format!("Config file not found: {p}"));
    }

    for candidate in DEFAULT_CONFIG_PATHS {
        let pb = PathBuf::from(candidate);
        if pb.exists() {
            info!(path = %pb.display(), "Found config file");
            return Ok(pb);
        }
    }

    Err(format!(
        "No config file found. Tried: {}",
        DEFAULT_CONFIG_PATHS.join(", ")
    ))
}

/// Load evaluator configs from a directory of YAML files.
fn load_evaluator_dir(dir: &Path, config_root: &Path) -> Vec<EvaluatorConfig> {
    let dir = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        config_root.join(dir)
    };

    if !dir.is_dir() {
        return Vec::new();
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .map(|ext| ext == "yaml" || ext == "yml")
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort();

    let mut evaluators = Vec::new();
    for path in entries {
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_yaml::from_str::<serde_yaml::Value>(&content) {
                Ok(val) => {
                    if let Some(seq) = val.as_sequence() {
                        for item in seq {
                            match serde_yaml::from_value::<EvaluatorConfig>(item.clone()) {
                                Ok(ec) => evaluators.push(ec),
                                Err(e) => warn!(
                                    path = %path.display(),
                                    error = %e,
                                    "Failed to parse evaluator entry"
                                ),
                            }
                        }
                    } else {
                        match serde_yaml::from_value::<EvaluatorConfig>(val) {
                            Ok(ec) => {
                                info!(name = %ec.name, path = %path.display(), "Loaded evaluator from file");
                                evaluators.push(ec);
                            }
                            Err(e) => warn!(
                                path = %path.display(),
                                error = %e,
                                "Failed to parse evaluator file"
                            ),
                        }
                    }
                }
                Err(e) => warn!(path = %path.display(), error = %e, "Failed to parse YAML"),
            },
            Err(e) => warn!(path = %path.display(), error = %e, "Failed to read file"),
        }
    }

    evaluators
}

/// Load and validate the platform configuration from a YAML file.
///
/// Merges inline evaluator definitions with any found in the `evaluators_dir`.
/// Duplicate evaluator names are resolved last-definition-wins.
///
/// # Errors
///
/// Returns an error string if the file cannot be found, read, or parsed.
pub fn load_config(path: Option<&str>) -> Result<PlatformConfig, String> {
    let config_path = find_config(path)?;
    let config_root = config_path.parent().unwrap_or(Path::new("."));

    let content =
        std::fs::read_to_string(&config_path).map_err(|e| format!("Failed to read config: {e}"))?;
    let mut config: PlatformConfig =
        serde_yaml::from_str(&content).map_err(|e| format!("Failed to parse config: {e}"))?;

    // Load evaluators from directory
    let eval_dir = config
        .evaluators_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| config_root.join("evaluators"));

    let dir_evaluators = load_evaluator_dir(&eval_dir, config_root);
    if !dir_evaluators.is_empty() {
        info!(
            count = dir_evaluators.len(),
            "Loaded evaluators from directory"
        );
        // Merge: inline first, then directory. Deduplicate by name (last wins).
        let mut merged: Vec<EvaluatorConfig> = Vec::new();
        let mut seen: HashMap<String, usize> = HashMap::new();

        for ec in config.evaluators.into_iter().chain(dir_evaluators) {
            if let Some(&idx) = seen.get(&ec.name) {
                merged[idx] = ec.clone();
                info!(name = %ec.name, "Evaluator overwritten by later definition");
            } else {
                seen.insert(ec.name.clone(), merged.len());
                merged.push(ec);
            }
        }
        config.evaluators = merged;
    }

    info!(
        evaluators = config.evaluators.len(),
        "Configuration loaded"
    );

    Ok(config)
}

/// Build an [`EvaluatorChain`] from the loaded configuration.
///
/// Disabled evaluators (`enabled: false`) are skipped. Unknown evaluator
/// types are logged and ignored.
pub fn build_chain(config: &PlatformConfig) -> EvaluatorChain {
    let mut chain = EvaluatorChain::new();

    for ec in &config.evaluators {
        if !ec.enabled {
            info!(name = %ec.name, "Evaluator disabled, skipping");
            continue;
        }

        let value = ec.to_evaluator_value();

        let evaluator: Option<Box<dyn crate::evaluators::Evaluator>> = match ec.eval_type.as_str() {
            "regex" => Some(Box::new(RegexEvaluator::new(ec.name.clone(), &value))),
            "pattern" => Some(Box::new(PatternEvaluator::new(ec.name.clone(), &value))),
            "sigma" => Some(Box::new(SigmaEvaluator::new(ec.name.clone(), &value))),
            "cel" => Some(Box::new(CELEvaluator::new(ec.name.clone(), &value))),
            "sql" => Some(Box::new(SQLEvaluator::new(ec.name.clone(), &value))),
            unknown => {
                error!(name = %ec.name, eval_type = unknown, "Unknown evaluator type, skipping");
                None
            }
        };

        if let Some(ev) = evaluator {
            info!(
                name = %ec.name,
                eval_type = %ec.eval_type,
                stages = ?ec.stages,
                "Registered evaluator"
            );
            chain.add(ev);
        }
    }

    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_config_missing() {
        let result = find_config(Some("/nonexistent/path.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_from_string() {
        let yaml = r#"
server:
  host: "0.0.0.0"
  port: 8080
evaluators:
  - name: test-regex
    type: regex
    stages: [tool.before]
    rules:
      - label: "test"
        pattern: "foo"
        action: detect
"#;
        let config: PlatformConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);

        let chain = build_chain(&config);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_build_chain_skips_disabled() {
        let yaml = r#"
evaluators:
  - name: disabled-eval
    type: regex
    enabled: false
    rules: []
  - name: enabled-eval
    type: regex
    rules:
      - label: x
        pattern: x
        action: detect
"#;
        let config: PlatformConfig = serde_yaml::from_str(yaml).unwrap();
        let chain = build_chain(&config);
        assert_eq!(chain.len(), 1);
    }
}
