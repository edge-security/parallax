use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use parallax::config::loader::{build_chain, load_config};
use parallax::reporting::audit::AuditLogger;
use parallax::reporting::webhook::WebhookReporter;
use parallax::server::api::{self, AppState};
use parallax::server::proxy::{self, ProxyState};

#[derive(Parser)]
#[command(
    name = "parallax",
    about = "A fast, configurable security evaluation engine for AI agent systems",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the evaluation server
    Serve {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,

        /// Override host from config
        #[arg(long)]
        host: Option<String>,

        /// Override port from config
        #[arg(long)]
        port: Option<u16>,

        /// Run mode: server (eval API) or proxy (Anthropic reverse proxy)
        #[arg(long, default_value = "server")]
        mode: String,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Configure OpenClaw to route through the security proxy
    #[command(name = "setup-openclaw")]
    SetupOpenclaw {
        /// Proxy host
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Proxy port
        #[arg(long, default_value = "9920")]
        port: u16,

        /// Claude model ID
        #[arg(long, default_value = "claude-sonnet-4-20250514")]
        model: String,
    },

    /// Revert OpenClaw to use Anthropic directly (bypass proxy)
    #[command(name = "revert-openclaw")]
    RevertOpenclaw {
        /// Claude model ID
        #[arg(long, default_value = "claude-sonnet-4-20250514")]
        model: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            config,
            host,
            port,
            mode,
            log_level,
        } => {
            // Initialize tracing
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(&log_level)),
                )
                .init();

            // Load configuration
            let mut platform_config = match load_config(config.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "Failed to load configuration");
                    std::process::exit(1);
                }
            };

            // Apply CLI overrides
            if let Some(h) = host {
                platform_config.server.host = h;
            }
            if let Some(p) = port {
                platform_config.server.port = p;
            }

            // Build evaluator chain
            let chain = build_chain(&platform_config);
            info!(evaluators = chain.len(), mode = %mode, "Evaluator chain built");

            // Initialize reporting
            let audit = platform_config
                .reporting
                .log_file
                .as_deref()
                .and_then(|path| {
                    match AuditLogger::new(path) {
                        Ok(logger) => {
                            info!(path, "Audit logger initialized");
                            Some(logger)
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to initialize audit logger");
                            None
                        }
                    }
                });

            let webhook = platform_config
                .reporting
                .webhook_url
                .as_deref()
                .map(|url| {
                    info!(url, "Webhook reporter initialized");
                    WebhookReporter::new(
                        url.to_string(),
                        platform_config.reporting.webhook_events.clone(),
                    )
                });

            let app = if mode == "proxy" {
                let proxy_state = Arc::new(ProxyState {
                    chain: Arc::new(chain),
                    audit: audit.map(Arc::new),
                    webhook: webhook.map(Arc::new),
                    client: reqwest::Client::new(),
                });
                proxy::proxy_router(proxy_state)
            } else {
                let state = Arc::new(AppState {
                    chain,
                    audit,
                    webhook,
                    mode: mode.clone(),
                });
                api::router(state)
            };

            let addr = format!(
                "{}:{}",
                platform_config.server.host, platform_config.server.port
            );

            info!(addr = %addr, mode = %mode, "Starting Parallax server");

            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .unwrap_or_else(|e| {
                    error!(addr = %addr, error = %e, "Failed to bind");
                    std::process::exit(1);
                });

            if let Err(e) = axum::serve(listener, app).await {
                error!(error = %e, "Server error");
                std::process::exit(1);
            }
        }

        Commands::SetupOpenclaw { host, port, model } => {
            setup_openclaw(&host, port, &model);
        }

        Commands::RevertOpenclaw { model } => {
            revert_openclaw(&model);
        }
    }
}

// ---------------------------------------------------------------------------
// setup-openclaw / revert-openclaw
// ---------------------------------------------------------------------------

fn setup_openclaw(host: &str, port: u16, model: &str) {
    let provider_name = "anthropic-secured";
    let base_url = format!("http://{}:{}/anthropic", host, port);
    let model_id = format!("{}/{}", provider_name, model);

    println!("Configuring OpenClaw to use security proxy at {}", base_url);
    println!();

    // Step 1: Register custom provider
    let provider_json = format!(
        r#"{{"baseUrl":"{}","api":"anthropic-messages","models":[{{"id":"{}","name":"Claude (secured)"}}]}}"#,
        base_url, model
    );
    run_openclaw_cmd(&[
        "config", "set",
        &format!("models.providers.{}", provider_name),
        &provider_json,
    ]);

    // Step 2: Set as default model
    run_openclaw_cmd(&[
        "config", "set",
        "agents.defaults.model.primary",
        &model_id,
    ]);

    // Step 3: Copy auth profile
    copy_auth_profile(provider_name);

    // Step 4: Disable shim plugin
    let result = run_openclaw_cmd_result(&[
        "config", "set",
        "plugins.entries.openclaw-security.enabled",
        "false",
    ]);
    if result.is_err() {
        println!("  NOTE: Could not disable shim plugin — if it's loaded, events may be double-counted.");
    }

    println!();
    println!("Done. OpenClaw will now route all Anthropic API traffic through the proxy.");
    println!("  Provider:  {}", provider_name);
    println!("  Model:     {}", model_id);
    println!("  Proxy URL: {}", base_url);
    println!();
    println!("Start the proxy with:");
    println!("  parallax serve --mode proxy -c <config.yaml>");
}

fn revert_openclaw(model: &str) {
    let model_id = format!("anthropic/{}", model);

    println!("Reverting OpenClaw to use Anthropic directly");
    println!();

    // Reset model
    run_openclaw_cmd(&[
        "config", "set",
        "agents.defaults.model.primary",
        &model_id,
    ]);

    // Remove custom provider
    run_openclaw_cmd(&[
        "config", "unset",
        "models.providers.anthropic-secured",
    ]);

    // Remove auth profile
    remove_auth_profile("anthropic-secured");

    // Re-enable shim plugin
    run_openclaw_cmd(&[
        "config", "set",
        "plugins.entries.openclaw-security.enabled",
        "true",
    ]);

    println!();
    println!("Done. OpenClaw now uses {} directly.", model_id);
}

fn run_openclaw_cmd(args: &[&str]) {
    let display: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    println!("  $ openclaw {}", display.join(" "));

    match std::process::Command::new("openclaw")
        .args(args)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("  ERROR: {}", stderr.trim());
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    println!("  {}", stdout.trim());
                }
            }
        }
        Err(e) => {
            eprintln!("  ERROR: Failed to run openclaw: {}", e);
        }
    }
}

fn run_openclaw_cmd_result(args: &[&str]) -> Result<(), ()> {
    let display: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    println!("  $ openclaw {}", display.join(" "));

    match std::process::Command::new("openclaw")
        .args(args)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                Err(())
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    println!("  {}", stdout.trim());
                }
                Ok(())
            }
        }
        Err(_) => Err(()),
    }
}

fn copy_auth_profile(provider_name: &str) {
    let home = match dirs_home() {
        Some(h) => h,
        None => {
            println!("  WARNING: Could not determine home directory");
            return;
        }
    };

    let agents_dir = home.join(".openclaw").join("agents");
    if !agents_dir.is_dir() {
        println!("  WARNING: No agents directory found — you may need to configure auth manually.");
        return;
    }

    let mut copied = false;
    if let Ok(entries) = std::fs::read_dir(&agents_dir) {
        for entry in entries.flatten() {
            let auth_file = entry.path().join("agent").join("auth-profiles.json");
            if !auth_file.exists() {
                continue;
            }

            match std::fs::read_to_string(&auth_file) {
                Ok(content) => {
                    let mut data: serde_json::Value = match serde_json::from_str(&content) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let profiles = match data.get_mut("profiles").and_then(|p| p.as_object_mut()) {
                        Some(p) => p,
                        None => continue,
                    };

                    // Find existing Anthropic key
                    let mut anthropic_key = None;
                    for (_id, profile) in profiles.iter() {
                        if profile.get("provider").and_then(|p| p.as_str()) == Some("anthropic") {
                            if let Some(key) = profile.get("key").and_then(|k| k.as_str()) {
                                anthropic_key = Some(key.to_string());
                                break;
                            }
                        }
                    }

                    let key = match anthropic_key {
                        Some(k) => k,
                        None => continue,
                    };

                    let new_profile_id = format!("{}:default", provider_name);
                    if profiles.contains_key(&new_profile_id) {
                        continue; // already set up
                    }

                    profiles.insert(
                        new_profile_id,
                        serde_json::json!({
                            "type": "api_key",
                            "provider": provider_name,
                            "key": key,
                        }),
                    );

                    if let Ok(json_str) = serde_json::to_string_pretty(&data) {
                        let _ = std::fs::write(&auth_file, format!("{}\n", json_str));
                        let agent_name = entry.file_name();
                        println!("  Copied Anthropic API key to {} in {}", provider_name, agent_name.to_string_lossy());
                        copied = true;
                    }
                }
                Err(_) => continue,
            }
        }
    }

    if !copied {
        println!("  WARNING: No Anthropic API key found to copy. Run: openclaw agents add <id>");
    }
}

fn remove_auth_profile(provider_name: &str) {
    let home = match dirs_home() {
        Some(h) => h,
        None => return,
    };

    let agents_dir = home.join(".openclaw").join("agents");
    if !agents_dir.is_dir() {
        return;
    }

    let profile_id = format!("{}:default", provider_name);
    if let Ok(entries) = std::fs::read_dir(&agents_dir) {
        for entry in entries.flatten() {
            let auth_file = entry.path().join("agent").join("auth-profiles.json");
            if !auth_file.exists() {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&auth_file) {
                let mut data: serde_json::Value = match serde_json::from_str(&content) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let removed = data
                    .get_mut("profiles")
                    .and_then(|p| p.as_object_mut())
                    .map(|profiles| profiles.remove(&profile_id).is_some())
                    .unwrap_or(false);

                if removed {
                    if let Ok(json_str) = serde_json::to_string_pretty(&data) {
                        let _ = std::fs::write(&auth_file, format!("{}\n", json_str));
                        let agent_name = entry.file_name();
                        println!("  Removed {} auth from {}", provider_name, agent_name.to_string_lossy());
                    }
                }
            }
        }
    }
}

fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(std::path::PathBuf::from)
}
