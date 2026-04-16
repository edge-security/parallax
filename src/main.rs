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
    about = "Runtime security engine for AI agents — blocks prompt injection, data exfiltration, and dangerous tool calls",
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

        /// Run mode: server (eval API) or proxy (LLM reverse proxy)
        #[arg(long, default_value = "server")]
        mode: String,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Configure an agent framework to route through the Parallax security proxy
    Setup {
        /// Agent framework to configure
        #[arg(long, value_parser = ["openclaw"])]
        framework: String,

        /// Proxy host
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Proxy port
        #[arg(long, default_value = "9920")]
        port: u16,

        /// Model ID
        #[arg(long, default_value = "claude-sonnet-4-20250514")]
        model: String,
    },

    /// Revert an agent framework to bypass the Parallax proxy
    Revert {
        /// Agent framework to revert
        #[arg(long, value_parser = ["openclaw"])]
        framework: String,

        /// Model ID
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
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(&log_level)),
                )
                .init();

            let mut platform_config = match load_config(config.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "Failed to load configuration");
                    std::process::exit(1);
                }
            };

            if let Some(h) = host {
                platform_config.server.host = h;
            }
            if let Some(p) = port {
                platform_config.server.port = p;
            }

            let chain = build_chain(&platform_config);
            info!(evaluators = chain.len(), mode = %mode, "Evaluator chain built");

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
                let upstream = platform_config.proxy.upstream_base_url().to_string();
                info!(upstream = %upstream, "Proxy upstream configured");
                let proxy_state = Arc::new(ProxyState {
                    chain: Arc::new(chain),
                    audit: audit.map(Arc::new),
                    webhook: webhook.map(Arc::new),
                    client: reqwest::Client::new(),
                    upstream_base: upstream,
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

        Commands::Setup { framework, host, port, model } => {
            match framework.as_str() {
                "openclaw" => parallax::integrations::openclaw::setup(&host, port, &model),
                _ => {
                    eprintln!("Unsupported framework: {}. Supported: openclaw", framework);
                    std::process::exit(1);
                }
            }
        }

        Commands::Revert { framework, model } => {
            match framework.as_str() {
                "openclaw" => parallax::integrations::openclaw::revert(&model),
                _ => {
                    eprintln!("Unsupported framework: {}. Supported: openclaw", framework);
                    std::process::exit(1);
                }
            }
        }
    }
}
