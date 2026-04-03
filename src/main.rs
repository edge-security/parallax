use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use parallax::config::loader::{build_chain, load_config};
use parallax::reporting::audit::AuditLogger;
use parallax::reporting::webhook::WebhookReporter;
use parallax::server::api::{self, AppState};

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

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
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
            info!(evaluators = chain.len(), "Evaluator chain built");

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

            // Build application state
            let state = Arc::new(AppState {
                chain,
                audit,
                webhook,
                mode: "server".to_string(),
            });

            let app = api::router(state);

            let addr = format!(
                "{}:{}",
                platform_config.server.host, platform_config.server.port
            );

            info!(addr = %addr, "Starting Parallax server");

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
    }
}
