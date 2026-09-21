use log::{LevelFilter, debug, error, info, warn};
use simple_border_gateway::cli::parse_cli;
use simple_border_gateway::services::{prepare_services, spawn_services, stop_services};
use simple_border_gateway::util::install_crypto_provider;
use snafu::{ResultExt, Whatever};
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;

use std::env;
use std::str::FromStr;

use simple_border_gateway::config::BorderGatewayConfig;

#[snafu::report]
#[tokio::main]
async fn main() -> Result<(), Whatever> {
    let cli = parse_cli();
    debug!("CLI parsed");

    println!("Starting simple-border-gateway");
    let app_log_level = cli.log_level.unwrap_or(
        LevelFilter::from_str(env::var("LOG_LEVEL").unwrap_or_default().as_str())
            .unwrap_or(LevelFilter::Info),
    );

    let mut builder = env_logger::Builder::new();
    if app_log_level < log::LevelFilter::Debug {
        builder.format_target(false);
    }

    builder
        // Only log errors for dependencies by default
        .filter_level(log::LevelFilter::Error)
        .filter_module("simple_border_gateway", app_log_level)
        .format_timestamp_millis()
        .target(env_logger::Target::Stdout)
        .parse_default_env()
        .init();

    debug!("Logging initialized");

    install_crypto_provider();
    debug!("Crypto provider installed");

    // Initial loading of the config file
    // This could have been inside the loop as well, but it was left out of it for simplicity
    // as the loop only contains the auto reload logic.
    debug!(
        "Initial reading of config file {}",
        cli.config_file.display()
    );
    let mut old_config = BorderGatewayConfig::load(&cli.config_file)?;

    let initial_services = prepare_services(old_config.clone(), &cli)?;
    // Inbound/Outbound tasks. Kept so they can be aborted on config reload.
    let mut tasks: Vec<JoinHandle<()>> = spawn_services(initial_services);

    let mut hup =
        signal(SignalKind::hangup()).whatever_context("Failed to start SIGHUP handler")?;

    // Auto reload logic
    loop {
        tokio::select! {
            // Handle Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                stop_services(tasks).await;
                break;
            }
            // Handle SIGHUP
            _ = hup.recv() => {
                info!("Received SIGHUP. Reloading config file {}...", cli.config_file.display());
                let config = match BorderGatewayConfig::load(&cli.config_file) {
                    Ok(config) => config,
                    Err(e) => {
                        error!("Failed to load configuration: {}", e);
                        warn!("The services will not be reloaded due to config errors");
                        continue;
                    }
                };
                if config == old_config {
                    info!("Configuration unchanged, skipping reload");
                    continue;
                }
                // Validate and build the new services *before* stopping the running ones,
                // so that an invalid config cannot take down a healthy gateway.
                let new_services = match prepare_services(config.clone(), &cli) {
                    Ok(services) => services,
                    Err(e) => {
                        error!("Failed to start services with new config: {}", e);
                        warn!("The services will not be reloaded due to config errors");
                        continue;
                    }
                };
                // Aborting existing tasks and waiting for them to release their
                // listening sockets before binding the new ones.
                info!("New configuration is valid and loaded. Aborting existing tasks...");
                stop_services(std::mem::take(&mut tasks)).await;
                // Starting new tasks with the new config
                info!("Starting the services with the new config...");
                tasks = spawn_services(new_services);
                old_config = config;
            }
        }
    }
    Ok(())
}
