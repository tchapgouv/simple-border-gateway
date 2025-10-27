use clap::Parser;
use log::{LevelFilter, debug, error, info, trace, warn};
use simple_border_gateway::http_gateway::inbound::InboundGatewayBuilder;
use simple_border_gateway::http_gateway::outbound::OutboundGatewayBuilder;
use simple_border_gateway::inbound::InboundHandler;
use simple_border_gateway::matrix::util::NameResolver;
use simple_border_gateway::outbound::OutboundHandler;
use simple_border_gateway::util::{
    create_http_client, crypto_provider, install_crypto_provider, read_pem,
};
use notify::{recommended_watcher, RecursiveMode, Watcher};
use snafu::{Report, ResultExt, Whatever};
use tokio::task::JoinHandle;

use std::env;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::mpsc;
use std::{collections::BTreeMap, fs};

use ruma::{serde::Base64, signatures::PublicKeyMap};
use simple_border_gateway::config::BorderGatewayConfig;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Log level, defaults to INFO
    #[arg(short = 'l', long, value_name = "LEVEL")]
    log_level: Option<LevelFilter>,

    /// Only run the inbound proxy, config will be ignored
    #[arg(short = 'i', long, default_value = "false")]
    inbound_only: bool,

    /// Only run the outbound proxy, config will be ignored
    #[arg(short = 'o', long, default_value = "false")]
    outbound_only: bool,

    /// Sets a custom config file
    #[arg(short = 'c', long, value_name = "FILE", default_value = "config.toml")]
    config_file: PathBuf,
}

async fn start_services(
    config: BorderGatewayConfig,
    cli: &Cli,
) -> Result<Vec<JoinHandle<()>>, Whatever> {
    debug!("Configuration loaded");
    let mut domain_server_name_map = BTreeMap::new();
    let mut target_base_urls: BTreeMap<String, String> = BTreeMap::new();

    for hs in config.internal_homeservers {
        domain_server_name_map.insert(hs.federation_domain.clone(), hs.server_name.clone());
        target_base_urls.insert(hs.federation_domain, hs.target_base_url);
    }

    let mut allowed_federation_domains: BTreeMap<String, String> = BTreeMap::new();
    let mut allowed_client_domains: BTreeMap<String, String> = BTreeMap::new();
    let mut public_key_map: PublicKeyMap = BTreeMap::new();

    for hs in config.external_homeservers {
        domain_server_name_map.insert(hs.federation_domain.clone(), hs.server_name.clone());
        allowed_federation_domains.insert(hs.federation_domain, hs.server_name.clone());
        domain_server_name_map.insert(hs.client_domain.clone(), hs.server_name.clone());
        allowed_client_domains.insert(hs.client_domain, hs.server_name.clone());

        let mut verify_keys: BTreeMap<String, Base64> = BTreeMap::new();
        for (k, v) in hs.verify_keys {
            verify_keys.insert(
                k,
                Base64::parse(v).whatever_context("Failed to parse verify key as base64")?,
            );
        }
        public_key_map.insert(hs.server_name, verify_keys);
    }

    let mut tasks = vec![];
    let name_resolver = NameResolver::new(domain_server_name_map);

    if let Some(inbound_config) = config.inbound_proxy {
        if cli.outbound_only {
            info!("Inbound proxy is configured but --outbound-only is set, inbound proxy will not be started");
        } else {
            let http_client = create_http_client(inbound_config.additional_root_certs, None)
                .whatever_context("Failed to create inbound http client")?;
            let handler = InboundHandler::new(name_resolver.clone(), public_key_map);

            let listen_address = inbound_config
                .listen_address
                .parse()
                .whatever_context("Failed to parse inbound listen address")?;

            tasks.push(tokio::spawn(async move {
                if let Err(err) =
                    InboundGatewayBuilder::new(listen_address, target_base_urls, handler)
                        .with_http_client(http_client)
                        .build_and_run()
                        .await
                {
                    error!("Failed to create inbound proxy");
                    error!("{}", Report::from_error(err));
                    exit(1);
                }
            }));
            info!("Inbound proxy initialized");
        }
    }

    if let Some(outbound_config) = config.outbound_proxy {
        if cli.outbound_only {
            info!("Outbound proxy is configured but --inbound-only is set, outbound proxy will not be started");
        } else {
            let http_client = create_http_client(
                outbound_config.additional_root_certs,
                outbound_config.upstream_proxy_url,
            )
            .whatever_context("Failed to create outbound http client")?;
            let handler = OutboundHandler::new(
                name_resolver,
                allowed_federation_domains,
                allowed_client_domains,
                outbound_config.allowed_non_matrix_regexes_dangerous,
            )
            .whatever_context("Failed to create outbound handler")?;

            let ca_private_key = read_pem(outbound_config.ca_priv_key.as_str())
                .whatever_context("Can't read CA private key for outbound proxy")?;
            let ca_cert = read_pem(&outbound_config.ca_cert)
                .whatever_context("Can't read CA certificate for outbound proxy")?;

            let listen_address = outbound_config
                .listen_address
                .parse()
                .whatever_context("Failed to parse outbound listen address")?;

            tasks.push(tokio::spawn(async move {
                if let Err(err) = OutboundGatewayBuilder::new(
                    listen_address,
                    ca_private_key,
                    ca_cert,
                    crypto_provider::default_provider(),
                    handler,
                )
                .with_http_client(http_client)
                .build_and_run()
                .await
                {
                    error!("Failed to create outbound proxy");
                    error!("{}", Report::from_error(err));
                    exit(1);
                }
            }));
            info!("Outbound proxy initialized");
        }
    }
    Ok(tasks)
}

#[snafu::report]
#[tokio::main]
async fn main() -> Result<(), Whatever> {
    let cli = Cli::parse();
    // Inbound/Outbound tasks. Made external to be able to abort them on config reload.
    let mut tasks: Vec<JoinHandle<()>>;
    // MPSC Channels used by the file watcher
    let (tx, rx) = mpsc::channel();
    let mut watcher = recommended_watcher(move |res| {
        let _ = tx.send(res);
    }).whatever_context("Failed to create file watcher")?;

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

    if cli.inbound_only && cli.outbound_only {
        error!("Cannot use --inbound-only and --outbound-only at the same time");
        std::process::exit(1);
    }

    install_crypto_provider();
    debug!("Crypto provider installed");
    
    // Starting to watch the config file
    watcher.watch(&cli.config_file, RecursiveMode::NonRecursive).whatever_context("Failed to watch config file")?;

    // Initial loading of the config file
    // This could have been inside the loop as well, but it was left out of it for simplicity
    // as the loop only contains the auto reload logic.
    debug!("Initial reading of config file {}", cli.config_file.display());
    let config_toml_str =
        fs::read_to_string(&cli.config_file).whatever_context("Failed to read config file")?;
    let config: BorderGatewayConfig =
        toml::from_str(&config_toml_str).whatever_context("Failed to deserialize config file")?;

    tasks = start_services(config, &cli).await?;

    // Auto reload logic
    loop {
        // Waiting for a file change event.
        // This is very simplistic on purpose, as it will reload the config on any file change event.
        let command = rx.recv().whatever_context("The watch channel closed")?;
        trace!("File change event received: {:?}", command);

        // Was the config file created or modified?
        match command {
            Ok(event) => {
                match event.kind {
                    notify::EventKind::Create(_) | notify::EventKind::Modify(notify::event::ModifyKind::Data(_)) => {
                        info!("Reloading config file {}...", cli.config_file.display());
                        let config_toml_str = match fs::read_to_string(&cli.config_file) {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Failed to read config file: {}", e);
                                warn!("The services will not be reloaded due to config errors");
                                continue;
                            }
                        };
                        let config: BorderGatewayConfig = match toml::from_str(&config_toml_str) {
                            Ok(c) => c,
                            Err(e) => {
                                error!("Failed to deserialize config file: {}", e);
                                warn!("The services will not be reloaded due to config errors");
                                continue;
                            }
                        };
                        // Aborting existing tasks
                        info!("New configuration is valid and loaded. Aborting existing tasks...");
                        for task in tasks.iter() {
                            task.abort();
                        }
                        // Starting new tasks with the new config
                        info!("Starting the services with the new config...");
                        tasks = match start_services(config, &cli).await {
                            Ok(t) => t,
                            Err(e) => {
                                error!("Failed to start services with new config: {}", e);
                                error!("Exiting due to failure to start services with new config");
                                exit(1);
                            }
                        };
                    },
                    notify::EventKind::Modify(modify_kind) => {
                        trace!("Ignoring modify kind: {:?}", modify_kind);
                    },
                    // Ignoring all other types of events, as they are not relevant for config reload
                    notify::EventKind::Access(_) |
                    notify::EventKind::Any |
                    notify::EventKind::Remove(_) |
                    notify::EventKind::Other => {
                        trace!("Ignoring event kind: {:?}", event.kind);
                    }
                }
            },
            Err(_) => todo!(),
        }
    }
}
