use clap::Parser;
use log::{debug, info, LevelFilter};
use simple_border_gateway::http_gateway::inbound::InboundGatewayBuilder;
use simple_border_gateway::http_gateway::outbound::OutboundGatewayBuilder;
use simple_border_gateway::http_gateway::util::{create_http_client, install_crypto_provider};
use simple_border_gateway::inbound::InboundHandler;
use simple_border_gateway::matrix::util::NameResolver;
use simple_border_gateway::outbound::OutboundHandler;

use std::env;
use std::path::PathBuf;
use std::str::FromStr;
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    println!("Starting simple-border-gateway");

    if cli.inbound_only && cli.outbound_only {
        eprintln!("Cannot use --inbound-only and --outbound-only at the same time");
        std::process::exit(1);
    }

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
    debug!("Reading config file {}", cli.config_file.display());

    let config_toml_str = fs::read_to_string(cli.config_file).expect("Failed to read config file");
    let config: BorderGatewayConfig =
        toml::from_str(&config_toml_str).expect("Failed to deserialize config file");

    debug!("Config file loaded");

    install_crypto_provider();

    debug!("Crypto provider installed");

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
                Base64::parse(v).expect("Failed to parse verify key as base64"),
            );
        }
        public_key_map.insert(hs.server_name, verify_keys);
    }

    debug!("Configuration initialized");

    let mut tasks = vec![];

    let name_resolver = NameResolver::new(domain_server_name_map);

    if let Some(inbound_config) = config.inbound_proxy {
        if cli.outbound_only {
            info!("Inbound proxy is configured but --outbound-only is set, inbound proxy will not be started");
        } else {
            let http_client = create_http_client(inbound_config.additional_root_certs, None)
                .expect("Failed to create inbound http client");
            let handler = InboundHandler::new(name_resolver.clone(), public_key_map);

            tasks.push(tokio::spawn(async move {
                InboundGatewayBuilder::new(
                    inbound_config.listen_address.parse().unwrap(),
                    target_base_urls,
                    handler,
                )
                .with_http_client(http_client)
                .build_and_run()
                .await
                .expect("Failed to create inbound proxy");
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
            .expect("Failed to create outbound http client");
            let handler = OutboundHandler::new(
                name_resolver,
                allowed_federation_domains,
                allowed_client_domains,
                outbound_config.allowed_non_matrix_regexes_dangerous,
            )
            .expect("Failed to create outbound handler");

            tasks.push(tokio::spawn(async move {
                OutboundGatewayBuilder::new(
                    outbound_config.listen_address.parse().unwrap(),
                    outbound_config.ca_priv_key,
                    outbound_config.ca_cert,
                    handler,
                )
                .with_http_client(http_client)
                .build_and_run()
                .await
                .expect("Failed to create outbound proxy");
            }));
            info!("Outbound proxy initialized");
        }
    }

    for task in tasks {
        let _ = task.await;
    }
}
