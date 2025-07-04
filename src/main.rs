use log::{debug, info};
use simple_border_gateway::util::NameResolver;

use std::env;
use std::str::FromStr;
use std::{collections::BTreeMap, fs};

use ruma::{serde::Base64, signatures::PublicKeyMap};
use simple_border_gateway::config::BorderGatewayConfig;
use simple_border_gateway::{
    inbound, outbound,
    util::{install_crypto_provider, shutdown_signal},
};

#[tokio::main]
async fn main() {
    println!("Starting simple-border-gateway");

    let app_log_level =
        log::LevelFilter::from_str(env::var("LOG_LEVEL").unwrap_or_default().as_str())
            .unwrap_or(log::LevelFilter::Info);

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

    let config_toml_str = fs::read_to_string("config.toml").expect("Failed to read config file");
    let config: BorderGatewayConfig =
        toml::from_str(&config_toml_str).expect("Failed to deserialize config file");

    debug!("Config file loaded");

    install_crypto_provider();

    debug!("Crypto provider installed");

    let mut domain_server_name_map = BTreeMap::new();
    let mut destination_base_urls: BTreeMap<String, String> = BTreeMap::new();

    for hs in config.internal_homeservers {
        domain_server_name_map.insert(hs.federation_domain.clone(), hs.server_name.clone());
        destination_base_urls.insert(hs.federation_domain, hs.destination_base_url);
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

    let server_name_resolver_inbound = NameResolver::new(domain_server_name_map);
    let server_name_resolver_outbound = server_name_resolver_inbound.clone();
    tasks.push(tokio::spawn(async move {
        inbound::create_proxy(
            &config.listen_address,
            server_name_resolver_inbound,
            shutdown_signal(),
            destination_base_urls,
            public_key_map,
        )
        .await
        .expect("Failed to create inbound proxy");
    }));

    info!("inbound_proxy initialized");

    if let Some(outbound_proxy) = config.outbound_proxy {
        tasks.push(tokio::spawn(async move {
            outbound::create_proxy(
                &outbound_proxy.listen_address,
                &outbound_proxy.ca_priv_key_path,
                &outbound_proxy.ca_cert_path,
                server_name_resolver_outbound,
                allowed_federation_domains,
                allowed_client_domains,
                outbound_proxy.allowed_non_matrix_regexes_dangerous,
                shutdown_signal(),
                outbound_proxy.upstream_proxy,
                None,
            )
            .await
            .expect("Failed to create outbound proxy");
        }));
        info!("outbound_proxy initialized");
    }

    for task in tasks {
        let _ = task.await;
    }
}
