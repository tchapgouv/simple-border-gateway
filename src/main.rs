mod inbound;
mod outbound;

mod config;
mod matrix_spec;
mod util;

use std::{collections::BTreeMap, fs};

use config::BorderGatewayConfig;
use ruma::{serde::Base64, signatures::PublicKeyMap};
use tracing::subscriber::NoSubscriber;
use util::{install_crypto_provider, shutdown_signal};

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    tracing::subscriber::set_global_default(NoSubscriber::new()).unwrap();

    let config_toml_str = fs::read_to_string("config.toml").expect("Failed to read config file");
    let config: BorderGatewayConfig =
        toml::from_str(&config_toml_str).expect("Failed to deserialize config file");

    install_crypto_provider();

    let mut destination_base_urls: BTreeMap<String, String> = BTreeMap::new();
    for hs in config.internal_homeservers {
        destination_base_urls.insert(hs.federation_domain, hs.destination_base_url);
    }

    let mut allowed_servernames: Vec<String> = Vec::new();
    let mut allowed_federation_domains: Vec<String> = Vec::new();
    let mut allowed_client_domains: Vec<String> = Vec::new();
    let mut public_key_map: PublicKeyMap = BTreeMap::new();

    for hs in config.external_homeservers {
        allowed_servernames.push(hs.server_name.clone());
        allowed_federation_domains.push(hs.federation_domain);
        allowed_client_domains.push(hs.client_domain);

        let mut verify_keys: BTreeMap<String, Base64> = BTreeMap::new();
        for (k, v) in hs.verify_keys {
            verify_keys.insert(
                k,
                Base64::parse(v).expect("Failed to parse verify key as base64"),
            );
        }
        public_key_map.insert(hs.server_name, verify_keys);
    }

    let mut tasks = vec![];

    tasks.push(tokio::spawn(async move {
        inbound::create_proxy(
            &config.listen_address,
            shutdown_signal(),
            destination_base_urls,
            public_key_map,
            config.allow_all_client_traffic,
        )
        .await;
    }));

    if let Some(outbound_proxy) = config.outbound_proxy {
        tasks.push(tokio::spawn(async move {
            outbound::create_proxy(
                &outbound_proxy.listen_address,
                &outbound_proxy.ca_priv_key_path,
                &outbound_proxy.ca_cert_path,
                allowed_servernames,
                allowed_federation_domains,
                allowed_client_domains,
                outbound_proxy.allowed_external_domains_dangerous,
                shutdown_signal(),
                outbound_proxy.upstream_proxy,
                None,
            )
            .await;
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}
