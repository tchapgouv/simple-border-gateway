mod inbound;
// mod outbound;

mod util;
mod config;
mod matrix_spec;

// mod membership;

use std::{collections::BTreeMap, fs};

use config::BorderGatewayConfig;
use ruma::{serde::Base64, signatures::PublicKeyMap};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();

    let config_toml_str = fs::read_to_string("config.toml").expect("Failed to read config file");
    let config: BorderGatewayConfig = toml::from_str(&config_toml_str).expect("Failed to deserialize config file");

    let mut destination_base_urls: BTreeMap<String, String> = BTreeMap::new();
    for hs in config.internal_homeservers {
        destination_base_urls.insert(hs.federation_domain, hs.destination_base_url);
    }

    let mut public_key_map: PublicKeyMap = BTreeMap::new();
    for hs in config.external_homeservers {
        let mut verify_keys :BTreeMap<String, Base64> = BTreeMap::new();
        for (k,v) in hs.verify_keys.iter() {
            verify_keys.insert(k.clone(), Base64::parse(v).expect("Failed to parse verify key as base64"));
        }
        public_key_map.insert(hs.server_name, verify_keys);
    }

    let inbound_proxy_task = tokio::spawn(async move {
        inbound::create_proxy(
            "0.0.0.0:9999",
            shutdown_signal(),
            destination_base_urls,
            public_key_map,
            config.allow_all_client_traffic.unwrap_or(false),
        )
        .await;
    });

    // let outbound_proxy_task = tokio::spawn(async move {
    //     outbound::create_proxy("0.0.0.0:3128", shutdown_signal()).await;
    // });

    // let _ = outbound_proxy_task.await;

    let _ = inbound_proxy_task.await;
}
