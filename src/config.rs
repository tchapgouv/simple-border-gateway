use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct InternalHomeserverConfig {
    pub server_name: String,
    pub federation_domain: String,
    pub destination_base_url: String,
}

#[derive(Deserialize, Serialize)]
pub struct ExternalHomeserverConfig {
    pub server_name: String,
    pub federation_domain: String,
    pub client_domain: String,
    pub verify_keys: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
pub struct UpstreamProxyConfig {
    pub url: String,
    pub auth: Option<UpstreamProxyAuth>,
    pub ca_pem: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct UpstreamProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Serialize)]
pub struct BorderGatewayConfig {
    #[serde(default = "default_border_gateway_listen_address")]
    pub listen_address: String,
    pub internal_homeservers: Vec<InternalHomeserverConfig>,
    pub external_homeservers: Vec<ExternalHomeserverConfig>,
    pub outbound_proxy: Option<OutboundProxyConfig>,
}

fn default_border_gateway_listen_address() -> String {
    "0.0.0.0:8000".to_string()
}

#[derive(Deserialize, Serialize)]
pub struct OutboundProxyConfig {
    #[serde(default = "default_outbound_proxy_listen_address")]
    pub listen_address: String,
    pub ca_priv_key_path: String,
    pub ca_cert_path: String,
    #[serde(default)]
    pub allowed_external_domains_dangerous: Vec<String>,
    pub upstream_proxy: Option<UpstreamProxyConfig>,
}

fn default_outbound_proxy_listen_address() -> String {
    "0.0.0.0:3128".to_string()
}
