use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(crate) struct InternalHomeserverConfig {
    pub(crate) server_name: String,
    pub(crate) federation_domain: String,
    pub(crate) destination_base_url: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ExternalHomeserverConfig {
    pub(crate) server_name: String,
    pub(crate) federation_domain: String,
    pub(crate) client_domain: String,
    pub(crate) verify_keys: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct UpstreamProxyConfig {
    pub(crate) url: String,
    pub(crate) ca_pem: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BorderGatewayConfig {
    #[serde(default = "default_border_gateway_listen_address")]
    pub(crate) listen_address: String,
    pub(crate) internal_homeservers: Vec<InternalHomeserverConfig>,
    pub(crate) external_homeservers: Vec<ExternalHomeserverConfig>,
    pub(crate) outbound_proxy: Option<OutboundProxyConfig>,
}

fn default_border_gateway_listen_address() -> String {
    "0.0.0.0:8000".to_string()
}

#[derive(Deserialize, Serialize)]
pub(crate) struct OutboundProxyConfig {
    #[serde(default = "default_outbound_proxy_listen_address")]
    pub(crate) listen_address: String,
    pub(crate) ca_priv_key_path: String,
    pub(crate) ca_cert_path: String,
    #[serde(default)]
    pub(crate) allowed_external_domains_dangerous: Vec<String>,
    pub(crate) upstream_proxy: Option<UpstreamProxyConfig>,
}

fn default_outbound_proxy_listen_address() -> String {
    "0.0.0.0:3128".to_string()
}
