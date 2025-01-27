use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(crate) struct InternalHomeserver {
    pub(crate) server_name: String,
    pub(crate) federation_domain: String,
    pub(crate) destination_base_url:String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ExternalHomeserver {
    pub(crate) server_name: String,
    pub(crate) verify_keys: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BorderGatewayConfig {
    pub(crate) internal_homeservers: Vec<InternalHomeserver>,
    pub(crate) external_homeservers: Vec<ExternalHomeserver>,
    #[serde(default)]
    pub(crate) allow_all_client_traffic: bool,
    pub(crate) proxy_ca_key: String,
    pub(crate) proxy_ca_cert: String,
}