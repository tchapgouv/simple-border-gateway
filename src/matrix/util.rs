use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use http::StatusCode;
use serde_json::{json, Value};
use ttl_cache::TtlCache;

use crate::http_gateway::util::{create_response, remove_default_https_port};

#[derive(Clone)]
pub struct NameResolver {
    domain_server_name_map: BTreeMap<String, String>,
    rdns_cache: Arc<RwLock<TtlCache<IpAddr, String>>>,
}

impl NameResolver {
    pub fn new(domain_server_name_map: BTreeMap<String, String>) -> Self {
        Self {
            domain_server_name_map,
            rdns_cache: Arc::new(RwLock::new(TtlCache::new(10000))),
        }
    }

    pub fn domain_to_server_name(&mut self, domain: &str) -> String {
        let domain = remove_default_https_port(domain);
        self.domain_server_name_map
            .get(domain)
            .unwrap_or(&domain.to_string())
            .clone()
    }

    pub fn ip_to_server_name(&mut self, ip: &IpAddr) -> String {
        let domain = self.ip_to_domain(ip);
        self.domain_to_server_name(&domain)
    }

    pub fn ip_to_domain(&mut self, ip: &IpAddr) -> String {
        #[allow(clippy::unwrap_used, reason = "rdns_cache should not be poisoned")]
        if let Some(cached_domain) = self.rdns_cache.read().unwrap().get(ip) {
            return cached_domain.clone();
        }

        // Let's still cache a bit even if we failed to lookup the rdns,
        // to not try again on each req
        let (domain, validity_minutes) = match dns_lookup::lookup_addr(ip) {
            Ok(domain) => (domain, 60),
            Err(_) => (ip.to_string(), 10),
        };
        #[allow(clippy::unwrap_used, reason = "rdns_cache should not be poisoned")]
        self.rdns_cache.write().unwrap().insert(
            *ip,
            domain.clone(),
            Duration::from_secs(validity_minutes * 60),
        );
        domain
    }
}

pub(crate) fn create_error_json(errcode: &str, error_msg: Option<&str>) -> Value {
    if let Some(error_msg_val) = error_msg {
        json!({"errcode": errcode, "error": error_msg_val})
    } else {
        json!({"errcode": errcode})
    }
}

pub(crate) fn create_matrix_response_with_msg<B: From<String>>(
    status: StatusCode,
    errcode: &str,
    error_msg: Option<&str>,
) -> Result<http::Response<B>, http::Error> {
    create_response(
        status,
        Some((
            B::from(create_error_json(errcode, error_msg).to_string()),
            "application/json",
        )),
    )
}

pub(crate) fn create_matrix_response<B: From<String>>(
    status: StatusCode,
    errcode: &str,
) -> http::Response<B> {
    #[allow(clippy::unwrap_used, reason = "no intrusted input")]
    create_matrix_response_with_msg(status, errcode, None).unwrap()
}
