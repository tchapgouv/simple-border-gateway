use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use log::{log, Level};
use regex::Regex;
use serde_json::{json, Value};
use ttl_cache::TtlCache;

use crate::config::UpstreamProxyConfig;

#[cfg(feature = "aws_lc_rs")]
pub use hudsucker::rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use hudsucker::rustls::crypto::ring as crypto_provider;

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

pub async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

pub(crate) fn create_http_client(
    upstream_proxy_config: Option<UpstreamProxyConfig>,
) -> Result<reqwest::Client, reqwest::Error> {
    install_crypto_provider();
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(upstream_proxy_config) = upstream_proxy_config {
        let mut proxy_config = reqwest::Proxy::all(upstream_proxy_config.url)?;
        if let Some(auth) = upstream_proxy_config.auth {
            proxy_config = proxy_config.basic_auth(auth.username.as_str(), auth.password.as_str());
        }
        builder = builder.proxy(proxy_config);
        if let Some(ca_pem) = upstream_proxy_config.ca_pem {
            builder =
                builder.add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes())?);
        }
        // dns resolver dns overrides ?
    }
    builder.build()
}

pub(crate) fn create_response<B: From<String>>(
    status: StatusCode,
    body_and_content_type: Option<(B, &str)>,
) -> Result<http::Response<B>, http::Error> {
    let builder = http::Response::builder().status(status);
    if let Some((body, content_type)) = body_and_content_type {
        return builder.header("Content-Type", content_type).body(body);
    }
    builder.body(B::from("".to_string()))
}

pub(crate) fn create_status_response<B: From<String>>(status: StatusCode) -> http::Response<B> {
    #[allow(clippy::unwrap_used, reason = "no intrusted input")]
    create_response(status, None).unwrap()
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

pub fn set_req_scheme_and_authority<B>(req: &mut http::Request<B>, scheme: &str, authority: &str) {
    let parts = req.uri().clone().into_parts();
    let mut builder = http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority);
    if let Some(path_and_query) = parts.path_and_query {
        builder = builder.path_and_query(path_and_query);
    }
    #[allow(clippy::unwrap_used, reason = "should never happen")]
    let uri = builder.build().unwrap();
    *req.uri_mut() = uri;
}

pub(crate) fn normalize_uri(uri: &http::Uri) -> String {
    let uri_str = uri.to_string();
    match fluent_uri::Uri::parse(uri_str.clone()) {
        Ok(fluent_uri) => fluent_uri.normalize().to_string(),
        Err(_) => uri_str,
    }
}

#[allow(clippy::unwrap_used, reason = "lazy static regex")]
static REMOVE_DEFAULT_PORTS_REGEX: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(:443|:80)$").unwrap());

pub(crate) fn remove_default_ports(host: &str) -> String {
    REMOVE_DEFAULT_PORTS_REGEX.replace_all(host, "").to_string()
}

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
        let domain = remove_default_ports(domain);
        self.domain_server_name_map
            .get(domain.as_str())
            .unwrap_or(&domain)
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

fn extract_origin_and_destination<B>(
    req: &Request<B>,
    socket_addr: SocketAddr,
    name_resolver: &mut NameResolver,
) -> (String, String) {
    let origin = if let Some(x_forwarded_for) = req.headers().get("X-Forwarded-For") {
        x_forwarded_for.to_str().unwrap_or_default().to_string()
    } else {
        name_resolver.ip_to_server_name(&socket_addr.ip())
    };

    let destination = if let Some(x_forwarded_host) = req.headers().get("X-Forwarded-Host") {
        x_forwarded_host.to_str().unwrap_or_default()
    } else if let Some(host) = req.headers().get("Host") {
        host.to_str().unwrap_or_default()
    } else {
        ""
    };

    (
        remove_default_ports(origin.as_str()),
        remove_default_ports(destination),
    )
}

pub(crate) struct ReqContext {
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) headers: HeaderMap,

    pub(crate) origin: String,
    pub(crate) destination: String,

    log_prefix: String,
    http_client: reqwest::Client,
    name_resolver: NameResolver,
}

impl ReqContext {
    pub(crate) fn new<B>(
        req: &Request<B>,
        socket_addr: SocketAddr,
        http_client: reqwest::Client,
        mut name_resolver: NameResolver,
        log_prefix: String,
    ) -> Self {
        let (origin, destination) =
            extract_origin_and_destination(req, socket_addr, &mut name_resolver);

        Self {
            method: req.method().clone(),
            uri: req.uri().clone(),
            headers: req.headers().clone(),
            origin,
            destination,
            log_prefix,
            http_client,
            name_resolver,
        }
    }

    pub(crate) async fn forward_request<S>(
        &mut self,
        body_stream: S,
        dest_base_url: Option<&str>,
    ) -> http::Response<reqwest::Body>
    where
        S: futures::stream::TryStream + Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        Bytes: From<S::Ok>,
    {
        let url = if let Some(dest_base_url) = dest_base_url {
            format!("{dest_base_url}{0}", self.path_and_query())
        } else {
            self.uri.to_string()
        };
        let http_res = self
            .http_client
            .request(self.method.clone(), url)
            .headers(self.headers.clone())
            .body(reqwest::Body::wrap_stream(body_stream))
            .send()
            .await;

        match http_res {
            Ok(http_res) => http_res.into(),
            Err(e) => {
                self.log(Level::Warn, &format!("503 - error forwarding: {e}"));
                create_status_response(StatusCode::BAD_GATEWAY)
            }
        }
    }

    pub(crate) fn path_and_query(&self) -> &str {
        self.uri.path_and_query().map_or("", |p| p.as_str())
    }

    pub(crate) fn log(&mut self, level: Level, msg: &str) {
        log!(
            level,
            "{0}: {1} -> {2} {3} {4} : {5}",
            self.log_prefix,
            self.name_resolver.domain_to_server_name(&self.origin),
            self.name_resolver.domain_to_server_name(&self.destination),
            self.method,
            self.path_and_query(),
            msg
        );
    }
}
