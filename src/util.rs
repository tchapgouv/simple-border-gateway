use std::net::SocketAddr;

use bytes::Bytes;
use http::{request::Parts, uri::Scheme};
use http_body_util::{BodyExt, Limited};
use log::{log, Level};
use regex::Regex;
use reqwest::Body;
use snafu::{ResultExt as _, Whatever};

use crate::{
    http_gateway::{
        util::{extract_destination_host, extract_origin_ip},
        GatewayDirection,
    },
    matrix::{
        spec::{Endpoint, ENDPOINTS},
        util::NameResolver,
    },
};

#[cfg(feature = "aws_lc_rs")]
pub use rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use rustls::crypto::ring as crypto_provider;

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

#[derive(Clone)]
pub(crate) struct RegexEndpoint {
    regex: Regex,
    endpoint: Endpoint,
}

#[allow(clippy::unwrap_used, reason = "lazy static regex")]
static REPLACE_VARIABLES_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new("\\{[^\\}]*}").unwrap());

impl RegexEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        // escape dots so they don't get interpreted
        let mut regex = endpoint.path.replace(".", "\\.");
        // replace variables in brackets with .*
        regex = REPLACE_VARIABLES_RE.replace_all(&regex, ".*").to_string();
        #[allow(
            clippy::unwrap_used,
            reason = " inputs statically defined in matrix_spec.rs"
        )]
        let regex = Regex::new(&regex).unwrap();
        RegexEndpoint { regex, endpoint }
    }
}

pub(crate) static REGEX_ALLOWED_ENDPOINTS: std::sync::LazyLock<Vec<RegexEndpoint>> =
    std::sync::LazyLock::new(|| Vec::from_iter(ENDPOINTS.map(RegexEndpoint::from)));

pub(crate) fn get_matching_endpoint<'a>(
    parts: &Parts,
    allowed_endpoints: &'a [RegexEndpoint],
) -> Option<&'a Endpoint> {
    for endpoint in allowed_endpoints {
        if endpoint.regex.is_match(parts.uri.to_string().as_str()) {
            if let Some(expected_method) = &endpoint.endpoint.method {
                if expected_method == parts.method {
                    return Some(&endpoint.endpoint);
                }
            } else {
                return Some(&endpoint.endpoint);
            }
        }
    }
    None
}

pub(crate) async fn to_bytes(body: Body, limit: usize) -> Option<Bytes> {
    Limited::new(body, limit)
        .collect()
        .await
        .map(|col| col.to_bytes())
        .ok()
}

pub(crate) struct RequestContext {
    pub(crate) parts: Parts,
    pub(crate) origin_server_name: String,
    pub(crate) destination_server_name: String,
    pub(crate) destination_host: String,
    log_prefix: String,
}

impl RequestContext {
    pub(crate) fn new(
        parts: Parts,
        direction: GatewayDirection,
        client_addr: SocketAddr,
        name_resolver: &mut NameResolver,
    ) -> Self {
        let origin_ip = extract_origin_ip(&parts, &direction, &client_addr);
        let destination_host = extract_destination_host(&parts, &direction).to_string();
        Self {
            parts,
            origin_server_name: name_resolver.ip_to_server_name(&origin_ip),
            destination_server_name: name_resolver.domain_to_server_name(&destination_host),
            destination_host,
            log_prefix: match direction {
                GatewayDirection::Inbound => "IN ",
                GatewayDirection::Outbound => "OUT",
            }
            .to_string(),
        }
    }

    pub(crate) fn log(&self, level: Level, msg: &str) {
        log!(
            level,
            "{0}: {1} -> {2} {3} {4} : {5}",
            self.log_prefix,
            self.origin_server_name,
            self.destination_server_name,
            self.parts.method,
            self.parts.uri.path_and_query().map_or("", |p| p.as_str()),
            msg,
        );
    }
}

#[allow(
    clippy::unwrap_used,
    reason = "we only remove default ports from a validated uri so no new untrusted input"
)]
pub(crate) fn remove_default_ports_from_uri(uri: http::Uri) -> String {
    let mut parts = uri.into_parts();
    if let Some(authority) = parts.authority.clone() {
        let host = authority.host().to_string();
        if let Some(port) = authority.port_u16() {
            if port == 443 && parts.scheme == Some(Scheme::HTTPS)
                || port == 80 && parts.scheme == Some(Scheme::HTTP)
            {
                parts.authority = Some(http::uri::Authority::from_maybe_shared(host).unwrap());
            }
        }
    }
    http::Uri::from_parts(parts).unwrap().to_string()
}

pub fn read_pem(path_or_content: &str) -> Result<String, Whatever> {
    let bytes = if path_or_content.starts_with("----") {
        path_or_content.as_bytes().to_vec()
    } else {
        std::fs::read(path_or_content).whatever_context("Failed to read PEM file")?
    };
    String::from_utf8(bytes).whatever_context("Failed to convert PEM content to UTF-8")
}

pub fn create_http_client(
    additional_root_certs: Vec<String>,
    upstream_proxy_url: Option<String>,
) -> Result<reqwest::Client, Whatever> {
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(upstream_proxy_url) = upstream_proxy_url {
        builder = builder.proxy(
            reqwest::Proxy::all(upstream_proxy_url)
                .whatever_context("Failed to create reqwest proxy config")?,
        );
    }
    for cert in additional_root_certs {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(
                read_pem(&cert)
                    .whatever_context("Failed to read PEM")?
                    .as_bytes(),
            )
            .whatever_context("Failed to parse PEM")?,
        );
    }
    // dns resolver dns overrides ?
    builder
        .build()
        .whatever_context("Failed to build reqwest client")
}
