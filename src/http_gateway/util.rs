use std::net::{IpAddr, SocketAddr};

use http::StatusCode;

#[cfg(feature = "aws_lc_rs")]
pub use rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use rustls::crypto::ring as crypto_provider;

use crate::http_gateway::GatewayDirection;

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

pub async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

pub(crate) fn read_pem(path_or_content: &str) -> Result<String, anyhow::Error> {
    let bytes = if path_or_content.starts_with("----") {
        path_or_content.as_bytes().to_vec()
    } else {
        std::fs::read(path_or_content)?
    };
    Ok(String::from_utf8(bytes)?)
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

pub(crate) fn extract_destination_host<'a>(
    parts: &'a http::request::Parts,
    direction: &GatewayDirection,
) -> &'a str {
    let mut host = parts
        .uri
        .authority()
        .map(|a| a.as_str())
        .unwrap_or_default();
    if direction == &GatewayDirection::Inbound {
        if let Some(x_forwarded_host_header) = parts.headers.get("X-Forwarded-Host") {
            host = x_forwarded_host_header.to_str().unwrap_or_default();
        } else if let Some(host_header) = parts.headers.get("Host") {
            host = host_header.to_str().unwrap_or_default();
        }
    }
    remove_default_https_port(host)
}

pub(crate) fn extract_origin_ip(
    parts: &http::request::Parts,
    direction: &GatewayDirection,
    client_addr: &SocketAddr,
) -> IpAddr {
    let mut origin_ip = client_addr.ip();
    if direction == &GatewayDirection::Inbound {
        if let Some(x_forwarded_for) = parts.headers.get("X-Forwarded-For") {
            if let Ok(ip) = x_forwarded_for.to_str().unwrap_or_default().parse() {
                origin_ip = ip;
            }
        } else if let Some(forwarded) = parts.headers.get("Forwarded") {
            if let Ok(ip) = forwarded.to_str().unwrap_or_default().parse() {
                origin_ip = ip;
            }
        }
    }
    origin_ip
}

pub(crate) fn remove_default_https_port(host: &str) -> &str {
    if host.ends_with(":443") {
        host.split_at(host.len() - 4).0
    } else {
        host
    }
}

pub fn create_http_client(
    additional_root_certs: Vec<String>,
    upstream_proxy_url: Option<String>,
) -> Result<reqwest::Client, anyhow::Error> {
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(upstream_proxy_url) = upstream_proxy_url {
        builder = builder.proxy(reqwest::Proxy::all(upstream_proxy_url)?);
    }
    for cert in additional_root_certs {
        builder = builder
            .add_root_certificate(reqwest::Certificate::from_pem(read_pem(&cert)?.as_bytes())?);
    }
    // dns resolver dns overrides ?
    Ok(builder.build()?)
}

// TODO only for tests
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
