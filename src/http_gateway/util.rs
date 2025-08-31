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
