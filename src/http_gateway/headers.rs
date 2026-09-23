//! Reverse-proxy header handling.
//!
//! The gateway forwards messages between two separate HTTP connections, so it cannot
//! blindly relay every header field: some fields are meaningful for a single hop only,
//! while others exist precisely to describe what a proxy did. This module centralizes
//! that rewriting so the inbound (reverse) and outbound (forward) proxies behave
//! consistently, following RFC 9110.

use std::net::IpAddr;

use http::{
    HeaderMap, HeaderName, HeaderValue, Version,
    header::{CONNECTION, FORWARDED, HOST, VIA},
};

/// The `X-Forwarded-*` fields are only de facto standards (RFC 9110 §7.6.2 registers
/// `Forwarded`), so they are not available as constants in the `http` crate.
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// Header fields that are specific to a single transport connection and must therefore
/// not be forwarded by a proxy (RFC 9110 §7.6.1).
const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Rewrite the headers of a request that is about to be forwarded to an origin server.
///
/// * hop-by-hop fields (and the fields named by `Connection`) are dropped,
/// * `client_ip`, the address of the peer this proxy received the request from, is
///   appended to the forwarding chain (`X-Forwarded-For` and `Forwarded`),
/// * the original request is described by `X-Forwarded-Host`/`X-Forwarded-Proto`; a
///   value already set by an upstream proxy is preserved,
/// * this proxy is appended to `Via`,
/// * `Host` is set to `destination`, the authority of the request target, as required
///   when the request is retargeted to another origin (RFC 9110 §7.2).
///
/// `scheme` is the scheme of the original request when it is known; a reverse proxy
/// that receives an origin-form request target cannot determine it and should pass
/// `None`.
pub(crate) fn prepare_forwarded_request(
    gateway_name: &str,
    headers: &mut HeaderMap,
    version: Version,
    client_ip: IpAddr,
    scheme: Option<&str>,
    destination: Option<&str>,
) {
    remove_hop_by_hop_headers(headers);
    add_forwarding_headers(headers, client_ip, scheme, destination);
    add_via_header(headers, version, gateway_name);

    if let Some(destination) = destination
        && let Ok(value) = HeaderValue::from_str(destination)
    {
        headers.insert(HOST, value);
    }
}

/// Rewrite the headers of a response that is about to be forwarded to the client.
///
/// Only the hop-by-hop fields are dropped and this proxy is appended to `Via`; the
/// rest of the response is left untouched.
pub(crate) fn prepare_forwarded_response(
    gateway_name: &str,
    headers: &mut HeaderMap,
    version: Version,
) {
    remove_hop_by_hop_headers(headers);
    add_via_header(headers, version, gateway_name);
}

/// Remove the hop-by-hop header fields a proxy must not forward (RFC 9110 §7.6.1).
///
/// Fields named by the `Connection` header field are also removed, since they are
/// hop-by-hop for the connection on which they were received.
fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    // `get_all` borrows the map, so collect the names advertised as hop-by-hop by the
    // immediate peer before removing anything.
    let mut connection_listed = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(value) = value.to_str() else { continue };
        for name in value.split(',') {
            if let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) {
                connection_listed.push(name);
            }
        }
    }

    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    for name in connection_listed {
        headers.remove(&name);
    }
}

/// Append this proxy to the `Via` header field (RFC 9110 §7.6.3).
///
/// `version` is the protocol version of the message being forwarded; it is reported as
/// the `received-protocol`.
fn add_via_header(headers: &mut HeaderMap, version: Version, gateway_name: &str) {
    let received_protocol = match version {
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "1.1",
    };
    if let Ok(value) = HeaderValue::from_str(&format!("{received_protocol} {gateway_name}",)) {
        headers.append(VIA, value);
    }
}

/// Describe the original request for the downstream server.
fn add_forwarding_headers(
    headers: &mut HeaderMap,
    client_ip: IpAddr,
    scheme: Option<&str>,
    destination: Option<&str>,
) {
    // De facto `X-Forwarded-*` fields: the list of proxies is accumulated, while the
    // original host and scheme are only recorded by the first proxy, so an existing
    // value is kept as-is.
    append_list_value(headers, &X_FORWARDED_FOR, &client_ip.to_string());
    if !headers.contains_key(&X_FORWARDED_HOST)
        && let Some(destination) = destination
        && let Ok(value) = HeaderValue::from_str(destination)
    {
        headers.insert(&X_FORWARDED_HOST, value);
    }
    if !headers.contains_key(&X_FORWARDED_PROTO)
        && let Some(scheme) = scheme
        && let Ok(value) = HeaderValue::from_str(scheme)
    {
        headers.insert(&X_FORWARDED_PROTO, value);
    }

    // `Forwarded` is the standardized equivalent (RFC 9110 §7.6.2); each proxy appends
    // its own field-value, so the chain built by upstream proxies is preserved. IPv6
    // addresses must be quoted and enclosed in brackets.
    let mut forwarded = match client_ip {
        IpAddr::V4(ip) => format!("for={ip}"),
        IpAddr::V6(ip) => format!("for=\"[{ip}]\""),
    };
    if let Some(destination) = destination {
        forwarded.push_str(&format!(";host=\"{destination}\""));
    }
    if let Some(scheme) = scheme {
        forwarded.push_str(&format!(";proto={scheme}"));
    }
    if let Ok(value) = HeaderValue::from_str(&forwarded) {
        headers.append(FORWARDED, value);
    }
}

/// Append `value` to the comma-separated list held by `name`, creating the field when
/// it does not exist yet.
fn append_list_value(headers: &mut HeaderMap, name: &HeaderName, value: &str) {
    let combined = match headers
        .get(name)
        .and_then(|existing| existing.to_str().ok())
    {
        Some(existing) => format!("{existing}, {value}"),
        None => value.to_owned(),
    };
    if let Ok(value) = HeaderValue::from_str(&combined) {
        headers.insert(name, value);
    }
}
