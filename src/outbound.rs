use std::{
    collections::HashSet,
    fs,
    future::{Future, Pending},
};

use http::Method;
use hudsucker::{
    builder::{ProxyBuilder, WantsHandlers},
    hyper_util::client::legacy::connect::Connect,
    NoopHandler,
};
use lazy_static::lazy_static;
use regex::Regex;

#[cfg(feature = "native-tls")]
use hudsucker::{
    certificate_authority::OpensslAuthority,
    openssl::{hash::MessageDigest, pkey::PKey, x509::X509},
};
#[cfg(feature = "rustls")]
use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{CertificateParams, KeyPair},
};
use hudsucker::{
    rustls::crypto::aws_lc_rs, Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};

use crate::{
    matrix_spec::{FederationEndpoint, FEDERATION_ENDPOINTS},
    util::create_forbidden_response,
};

#[derive(Clone)]
struct FederationRegexEndpoint {
    regex: Regex,
    endpoint: FederationEndpoint,
}

#[derive(Clone)]
struct LogHandler {
    federation_endpoints: Vec<FederationRegexEndpoint>,
    allowed_federation_domains: HashSet<String>,
    allowed_external_domains: HashSet<String>,
}

lazy_static! {
    static ref ENDPOINT_PATTERN_RE: Regex = Regex::new(".*({.*}).*").unwrap();
}

impl LogHandler {
    fn new(allowed_federation_domains: Vec<String>, allowed_external_domains: Vec<String>) -> Self {
        let mut federation_endpoints = Vec::new();
        for endpoint in FEDERATION_ENDPOINTS {
            let regex_str = ENDPOINT_PATTERN_RE.replace_all(&endpoint.path, "{.*}");
            let regex = Regex::new(&regex_str).expect("TODO");
            federation_endpoints.push(FederationRegexEndpoint { regex, endpoint });
        }

        LogHandler {
            federation_endpoints,
            allowed_federation_domains: HashSet::from_iter(allowed_federation_domains),
            allowed_external_domains: HashSet::from_iter(allowed_external_domains),
        }
    }

    fn is_valid_federation_request(&self, req: &http::Request<Body>) -> bool {
        for endpoint in self.federation_endpoints.clone() {
            if endpoint.regex.is_match(req.uri().to_string().as_str()) {
                if let Some(expected_method) = endpoint.endpoint.method {
                    if expected_method == req.method() {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
        return false;
    }
}

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: http::Request<Body>,
    ) -> RequestOrResponse {
        if req.method() != Method::CONNECT {
            if self
                .allowed_external_domains
                .contains(req.uri().host().unwrap_or(""))
            {
                return req.into();
            }
            if self
                .allowed_federation_domains
                .contains(req.uri().host().unwrap_or(""))
                && self.is_valid_federation_request(&req)
            {
                return req.into();
            }
            create_forbidden_response("M_FORBIDDEN", None).into()
        } else {
            req.into()
        }
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: http::Response<Body>,
    ) -> http::Response<Body> {
        res
    }
}

pub(crate) async fn create_proxy<F>(
    listening_addr: &str,
    ca_priv_key_path: &str,
    ca_cert_path: &str,
    allowed_federation_domains: Vec<String>,
    allowed_external_domains: Vec<String>,
    shutdown_signal: F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let proxy_builder = get_proxy_builder(listening_addr, ca_priv_key_path, ca_cert_path);

    let proxy = proxy_builder
        .with_http_handler(LogHandler::new(
            allowed_federation_domains,
            allowed_external_domains,
        ))
        .with_graceful_shutdown(shutdown_signal)
        .build()
        .expect("Failed to build proxy");

    let res = proxy.start().await;
    if res.is_err() {
        println!("error outbound proxy start {:?}", res.err());
    }
}

#[cfg(feature = "native-tls")]
pub(crate) fn get_proxy_builder(
    listening_addr: &str,
    ca_priv_key_path: &str,
    ca_cert_path: &str,
) -> ProxyBuilder<
    WantsHandlers<OpensslAuthority, impl Connect + Clone, NoopHandler, NoopHandler, Pending<()>>,
> {
    let ca_private_key_bytes =
        fs::read(ca_priv_key_path).expect("Failed to read CA private key file");
    let ca_cert_bytes = fs::read(ca_cert_path).expect("Failed to read CA certificate file");

    let private_key = PKey::private_key_from_pem(ca_private_key_bytes.as_slice())
        .expect("Failed to parse private key");
    let ca_cert = X509::from_pem(ca_cert_bytes.as_slice()).expect("Failed to parse CA certificate");

    let ca = OpensslAuthority::new(
        private_key,
        ca_cert,
        MessageDigest::sha256(),
        1_000,
        aws_lc_rs::default_provider(),
    );

    Proxy::builder()
        .with_addr(listening_addr.parse().unwrap())
        .with_ca(ca)
        .with_native_tls_client()
}

#[cfg(feature = "rustls")]
pub(crate) fn get_proxy_builder(
    listening_addr: &str,
    ca_priv_key_path: &str,
    ca_cert_path: &str,
) -> ProxyBuilder<
    WantsHandlers<RcgenAuthority, impl Connect + Clone, NoopHandler, NoopHandler, Pending<()>>,
> {
    let ca_private_key =
        fs::read_to_string(ca_priv_key_path).expect("Failed to read CA private key file");
    let ca_cert = fs::read_to_string(ca_cert_path).expect("Failed to read CA certificate file");

    let key_pair =
        KeyPair::from_pem(ca_private_key.as_str()).expect("Failed to parse CA private key");
    let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert.as_str())
        .expect("Failed to parse CA certificate")
        .self_signed(&key_pair)
        .expect("Failed to sign CA certificate");

    let ca = RcgenAuthority::new(key_pair, ca_cert, 1_000, aws_lc_rs::default_provider());

    Proxy::builder()
        .with_addr(listening_addr.parse().unwrap())
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
}
