use std::{
    fs,
    future::{Future, Pending},
};

use handlers::LogHandler;
use hudsucker::{
    builder::{ProxyBuilder, WantsHandlers},
    hyper_util::client::legacy::connect::Connect,
    NoopHandler,
};

use hudsucker::Proxy;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{CertificateParams, KeyPair},
};

use crate::config::UpstreamProxyConfig;

mod handlers;

#[allow(clippy::too_many_arguments)]
pub async fn create_proxy<F>(
    listening_addr: &str,
    ca_priv_key_path: &str,
    ca_cert_path: &str,
    allowed_servernames: Vec<String>,
    allowed_federation_domains: Vec<String>,
    allowed_client_domains: Vec<String>,
    allowed_external_domains_dangerous: Vec<String>,
    shutdown_signal: F,
    upstream_proxy_config: Option<UpstreamProxyConfig>,
    _for_tests_only_mock_server_host: Option<String>,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let proxy_builder = get_proxy_builder(listening_addr, ca_priv_key_path, ca_cert_path);

    let proxy = proxy_builder
        .with_http_handler(LogHandler::new(
            allowed_servernames,
            allowed_federation_domains,
            allowed_client_domains,
            allowed_external_domains_dangerous,
            upstream_proxy_config,
            _for_tests_only_mock_server_host,
        ))
        .with_graceful_shutdown(shutdown_signal)
        .build()
        .expect("Failed to build proxy");

    let res = proxy.start().await;
    if res.is_err() {
        println!("error outbound proxy start {:?}", res.err());
    }
}

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

    let ca = RcgenAuthority::new(
        key_pair,
        ca_cert,
        1_000,
        crate::util::crypto_provider::default_provider(),
    );

    Proxy::builder()
        .with_addr(listening_addr.parse().unwrap())
        .with_ca(ca)
        .with_rustls_client(crate::util::crypto_provider::default_provider())
}
