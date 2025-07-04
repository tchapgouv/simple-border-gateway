use std::{collections::BTreeMap, fs, future::Pending};

use handlers::GatewayHandler;
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

use crate::{
    config::UpstreamProxyConfig,
    util::{shutdown_signal, NameResolver},
};

mod handlers;

#[allow(clippy::too_many_arguments, reason = "parsed args from main")]
pub async fn create_proxy(
    listening_addr: &str,
    ca_priv_key_path: &str,
    ca_cert_path: &str,
    name_resolver: NameResolver,
    allowed_federation_domains: BTreeMap<String, String>,
    allowed_client_domains: BTreeMap<String, String>,
    allowed_external_domains_dangerous: Vec<String>,
    upstream_proxy_config: Option<UpstreamProxyConfig>,
    _for_tests_only_mock_server_host: Option<String>,
) -> Result<(), anyhow::Error> {
    let proxy_builder = get_proxy_builder(listening_addr, ca_priv_key_path, ca_cert_path);

    let proxy = proxy_builder
        .with_http_handler(GatewayHandler::new(
            name_resolver,
            allowed_federation_domains,
            allowed_client_domains,
            allowed_external_domains_dangerous,
            upstream_proxy_config,
            _for_tests_only_mock_server_host,
        )?)
        .with_graceful_shutdown(shutdown_signal())
        .build()?;

    Ok(proxy.start().await?)
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
        .with_addr(
            listening_addr
                .parse()
                .expect("Failed to parse listening address"),
        )
        .with_ca(ca)
        .with_rustls_client(crate::util::crypto_provider::default_provider())
}
