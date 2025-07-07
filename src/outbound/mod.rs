use std::collections::BTreeMap;

use handlers::GatewayHandler;

use hudsucker::Proxy;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{CertificateParams, KeyPair},
};

use crate::util::{read_pem, shutdown_signal, NameResolver};

mod handlers;

#[allow(clippy::too_many_arguments, reason = "parsed args from main")]
pub async fn create_proxy(
    listening_addr: &str,
    http_client: reqwest::Client,
    ca_priv_key: &str,
    ca_cert: &str,
    name_resolver: NameResolver,
    allowed_federation_domains: BTreeMap<String, String>,
    allowed_client_domains: BTreeMap<String, String>,
    allowed_external_domains_dangerous: Vec<String>,
    _for_tests_only_mock_server_host: Option<String>,
) -> Result<(), anyhow::Error> {
    let ca_private_key = read_pem(ca_priv_key)?;
    let ca_cert = read_pem(ca_cert)?;

    let key_pair = KeyPair::from_pem(ca_private_key.as_str())?;
    let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert.as_str())?.self_signed(&key_pair)?;

    let ca = RcgenAuthority::new(
        key_pair,
        ca_cert,
        1_000,
        crate::util::crypto_provider::default_provider(),
    );

    let builder = Proxy::builder()
        .with_addr(
            listening_addr
                .parse()
                .expect("Failed to parse listening address"),
        )
        .with_ca(ca)
        .with_rustls_client(crate::util::crypto_provider::default_provider());

    let proxy = builder
        .with_http_handler(GatewayHandler::new(
            http_client,
            name_resolver,
            allowed_federation_domains,
            allowed_client_domains,
            allowed_external_domains_dangerous,
            _for_tests_only_mock_server_host,
        )?)
        .with_graceful_shutdown(shutdown_signal())
        .build()?;

    Ok(proxy.start().await?)
}
