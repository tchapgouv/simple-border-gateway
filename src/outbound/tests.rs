use std::future::Future;

use http::header::HOST;
use httpmock::MockServer;
use hudsucker::RequestOrResponse;
use rcgen::{Certificate, CertificateParams, IsCa, KeyPair};
use tempfile::TempDir;
use tokio::fs;

use crate::{
    config::UpstreamProxyConfig, install_crypto_provider, outbound,
    tests_util::{
        get_well_known_endpoint_mock, set_req_authority_for_tests, verify_well_known_response,
    },
};

fn generate_self_signed_ca() -> (KeyPair, Certificate) {
    let mut params = CertificateParams::new(vec!["Test Root CA".to_string()]).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let keypair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&keypair).unwrap();
    (keypair, cert)
}

async fn create_outbound_proxy_and_client(
    temp_dir: &TempDir,
    port: u16,
    mock_server_host: Option<String>,
    upstream_proxy_config: Option<UpstreamProxyConfig>,
) -> reqwest::Client {
    install_crypto_provider();

    let (ca_keypair, ca_cert) = generate_self_signed_ca();

    let ca_cert_path = temp_dir.path().join("ca.crt");
    let ca_key_path = temp_dir.path().join("ca.key");

    fs::write(&ca_cert_path, ca_cert.pem()).await.unwrap();
    fs::write(&ca_key_path, ca_keypair.serialize_pem())
        .await
        .unwrap();

    let allowed_servernames = vec!["example.com".to_string()];
    let allowed_federation_domains = vec!["fed.example.com".to_string()];
    let allowed_client_domains = vec!["client.example.com".to_string()];
    let allowed_external_domains = vec![];

    tokio::spawn(async move {
        outbound::create_proxy(
            format!("127.0.0.1:{}", port).as_str(),
            ca_key_path.to_str().unwrap(),
            ca_cert_path.to_str().unwrap(),
            allowed_servernames,
            allowed_federation_domains,
            allowed_client_domains,
            allowed_external_domains,
            crate::util::shutdown_signal(),
            upstream_proxy_config,
            mock_server_host,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", port)).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    client
}

static OUTBOUND_PROXY_PORT_BASE: u16 = 9000;

#[tokio::test]
async fn test_well_known_endpoint() {
    let temp_dir = tempfile::tempdir().unwrap();

    let mock_server = MockServer::start();
    let mock_server_host = mock_server.address().to_string();

    let client = create_outbound_proxy_and_client(
        &temp_dir,
        OUTBOUND_PROXY_PORT_BASE,
        Some(mock_server_host),
        None,
    )
    .await;

    let mock = get_well_known_endpoint_mock(&mock_server);

    let response = client
        .get("https://example.com/.well-known/matrix/server")
        .header(HOST, "example.com")
        .send()
        .await
        .unwrap();
    mock.assert();

    verify_well_known_response(response).await;
}

#[derive(Clone)]
struct MockHudsuckerHandler {
    mock_server_host: String,
}

impl MockHudsuckerHandler {
    fn new(mock_server_host: String) -> Self {
        Self { mock_server_host }
    }
}
impl hudsucker::HttpHandler for MockHudsuckerHandler {
    fn handle_request(
        &mut self,
        _ctx: &hudsucker::HttpContext,
        mut _req: http::Request<hudsucker::Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        set_req_authority_for_tests(&mut _req, &self.mock_server_host);
        Box::pin(async { hudsucker::RequestOrResponse::Request(_req) })
    }
}

#[tokio::test]
async fn test_upstream_proxy_support() {
    let mock_server = MockServer::start();
    let mock_server_host = mock_server.address().to_string();

    let mock = get_well_known_endpoint_mock(&mock_server);

    let (upstream_proxy_keypair, upstream_proxy_ca_cert) = generate_self_signed_ca();
    let upstream_proxy_ca_pem = upstream_proxy_ca_cert.pem();

    let ca = hudsucker::certificate_authority::RcgenAuthority::new(
        upstream_proxy_keypair,
        upstream_proxy_ca_cert,
        1_000,
        crate::util::crypto_provider::default_provider(),
    );

    let proxy = hudsucker::Proxy::builder()
        .with_addr("127.0.0.1:3128".parse().unwrap())
        .with_ca(ca)
        .with_rustls_client(crate::util::crypto_provider::default_provider())
        .with_http_handler(MockHudsuckerHandler::new(mock_server_host))
        .build()
        .unwrap();

    let upstream_proxy = tokio::spawn(async move {
        proxy.start().await.unwrap();
    });

    let temp_dir = tempfile::tempdir().unwrap();

    let client = create_outbound_proxy_and_client(
        &temp_dir,
        OUTBOUND_PROXY_PORT_BASE + 1,
        Some("example.com".to_string()),
        Some(UpstreamProxyConfig {
            url: "http://127.0.0.1:3128".to_string(),
            ca_pem: Some(upstream_proxy_ca_pem),
        }),
    )
    .await;

    let response = client
        .get("https://example.com/.well-known/matrix/server")
        .header(HOST, "example.com")
        .send()
        .await
        .unwrap();

    mock.assert();

    verify_well_known_response(response).await;

    upstream_proxy.abort();
}
