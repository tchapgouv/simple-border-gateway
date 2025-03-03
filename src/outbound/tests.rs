use async_once::AsyncOnce;
use http::{header::HOST, StatusCode};
use httpmock::MockServer;
use lazy_static::lazy_static;
use rcgen::{CertificateParams, IsCa, KeyPair};
use tempfile::TempDir;
use tokio::fs;

use crate::outbound;

lazy_static! {
    static ref TEMP_DIR: TempDir = tempfile::tempdir().unwrap();
    static ref MOCK_SERVER: AsyncOnce<MockServer> =
        AsyncOnce::new(create_mock_server_and_proxy(&*TEMP_DIR));
}

async fn create_mock_server_and_proxy(temp_dir: &TempDir) -> MockServer {
    crate::util::install_crypto_provider();

    let mut params = CertificateParams::new(vec!["Test Root CA".to_string()]).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let keypair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&keypair).unwrap();
    let ca_cert = cert.pem();
    let ca_key = keypair.serialize_pem();

    let ca_cert_path = temp_dir.path().join("ca.crt");
    let ca_key_path = temp_dir.path().join("ca.key");

    fs::write(&ca_cert_path, ca_cert).await.unwrap();
    fs::write(&ca_key_path, ca_key).await.unwrap();

    let allowed_servernames = vec!["example.com".to_string()];
    let allowed_federation_domains = vec!["fed.example.com".to_string()];
    let allowed_client_domains = vec!["client.example.com".to_string()];
    let allowed_external_domains = vec![];

    let mock_server = MockServer::start();
    let mock_server_host = mock_server.address().to_string();

    tokio::spawn(async move {
        outbound::create_proxy(
            "127.0.0.1:9998",
            ca_key_path.to_str().unwrap(),
            ca_cert_path.to_str().unwrap(),
            allowed_servernames,
            allowed_federation_domains,
            allowed_client_domains,
            allowed_external_domains,
            crate::util::shutdown_signal(),
            None,
            Some(mock_server_host),
        )
        .await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    mock_server
}

#[tokio::test]
async fn test_well_known_endpoint() {
    let mock_server = MOCK_SERVER.get().await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"m.server\": \"example.com:443\"}");
    });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://127.0.0.1:9998").unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client
        .get("https://example.com/.well-known/matrix/server")
        .header(HOST, "example.com")
        .send()
        .await
        .unwrap();
    mock.assert();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(body, "{\"m.server\": \"example.com:443\"}");
}
