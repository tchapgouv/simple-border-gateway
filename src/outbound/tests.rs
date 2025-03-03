use http::{header::HOST, StatusCode};
use httpmock::MockServer;
use rcgen::{CertificateParams, IsCa, KeyPair};
use tokio::fs;

use crate::outbound;

#[tokio::test]
async fn test_well_known_endpoint() {
    // Install crypto provider for certificate generation
    crate::util::install_crypto_provider();

    // Generate a dynamic CA key and certificate
    let mut params = CertificateParams::new(vec!["Test Root CA".to_string()]).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let keypair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&keypair).unwrap();
    let ca_cert = cert.pem();
    let ca_key = keypair.serialize_pem();

    // Create temp files for CA cert and key
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_cert_path = temp_dir.path().join("ca.crt");
    let ca_key_path = temp_dir.path().join("ca.key");

    fs::write(&ca_cert_path, ca_cert).await.unwrap();
    fs::write(&ca_key_path, ca_key).await.unwrap();

    // Start a mock server to respond to the well-known request
    let mock_server = MockServer::start();

    let mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"m.server\": \"example.com:443\"}");
    });

    let allowed_servernames = vec!["example.com".to_string()];
    let allowed_federation_domains = vec!["fed.example.com".to_string()];
    let allowed_client_domains = vec!["client.example.com".to_string()];
    let allowed_external_domains = vec![];

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
            Some(mock_server_host),
        )
        .await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Test the well-known endpoint through the proxy
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

    println!("response: {:?}", response);
    mock.assert();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(body, "{\"m.server\": \"example.com:443\"}");
}
