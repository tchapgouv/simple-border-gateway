use std::{future::Future, sync::LazyLock};

use http::{header::HOST, StatusCode};
use httpmock::MockServer;
use hudsucker::RequestOrResponse;
use rcgen::{Certificate, CertificateParams, IsCa, KeyPair};
use tempfile::TempDir;
use tokio::{fs, sync::OnceCell};

use crate::{
    config::UpstreamProxyConfig, install_crypto_provider, outbound,
    util::set_req_authority_for_tests,
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

fn get_well_known_endpoint_mock(mock_server: &MockServer) -> httpmock::Mock {
    mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"m.server\": \"example.com:443\"}");
    })
}

async fn verify_well_known_response(response: reqwest::Response) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(body, "{\"m.server\": \"example.com:443\"}");
}

static PORT_BASE: u16 = 9000;

#[tokio::test]
async fn test_well_known_endpoint() {
    let temp_dir = tempfile::tempdir().unwrap();

    let mock_server = MockServer::start();
    let mock_server_host = mock_server.address().to_string();

    let client =
        create_outbound_proxy_and_client(&temp_dir, PORT_BASE, Some(mock_server_host), None).await;

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
        PORT_BASE + 1,
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

// #[tokio::test]
// async fn test_authenticated_request() {
//     install_crypto_provider();

//     let temp_dir = tempfile::tempdir().unwrap();
//     let gateway_ca_key_path = temp_dir.path().join("gateway_ca.key");
//     let gateway_ca_cert_path = temp_dir.path().join("gateway_ca.crt");

//     let gateway_certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
//     std::fs::write(&gateway_ca_key_path, gateway_certified_key.key_pair.serialize_pem()).unwrap();
//     std::fs::write(&gateway_ca_cert_path, gateway_certified_key.cert.pem()).unwrap();

//     // Start mock upstream server
//     let mock_server = httpmock::MockServer::start();
//     let mock = mock_server.mock(|when, then| {
//         when.method("GET")
//             .path("/_matrix/federation/v1/version")
//             .header("Host", "example.com")
//             .header_exists("Authorization");
//         then.status(200)
//             .header("content-type", "application/json")
//             .body("{\"server\": {\"name\": \"mock\", \"version\": \"0.1.0\"}}");
//     });

//     // Start upstream proxy that will receive requests
//     let upstream_proxy = tokio::spawn(async move {
//         let mock_server_url = mock_server.base_url();
//         let upstream = httpmock::MockServer::start();
//         upstream
//             .mock(|when, then| {
//                 when.any_request();
//                 then.status(200)
//                     .header("content-type", "application/json")
//                     .body_from_request(move |req| {
//                         // Forward the request to our mock server
//                         let client = reqwest::Client::new();
//                         let res = client
//                             .get(format!("{}{}", mock_server_url, req.path))
//                             .headers(req.headers.clone())
//                             .send()
//                             .unwrap();
//                         res.text().unwrap()
//                     });
//             })
//             .await;
//     });

//     let allowed_servernames = vec!["example.com".to_string()];
//     let allowed_federation_domains = vec!["example.com".to_string()];
//     let allowed_client_domains = vec!["example.com".to_string()];
//     let allowed_external_domains = vec![];

//     let _proxy = tokio::spawn(async move {
//         outbound::create_proxy(
//             "127.0.0.1:9997",
//             gateway_ca_key_path.to_str().unwrap(),
//             gateway_ca_cert_path.to_str().unwrap(),
//             allowed_servernames,
//             allowed_federation_domains,
//             allowed_client_domains,
//             allowed_external_domains,
//             crate::util::shutdown_signal(),
//             Some("http://127.0.0.1:9996".to_string()),
//             None,
//         )
//         .await;
//     });

//     tokio::time::sleep(std::time::Duration::from_millis(100)).await;

//     // Generate signing key
//     let key_pair = crypto_provider::default_provider()
//         .generate_signing_keypair()
//         .unwrap();

//     // Create client that will use our proxy
//     let client = reqwest::Client::builder()
//         .proxy(reqwest::Proxy::all("http://127.0.0.1:9997").unwrap())
//         .danger_accept_invalid_certs(true)
//         .build()
//         .unwrap();

//     // Build signed request
//     let request_method = "GET";
//     let request_uri = "/_matrix/federation/v1/version";
//     let origin = "example.com";
//     let destination = "example.com";

//     let mut signed_json = serde_json::json!({
//         "method": request_method,
//         "uri": request_uri,
//         "origin": origin,
//         "destination": destination
//     });

//     let signature = key_pair
//         .sign(serde_json::to_string(&signed_json).unwrap().as_bytes())
//         .unwrap();
//     let key_id = "ed25519:1";

//     signed_json["signatures"] = serde_json::json!({
//         origin: {
//             key_id: Base64::new(signature.to_vec())
//         }
//     });

//     let auth_header = format!("X-Matrix {}", signed_json.to_string());

//     let response = client
//         .get(format!("https://example.com{}", request_uri))
//         .header(HOST, "example.com")
//         .header("Authorization", auth_header)
//         .send()
//         .await
//         .unwrap();

//     assert_eq!(response.status(), StatusCode::OK);
//     mock.assert();

//     upstream_proxy.abort();
// }
