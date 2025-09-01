use http::StatusCode;
use rand::Rng;
use reqwest::Body;
use ruma::serde::Base64;
use ruma::signatures::{sign_json, Ed25519KeyPair};
use ruma::CanonicalJsonValue;
use simple_border_gateway::http_gateway::inbound::InboundGatewayBuilder;
use simple_border_gateway::inbound::InboundHandler;
use simple_border_gateway::matrix::util::NameResolver;
use simple_border_gateway::util::install_crypto_provider;
use std::collections::BTreeMap;

async fn setup_mock_gateway() -> (httpmock::MockServer, u32, Ed25519KeyPair) {
    // env_logger::builder()
    //     .filter_level(log::LevelFilter::Debug)
    //     .target(env_logger::Target::Stdout)
    //     .format_timestamp_micros()
    //     .init();

    install_crypto_provider();

    let keypair =
        Ed25519KeyPair::from_der(&Ed25519KeyPair::generate().unwrap(), "test".to_owned()).unwrap();

    let public_key = keypair.public_key().to_vec();
    let key_id = format!("ed25519:{}", keypair.version());

    let mock_server = httpmock::MockServer::start();

    let mut target_base_urls = BTreeMap::new();
    target_base_urls.insert("target.org".to_string(), mock_server.base_url());

    let mut public_key_map: BTreeMap<String, BTreeMap<String, Base64>> = BTreeMap::new();
    let mut mock_server_key: BTreeMap<String, Base64> = BTreeMap::new();
    mock_server_key.insert(key_id.clone(), Base64::new(public_key.to_vec()));
    public_key_map.insert("origin.org".to_string(), mock_server_key);

    let handler = InboundHandler::new(NameResolver::new(BTreeMap::new()), public_key_map);

    let port = rand::rng().random_range(1024..65535);

    tokio::spawn(async move {
        InboundGatewayBuilder::new(
            format!("127.0.0.1:{}", port).parse().unwrap(),
            target_base_urls,
            handler,
        )
        .build_and_run()
        .await
        .expect("Failed to create inbound proxy");
    });

    (mock_server, port, keypair)
}

// Not working, error sometimes
// reqwest::Error { kind: Request, url: "http://localhost:39945/_matrix/federation/v1/query/profile", source: hyper_util::client::legacy::Error(SendRequest, hyper::Error(IncompleteMessage)) }
// lazy_static! {
//     static ref MOCK_GATEWAY: AsyncOnce<(httpmock::MockServer, u32, Ed25519KeyPair)> =
//         AsyncOnce::new(async { setup_mock_gateway().await });
// }

#[tokio::test]
async fn test_invalid_endpoint() {
    let (_, port, _) = setup_mock_gateway().await;
    let response = reqwest::Client::new()
        .get(format!(
            "http://localhost:{}/_matrix/federation/v1/invalid",
            port
        ))
        .header("X-Forwarded-Host", "target.org")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_unauthenticated_endpoint() {
    let (mock_server, port, _) = setup_mock_gateway().await;

    let mut mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200);
    });

    let response = reqwest::Client::new()
        .get(format!(
            "http://localhost:{}/.well-known/matrix/server",
            port
        ))
        .header("X-Forwarded-Host", "target.org")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();

    mock.delete();
}

fn sign_request(
    key_id: &str,
    keypair: &Ed25519KeyPair,
    method: &str,
    uri: &str,
    origin_name: &str,
    destination_name: &str,
) -> String {
    let mut request_map = BTreeMap::from([
        (
            "method".to_string(),
            CanonicalJsonValue::String(method.to_string()),
        ),
        (
            "uri".to_string(),
            CanonicalJsonValue::String(uri.to_string()),
        ),
        (
            "origin".to_string(),
            CanonicalJsonValue::String(origin_name.to_string()),
        ),
        (
            "destination".to_string(),
            CanonicalJsonValue::String(destination_name.to_string()),
        ),
    ]);

    sign_json(origin_name, keypair, &mut request_map).unwrap();

    let server_sigs = request_map["signatures"]
        .as_object()
        .unwrap()
        .get(origin_name)
        .unwrap();
    let signature = server_sigs
        .as_object()
        .unwrap()
        .get(key_id)
        .unwrap()
        .as_str()
        .unwrap();

    signature.to_string()
}

#[tokio::test]
async fn test_authenticated_endpoint_with_valid_request() {
    let (mock_server, port, keypair) = setup_mock_gateway().await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let mut mock = mock_server.mock(|when, then| {
        when.method(method).path(path);
        then.status(200);
    });

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        destination_name,
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = reqwest::Client::new()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        .header("X-Forwarded-Host", destination_name)
        .header("Authorization", auth_header.clone())
        .send()
        .await
        .unwrap();

    let status = response.status();

    assert_eq!(status, StatusCode::OK);
    mock.assert();

    mock.delete();
}

#[tokio::test]
async fn test_authenticated_endpoint_from_unauthorized_server() {
    let (_, port, keypair) = setup_mock_gateway().await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile";
    let origin_name = "unauthorized.org";
    let destination_name = "target.org";

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        destination_name,
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = reqwest::Client::new()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        .header("X-Forwarded-Host", destination_name)
        .header("Authorization", auth_header.clone())
        .send()
        .await
        .unwrap();

    let status = response.status();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_authenticated_endpoint_with_invalid_signature() {
    let (_, port, keypair) = setup_mock_gateway().await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        // This will make the signature invalid
        "wrong.org",
        destination_name,
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = reqwest::Client::new()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        .header("X-Forwarded-Host", destination_name)
        .header("Authorization", auth_header.clone())
        .send()
        .await
        .unwrap();

    let status = response.status();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_authenticated_endpoint_with_invalid_auth_header() {
    let (_, port, _) = setup_mock_gateway().await;

    let response = reqwest::Client::new()
        .get(format!(
            "http://localhost:{}/_matrix/federation/v1/query/profile",
            port
        ))
        .header("X-Forwarded-Host", "target.org")
        .header("Authorization", "X-Matrix wrong")
        .send()
        .await
        .unwrap();

    let status = response.status();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_authenticated_endpoint_without_auth_header() {
    let (_, port, _) = setup_mock_gateway().await;

    let response = reqwest::Client::new()
        .get(format!(
            "http://localhost:{}/_matrix/federation/v1/query/profile",
            port
        ))
        .header("X-Forwarded-Host", "target.org")
        .send()
        .await
        .unwrap();

    let status = response.status();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_authenticated_endpoint_with_non_utf8_body() {
    let (_, port, keypair) = setup_mock_gateway().await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "PUT";
    let path = "/_matrix/federation/v1/send/1234";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        destination_name,
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = reqwest::Client::new()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        .header("X-Forwarded-Host", destination_name)
        .header("Authorization", auth_header.clone())
        // Invalid UTF-8 code point
        .body(Body::from(vec![255]))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
