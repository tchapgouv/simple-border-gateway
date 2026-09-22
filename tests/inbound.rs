use http::StatusCode;
use rand::RngExt;
use reqwest::Body;
use ruma::CanonicalJsonValue;
use ruma::serde::Base64;
use ruma::signatures::{Ed25519KeyPair, sign_json};
use simple_border_gateway::cli::Cli;
use simple_border_gateway::config::{
    BorderGatewayConfig, EndpointConfig, ExternalHomeserverConfig, InboundProxyConfig,
    InternalHomeserverConfig, OverrideRuleConfig, RulesetConfig,
};
use simple_border_gateway::matrix::spec::{AuthType, EndpointType};
use simple_border_gateway::services::{prepare_services, spawn_services};
use simple_border_gateway::util::install_crypto_provider;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Build a client that ignores any ambient proxy configuration (e.g. HTTP_PROXY), so requests
/// reach the local gateway directly.
fn test_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// Wait until the gateway accepts connections on the given port.
async fn wait_for_gateway(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("gateway did not start listening on port {port}");
}

/// Minimal ruleset for the tests: adds a custom endpoint and overrides the actions of some default
/// endpoints.
fn custom_ruleset() -> RulesetConfig {
    RulesetConfig {
        name: "custom".to_string(),
        additional_endpoints: vec![EndpointConfig {
            id: "well_known_element_call".to_string(),
            path: "/.well-known/matrix/element_call".to_string(),
            method: Some("GET".to_string()),
            auth_type: AuthType::Unauthenticated,
            endpoint_type: EndpointType::WellKnown,
            domain: None,
        }],
        override_rules: vec![
            OverrideRuleConfig {
                endpoint: "well_known_element_call".to_string(),
                inbound_action: Some("allow".to_string()),
                outbound_action: Some("allow".to_string()),
            },
            OverrideRuleConfig {
                endpoint: "well_known_server".to_string(),
                inbound_action: Some("reject".to_string()),
                outbound_action: Some("reject".to_string()),
            },
            OverrideRuleConfig {
                endpoint: "query_profile".to_string(),
                inbound_action: Some("allow".to_string()),
                outbound_action: Some("allow".to_string()),
            },
            OverrideRuleConfig {
                endpoint: "key_v2_query_post".to_string(),
                inbound_action: Some("reject".to_string()),
                outbound_action: Some("reject".to_string()),
            },
            OverrideRuleConfig {
                endpoint: "send_transaction".to_string(),
                inbound_action: Some("allow".to_string()),
                outbound_action: Some("allow".to_string()),
            },
        ],
    }
}

async fn setup_mock_gateway(
    no_overridden_rules: bool,
    reject_all_by_default: bool,
) -> (httpmock::MockServer, u16, Ed25519KeyPair) {
    // env_logger::builder()
    //     .filter_level(log::LevelFilter::Debug)
    //     .target(env_logger::Target::Stdout)
    //     .format_timestamp_micros()
    //     .init();

    install_crypto_provider();

    let keypair = Ed25519KeyPair::from_der(&Ed25519KeyPair::generate(), "test".to_owned()).unwrap();

    let public_key = keypair.public_key().to_vec();
    let key_id = format!("ed25519:{}", keypair.version());
    let verify_key: Base64 = Base64::new(public_key);

    let mock_server = httpmock::MockServer::start();

    // An empty ruleset list means every homeserver falls back to the default ruleset.
    let rulesets = if no_overridden_rules {
        vec![]
    } else {
        vec![custom_ruleset()]
    };
    let ruleset_name = rulesets.first().map(|ruleset| ruleset.name.clone());

    let mut external_homeservers = vec![ExternalHomeserverConfig {
        server_name: "origin.org".to_string(),
        federation_domain: "federation.origin.org".to_string(),
        client_domain: "client.origin.org".to_string(),
        verify_keys: BTreeMap::from([(key_id.clone(), verify_key.encode())]),
        ruleset: ruleset_name.clone(),
    }];
    // Requests without an X-Matrix auth header get their origin server from a reverse lookup of
    // the client IP, which resolves to "localhost" for loopback requests. Attaching the ruleset
    // here exercises the "unknown server but known ruleset" path for those requests.
    external_homeservers.push(ExternalHomeserverConfig {
        server_name: "localhost".to_string(),
        federation_domain: "federation.localhost".to_string(),
        client_domain: "client.localhost".to_string(),
        verify_keys: BTreeMap::new(),
        ruleset: ruleset_name,
    });

    let port: u16 = rand::rng().random_range(1024..65535);

    let config = BorderGatewayConfig {
        internal_homeservers: vec![InternalHomeserverConfig {
            server_name: "target.org".to_string(),
            federation_domain: "target.org".to_string(),
            target_base_url: mock_server.base_url(),
        }],
        external_homeservers,
        inbound_proxy: Some(InboundProxyConfig {
            listen_address: format!("127.0.0.1:{port}"),
            additional_root_certs: vec![],
        }),
        outbound_proxy: None,
        rulesets,
    };

    let cli = Cli {
        log_level: None,
        inbound_only: false,
        outbound_only: false,
        config_file: PathBuf::from("config.toml"),
        reject_all_by_default,
    };

    let services = prepare_services(config, &cli).expect("Failed to prepare inbound service");
    spawn_services(services);
    wait_for_gateway(port).await;

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
    let (_, port, _) = setup_mock_gateway(false, false).await;
    let response = test_client()
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
async fn test_endpoint_postfix_anchor_violation() {
    let (mock_server, port, _) = setup_mock_gateway(true, false).await;

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile/_matrix/key/v2/server";
    let destination_name = "target.org";

    let mock = mock_server.mock(|when, then| {
        when.method(method).path(path);
        then.status(200);
    });

    let response = reqwest::Client::new()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        .header("X-Forwarded-Host", destination_name)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(mock.calls(), 0);
}

#[tokio::test]
async fn test_endpoint_prefix_anchor_violation() {
    let (mock_server, port, _) = setup_mock_gateway(true, false).await;

    let method = "GET";
    let path = "/prefix/_matrix/key/v2/server";
    let destination_name = "target.org";

    let mock = mock_server.mock(|when, then| {
        when.method(method).path(path);
        then.status(200);
    });

    let response = reqwest::Client::new()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        .header("X-Forwarded-Host", destination_name)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(mock.calls(), 0);
}

// Test a custom endpoint added in the ruleset.
// This endpoint is on purpose not part of the default ruleset.
#[tokio::test]
async fn test_custom_endpoint() {
    let (mock_server, port, _) = setup_mock_gateway(false, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/element_call");
        then.status(200);
    });

    let response = test_client()
        .get(format!(
            "http://localhost:{}/.well-known/matrix/element_call",
            port
        ))
        .header("X-Forwarded-Host", "target.org")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_unauthenticated_endpoint() {
    let (mock_server, port, _) = setup_mock_gateway(true, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200);
    });

    let response = test_client()
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
}

#[tokio::test]
async fn test_unauthenticated_endpoint_can_be_rejected_by_ruleset() {
    let (_, port, _) = setup_mock_gateway(false, false).await;

    let response = test_client()
        .get(format!(
            "http://localhost:{}/.well-known/matrix/server",
            port
        ))
        .header("X-Forwarded-Host", "target.org")
        .send()
        .await
        .expect("well-known request failed");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_reject_all_applies_to_unauthenticated_default_endpoint() {
    let (_, port, _) = setup_mock_gateway(true, true).await;

    let response = test_client()
        .get(format!(
            "http://localhost:{}/.well-known/matrix/server",
            port
        ))
        .header("X-Forwarded-Host", "target.org")
        .send()
        .await
        .expect("well-known request failed");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

fn sign_request(
    key_id: &str,
    keypair: &Ed25519KeyPair,
    method: &str,
    uri: &str,
    origin_name: &str,
    destination_name: Option<&str>,
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
    ]);
    if let Some(destination_name) = destination_name {
        request_map.insert(
            "destination".to_string(),
            CanonicalJsonValue::String(destination_name.to_string()),
        );
    }

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
// We have the reject all mode on, however, we also have an override that allows /_matrix/federation/v1/query/profile to go through.
// The result here should be a 200, as the gateway should let it through.
async fn test_authenticated_endpoint_with_override_ruleset() {
    let (mock_server, port, keypair) = setup_mock_gateway(false, true).await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let mock = mock_server.mock(|when, then| {
        when.method(method).path(path);
        then.status(200);
    });

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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
}

#[tokio::test]
// This check if the request is successfully bounced in case the server enforces the reject all by default mode.
async fn test_authenticated_endpoint_with_rejected_default_ruleset() {
    let (_, port, keypair) = setup_mock_gateway(true, true).await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/publicRooms";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_authenticated_endpoint_with_valid_request() {
    let (mock_server, port, keypair) = setup_mock_gateway(false, false).await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let mock = mock_server.mock(|when, then| {
        when.method(method).path(path);
        then.status(200);
    });

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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
}

#[tokio::test]
// A request signed for another homeserver must not be accepted, even if the signature itself is
// valid and the origin is allowed.
async fn test_authenticated_endpoint_with_mismatched_destination() {
    let (_, port, keypair) = setup_mock_gateway(false, false).await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile";
    let origin_name = "origin.org";
    // The request is signed for (and claims to be addressed to) another server...
    let destination_name = "other.org";

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        // ...but it is actually sent to the gateway addressed to another server.
        .header("X-Forwarded-Host", "target.org")
        .header("Authorization", auth_header.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
// Requests without a XMatrix destination field should be rejected.
async fn test_authenticated_endpoint_without_destination() {
    let (_, port, keypair) = setup_mock_gateway(false, false).await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "GET";
    let path = "/_matrix/federation/v1/query/profile";
    let origin_name = "origin.org";

    let signature = sign_request(&key_id, &keypair, method, path, origin_name, None);

    let auth_header = format!(
        "X-Matrix origin=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, key_id, signature
    );

    let response = test_client()
        .request(
            method.parse().unwrap(),
            format!("http://localhost:{}{}", port, path),
        )
        .header("X-Forwarded-Host", "target.org")
        .header("Authorization", auth_header.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// This test, although it's nearly identical to the unauthorized endpoint ones
// is supposed to pass as we only rely on the default ruleset. The default ruleset allows this endpoint.
#[tokio::test]
async fn test_authenticated_endpoint_with_default_ruleset() {
    let (mock_server, port, keypair) = setup_mock_gateway(true, false).await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "POST";
    let path = "/_matrix/key/v2/query";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let mock = mock_server.mock(|when, then| {
        when.method(method).path(path);
        then.status(200);
    });

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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
}

#[tokio::test]
async fn test_authenticated_endpoint_with_unauthorized_endpoint() {
    let (_, port, keypair) = setup_mock_gateway(false, false).await;
    let key_id = format!("ed25519:{}", keypair.version());

    let method = "POST";
    let path = "/_matrix/key/v2/query";
    let origin_name = "origin.org";
    let destination_name = "target.org";

    let signature = sign_request(
        &key_id,
        &keypair,
        method,
        path,
        origin_name,
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_authenticated_endpoint_from_unauthorized_server() {
    let (_, port, keypair) = setup_mock_gateway(false, false).await;
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
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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
    let (_, port, keypair) = setup_mock_gateway(false, false).await;
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
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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
    let (_, port, _) = setup_mock_gateway(false, false).await;

    let response = test_client()
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
    let (_, port, _) = setup_mock_gateway(false, false).await;

    let response = test_client()
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
    let (_, port, keypair) = setup_mock_gateway(false, false).await;
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
        Some(destination_name),
    );

    let auth_header = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin_name, destination_name, key_id, signature
    );

    let response = test_client()
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
