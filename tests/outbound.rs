use http::StatusCode;
use rand::RngExt;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use reqwest::Proxy;
use simple_border_gateway::cli::Cli;
use simple_border_gateway::config::{
    BorderGatewayConfig, EndpointConfig, ExternalHomeserverConfig, OutboundProxyConfig,
    OverrideRuleConfig, RulesetConfig, UpstreamProxyConfig,
};
use simple_border_gateway::matrix::spec::{AuthType, EndpointType};
use simple_border_gateway::services::{prepare_services, spawn_services};
use simple_border_gateway::util::install_crypto_provider;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

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
                endpoint: "query_profile".to_string(),
                inbound_action: Some("allow".to_string()),
                outbound_action: Some("allow".to_string()),
            },
            OverrideRuleConfig {
                endpoint: "3pid_onbind".to_string(),
                inbound_action: Some("reject".to_string()),
                outbound_action: Some("reject".to_string()),
            },
            OverrideRuleConfig {
                endpoint: "legacy_media".to_string(),
                inbound_action: Some("allow".to_string()),
                outbound_action: Some("allow".to_string()),
            },
        ],
    }
}

async fn setup_mock_gateway(
    upstream_proxy_config: Option<UpstreamProxyConfig>,
    reject_all_by_default: bool,
) -> (httpmock::MockServer, reqwest::Client) {
    // env_logger::builder()
    //     .filter_level(log::LevelFilter::Info)
    //     .target(env_logger::Target::Stdout)
    //     .format_timestamp_micros()
    //     .init();

    install_crypto_provider();

    let mock_server = httpmock::MockServer::start();

    // The mock server's authority is used as the homeserver name, the federation domain and the
    // client domain. Requests are sent as plain HTTP so the outbound proxy forwards them straight
    // to the mock server, without any authority rewriting.
    let authority = mock_server.address().to_string();

    let ca_key_pair = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

    let port: u16 = rand::rng().random_range(1024..65535);

    let config = BorderGatewayConfig {
        internal_homeservers: vec![],
        external_homeservers: vec![ExternalHomeserverConfig {
            server_name: authority.clone(),
            federation_domain: authority.clone(),
            client_domain: authority.clone(),
            verify_keys: BTreeMap::new(),
            ruleset: Some("custom".to_string()),
        }],
        inbound_proxy: None,
        outbound_proxy: Some(OutboundProxyConfig {
            listen_address: format!("127.0.0.1:{port}"),
            additional_root_certs: vec![],
            upstream_proxy: upstream_proxy_config,
            // The CA is still parsed and the RcgenAuthority is still built when the service is
            // spawned; the requests themselves are plain HTTP and no longer exercise the TLS
            // interception handshake.
            ca_priv_key: ca_key_pair.serialize_pem(),
            ca_cert: ca_cert.pem(),
            hazmat_non_matrix_endpoints: vec![EndpointConfig {
                id: "webpush_mozilla".to_string(),
                // Reuse the mock server's authority so the outbound proxy forwards these requests
                // straight to the mock server. The path is restricted to /wpush/... so the
                // catch-all does not shadow the Matrix endpoints served by the same mock server.
                domain: Some(authority.clone()),
                path: "/wpush/{*anything}".to_string(),
                method: None,
                auth_type: AuthType::Unauthenticated,
                endpoint_type: EndpointType::Federation,
            }],
        }),
        rulesets: vec![custom_ruleset()],
    };

    let cli = Cli {
        log_level: None,
        inbound_only: false,
        outbound_only: false,
        config_file: PathBuf::from("config.toml"),
        reject_all_by_default,
    };

    let services = prepare_services(config, &cli).expect("Failed to prepare outbound service");
    spawn_services(services);
    wait_for_gateway(port).await;

    let proxied_client = reqwest::Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
        .build()
        .unwrap();

    (mock_server, proxied_client)
}

#[tokio::test]
async fn test_invalid_endpoint() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;
    let response = client
        .get(mock_server.url("/_matrix/federation/v1/invalid"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_valid_federation_request_but_unknown_endpoint() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let response = client
        .get(mock_server.url("/_matrix/federation/v1/query/avatar"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_valid_federation_request_from_rejected_whitelist() {
    let (mock_server, client) = setup_mock_gateway(None, true).await;

    // This endpoint is missing from the override ruleset, but it's part of the default ruleset
    // This should be rejected as the default ruleset is in reject all mode, with no override on this endpoint.
    let response = client
        .get(mock_server.url("/_matrix/federation/v1/query/directory"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// Test a custom endpoint added in the ruleset.
#[tokio::test]
async fn test_custom_endpoint() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/element_call");
        then.status(200);
    });

    // Should be accepted as it's an allowed custom endpoint
    let response = client
        .get(mock_server.url("/.well-known/matrix/element_call"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_valid_federation_request_from_rejected_whitelist_override() {
    let (mock_server, client) = setup_mock_gateway(None, true).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET")
            .path("/_matrix/federation/v1/query/profile");
        then.status(200);
    });

    // Despite the default ruleset being in reject all mode, this endpoint is explicitly allowed in the override ruleset, so it should be accepted.
    let response = client
        .get(mock_server.url("/_matrix/federation/v1/query/profile"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_valid_federation_request_from_default_whitelist() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET")
            .path("/_matrix/federation/v1/query/directory");
        then.status(200);
    });

    // This endpoint is missing from the override ruleset, but it's part of the default ruleset
    // This SHOULD be accepted.
    let response = client
        .get(mock_server.url("/_matrix/federation/v1/query/directory"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_valid_federation_request_but_rejected_endpoint() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let response = client
        .put(mock_server.url("/_matrix/federation/v1/3pid/onbind"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_valid_federation_request() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET")
            .path("/_matrix/federation/v1/query/profile");
        then.status(200);
    });

    let response = client
        .get(mock_server.url("/_matrix/federation/v1/query/profile"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_unauthorized_federation_request() {
    let (_mock_server, client) = setup_mock_gateway(None, false).await;

    let response = client
        .get("http://federation.unauthorized.org/_matrix/federation/v1/query/profile")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_valid_legacy_media_request() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET")
            .path("/_matrix/media/v3/download/test.org/mediaId");
        then.status(200);
    });

    let response = client
        .get(mock_server.url("/_matrix/media/v3/download/test.org/mediaId"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_unauthorized_legacy_media_request() {
    let (_mock_server, client) = setup_mock_gateway(None, false).await;

    let response = client
        .get("http://matrix.unauthorized.org/_matrix/media/v3/download/test.org/mediaId")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_valid_well_known_request() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200);
    });

    let response = client
        .get(mock_server.url("/.well-known/matrix/server"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_unauthorized_well_known_request() {
    let (_mock_server, client) = setup_mock_gateway(None, false).await;

    let response = client
        .get("http://unauthorized.org/.well-known/matrix/server")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_allowed_non_matrix_endpoint() {
    let (mock_server, client) = setup_mock_gateway(None, false).await;

    let mock = mock_server.mock(|when, then| {
        when.method("GET").path("/wpush/v1/id");
        then.status(200);
    });

    // /wpush/v1/id is not a Matrix endpoint, but it is declared as a non-matrix endpoint for the
    // mock server's authority, so it is allowed and forwarded to the mock server.
    let response = client
        .get(mock_server.url("/wpush/v1/id"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

#[tokio::test]
async fn test_non_matrix_endpoint_rejected_on_other_domain() {
    let (_, client) = setup_mock_gateway(None, false).await;

    // Same path, but a different destination domain than the one declared for the endpoint.
    let response = client
        .get("http://not-mozilla.org/wpush/v1/id")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_upstream_proxy() {
    let proxy_mock_server = httpmock::MockServer::start();

    let upstream_proxy = UpstreamProxyConfig {
        url: format!("http://{}", proxy_mock_server.address()),
        username: Some("proxyuser".to_string()),
        password: Some("proxypwd".to_string()),
    };

    let (mock_server, client) = setup_mock_gateway(Some(upstream_proxy), false).await;

    let mock = proxy_mock_server.mock(|when, then| {
        when.method("GET")
            .path("/_matrix/federation/v1/query/profile")
            // The credentials configured for the upstream proxy are sent as HTTP basic auth.
            // `cHJveHl1c2VyOnByb3h5cHdk` is the base64 encoding of `proxyuser:proxypwd`.
            .header("proxy-authorization", "Basic cHJveHl1c2VyOnByb3h5cHdk");
        then.status(200);
    });

    let response = client
        .get(mock_server.url("/_matrix/federation/v1/query/profile"))
        .send()
        .await
        .unwrap();

    // The response made it back through the upstream proxy.
    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}
