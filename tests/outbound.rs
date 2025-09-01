use http::{Request, Response, StatusCode};
use rand::Rng;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use reqwest::{Body, Proxy};
use simple_border_gateway::http_gateway::outbound::OutboundGatewayBuilder;
use simple_border_gateway::http_gateway::{
    GatewayDirection, GatewayForwardError, GatewayHandler, RequestOrResponse,
};
use simple_border_gateway::matrix::util::NameResolver;
use simple_border_gateway::outbound::OutboundHandler;
use simple_border_gateway::util::{create_http_client, crypto_provider, install_crypto_provider};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;

fn set_req_scheme_and_authority<B>(req: &mut http::Request<B>, scheme: &str, authority: &str) {
    let parts = req.uri().clone().into_parts();
    let mut builder = http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority);
    if let Some(path_and_query) = parts.path_and_query {
        builder = builder.path_and_query(path_and_query);
    }
    *req.uri_mut() = builder.build().unwrap();
}

#[derive(Clone)]
struct HandlerWithMockServer {
    original_handler: OutboundHandler,
    mock_server_authority: String,
}

impl GatewayHandler for HandlerWithMockServer {
    async fn handle_request(
        &mut self,
        req: Request<Body>,
        _direction: GatewayDirection,
        _client_addr: SocketAddr,
    ) -> RequestOrResponse {
        let req = self
            .original_handler
            .handle_request(req, _direction, _client_addr)
            .await;
        if let RequestOrResponse::Request(mut req) = req {
            set_req_scheme_and_authority(&mut req, "http", &self.mock_server_authority);
            req.into()
        } else {
            req
        }
    }

    fn handle_response(
        &mut self,
        resp: Response<Body>,
        _direction: GatewayDirection,
    ) -> impl Future<Output = Response<Body>> + Send {
        self.original_handler.handle_response(resp, _direction)
    }

    fn handle_error(
        &mut self,
        err: GatewayForwardError,
        _direction: GatewayDirection,
    ) -> impl Future<Output = Response<Body>> + Send {
        self.original_handler.handle_error(err, _direction)
    }
}

async fn setup_mock_gateway(
    upstream_proxy_url: Option<String>,
) -> (httpmock::MockServer, reqwest::Client) {
    // env_logger::builder()
    //     .filter_level(log::LevelFilter::Info)
    //     .target(env_logger::Target::Stdout)
    //     .format_timestamp_micros()
    //     .init();

    install_crypto_provider();

    let mock_server = httpmock::MockServer::start();

    let original_handler = OutboundHandler::new(
        NameResolver::new(BTreeMap::new()),
        BTreeMap::from([(
            "federation.target.org".to_string(),
            "target.org".to_string(),
        )]),
        BTreeMap::from([("matrix.target.org".to_string(), "target.org".to_string())]),
        vec!["https://matrix\\.org/_matrix/push/v1/notify".to_string()],
    )
    .expect("Failed to create outbound handler");

    let handler = HandlerWithMockServer {
        original_handler,
        mock_server_authority: format!("localhost:{}", mock_server.port()),
    };

    let ca_key_pair = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

    let port = rand::rng().random_range(1024..65535);

    let ca_cert_pem = ca_cert.pem();

    let mut gateway_builder = OutboundGatewayBuilder::new(
        format!("127.0.0.1:{}", port).parse().unwrap(),
        ca_key_pair.serialize_pem(),
        ca_cert.pem(),
        crypto_provider::default_provider(),
        handler,
    );

    if let Some(upstream_proxy_url) = upstream_proxy_url {
        gateway_builder = gateway_builder
            .with_http_client(create_http_client(vec![], Some(upstream_proxy_url)).unwrap());
    }

    tokio::spawn(async move {
        gateway_builder
            .build_and_run()
            .await
            .expect("Failed to create outbound proxy");
    });

    let proxied_client = reqwest::Client::builder()
        .proxy(Proxy::all(format!("http://localhost:{}", port)).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    (mock_server, proxied_client)
}

#[tokio::test]
async fn test_invalid_endpoint() {
    let (_, client) = setup_mock_gateway(None).await;
    let response = client
        .get("https://federation.target.org/_matrix/federation/v1/invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_valid_federation_request() {
    let (mock_server, client) = setup_mock_gateway(None).await;

    let mut mock = mock_server.mock(|when, then| {
        when.method("GET")
            .path("/_matrix/federation/v1/query/profile");
        then.status(200);
    });

    let response = client
        .get("https://federation.target.org/_matrix/federation/v1/query/profile")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();

    mock.delete();
}

#[tokio::test]
async fn test_unauthorized_federation_request() {
    let (_, client) = setup_mock_gateway(None).await;

    let response = client
        .get("https://federation.unauthorized.org/_matrix/federation/v1/query/profile")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_valid_legacy_media_request() {
    let (mock_server, client) = setup_mock_gateway(None).await;

    let mut mock = mock_server.mock(|when, then| {
        when.method("GET")
            .path("/_matrix/media/v3/download/test.org/mediaId");
        then.status(200);
    });

    let response = client
        .get("https://matrix.target.org/_matrix/media/v3/download/test.org/mediaId")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();

    mock.delete();
}

#[tokio::test]
async fn test_unauthorized_legacy_media_request() {
    let (_, client) = setup_mock_gateway(None).await;

    let response = client
        .get("https://matrix.unauthorized.org/_matrix/media/v3/download/test.org/mediaId")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_valid_well_known_request() {
    let (mock_server, client) = setup_mock_gateway(None).await;

    let mut mock = mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200);
    });

    let response = client
        .get("https://target.org/.well-known/matrix/server")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();

    mock.delete();
}

#[tokio::test]
async fn test_unauthorized_well_known_request() {
    let (_, client) = setup_mock_gateway(None).await;

    let response = client
        .get("https://unauthorized.org/.well-known/matrix/server")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_allowed_non_matrix_regex() {
    let (mock_server, client) = setup_mock_gateway(None).await;

    let mut mock = mock_server.mock(|when, then| {
        when.method("GET").path("/_matrix/push/v1/notify");
        then.status(200);
    });

    let response = client
        .get("https://matrix.org/_matrix/push/v1/notify")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();

    mock.delete();
}
