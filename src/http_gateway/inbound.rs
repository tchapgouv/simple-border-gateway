use std::{collections::BTreeMap, net::SocketAddr};

use axum::{
    extract::{ConnectInfo, State},
    Router,
};
use tokio::net::TcpListener;
use tracing::Level;

use crate::http_gateway::{
    util::{extract_destination_host, shutdown_signal},
    GatewayDirection, GatewayError, GatewayHandler, RequestOrResponse,
};

#[derive(Clone)]
struct InboundGatewayState<H: GatewayHandler> {
    http_client: reqwest::Client,
    target_base_urls: BTreeMap<String, String>,
    handler: H,
}

pub struct InboundGatewayBuilder<H: GatewayHandler> {
    listen_address: SocketAddr,
    target_base_urls: BTreeMap<String, String>,
    handler: H,
    http_client: Option<reqwest::Client>,
    tracing_level: Option<Level>,
}

impl<H: GatewayHandler> InboundGatewayBuilder<H> {
    pub fn new(
        listen_address: SocketAddr,
        target_base_urls: BTreeMap<String, String>,
        handler: H,
    ) -> Self {
        Self {
            listen_address,
            target_base_urls,
            handler,
            http_client: None,
            tracing_level: None,
        }
    }

    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn with_tracing(mut self, level: Level) -> Self {
        self.tracing_level = Some(level);
        self
    }

    pub async fn build_and_run(self) -> Result<(), anyhow::Error> {
        let http_client = self.http_client.unwrap_or_default();

        let state = InboundGatewayState {
            http_client,
            target_base_urls: self.target_base_urls,
            handler: self.handler,
        };

        let listener = TcpListener::bind::<SocketAddr>(self.listen_address).await?;

        let mut router = Router::new();
        if let Some(level) = self.tracing_level {
            router = router.layer(
                tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(level))
                    .on_request(tower_http::trace::DefaultOnRequest::new().level(level))
                    .on_response(
                        tower_http::trace::DefaultOnResponse::new()
                            .level(level)
                            .include_headers(true),
                    ),
            );
        }
        router = router.fallback(inbound_handler::<H>);

        axum::serve(
            listener,
            router
                .with_state(state)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("Error starting inbound proxy: {}", e))
    }
}

async fn inbound_handler<H: GatewayHandler>(
    State(mut state): State<InboundGatewayState<H>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: http::Request<axum::body::Body>,
) -> http::Response<reqwest::Body> {
    let req = match convert_request(req) {
        Ok(req) => req,
        Err(e) => {
            return state
                .handler
                .handle_error(e, GatewayDirection::Inbound)
                .await
        }
    };
    let req_or_resp = state
        .handler
        .handle_request(req, GatewayDirection::Inbound, socket_addr)
        .await;
    match req_or_resp {
        RequestOrResponse::Request(req) => {
            let resp = forward_request(&mut state, req).await;
            state
                .handler
                .handle_response(resp, GatewayDirection::Inbound)
                .await
        }
        RequestOrResponse::Response(resp) => resp,
    }
}

async fn forward_request<H: GatewayHandler>(
    state: &mut InboundGatewayState<H>,
    req: http::Request<reqwest::Body>,
) -> http::Response<reqwest::Body> {
    let (parts, body) = req.into_parts();
    let dest_host = extract_destination_host(&parts, &GatewayDirection::Inbound);

    let Some(target_base_url) = state.target_base_urls.get(dest_host) else {
        return state
            .handler
            .handle_error(
                GatewayError::DestinationNotFound(dest_host.to_string()),
                GatewayDirection::Inbound,
            )
            .await;
    };

    let url = format!(
        "{target_base_url}{0}",
        parts.uri.path_and_query().map_or("", |p| p.as_str())
    );

    let req = match state
        .http_client
        .request(parts.method.clone(), url)
        .headers(parts.headers.clone())
        .body(body)
        .build()
    {
        Ok(req) => req,
        Err(e) => {
            return state
                .handler
                .handle_error(
                    GatewayError::ConvertRequest(Box::new(e)),
                    GatewayDirection::Inbound,
                )
                .await
        }
    };

    match state.http_client.execute(req).await {
        Ok(resp) => resp.into(),
        Err(e) => {
            return state
                .handler
                .handle_error(
                    GatewayError::Forward(Box::new(e)),
                    GatewayDirection::Inbound,
                )
                .await
        }
    }
}

fn convert_request(
    req: http::Request<axum::body::Body>,
) -> Result<http::Request<reqwest::Body>, GatewayError> {
    let mut builder = http::Request::builder().method(req.method()).uri(req.uri());
    for (name, value) in req.headers() {
        builder = builder.header(name, value);
    }

    builder
        .body(reqwest::Body::wrap_stream(
            req.into_body().into_data_stream(),
        ))
        .map_err(|e| GatewayError::ConvertRequest(Box::new(e)))
}
