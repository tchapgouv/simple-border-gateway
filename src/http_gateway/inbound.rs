use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    extract::{ConnectInfo, State},
};
use snafu::{ResultExt, Snafu};
use tokio::net::TcpListener;
use tracing::Level;

use crate::http_gateway::{
    GatewayDirection, GatewayForwardError, GatewayHandler, RequestOrResponse,
    util::{extract_destination_host, shutdown_signal},
};

#[derive(Debug, Snafu)]
#[snafu(display("Failed to bind inbound proxy"))]
pub struct InboundGatewayBindError {
    source: std::io::Error,
}

/// Shared, per-gateway state. It is wrapped in an [`Arc`] before being handed to axum,
/// so each request clones only an [`Arc`] handle instead of deep-cloning the whole state.
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

    pub async fn build_and_run(self) -> Result<(), InboundGatewayBindError> {
        let http_client = self.http_client.unwrap_or_default();

        let state = InboundGatewayState {
            http_client,
            target_base_urls: self.target_base_urls,
            handler: self.handler,
        };

        let listener = TcpListener::bind::<SocketAddr>(self.listen_address)
            .await
            .context(InboundGatewayBindSnafu)?;

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
                .with_state(Arc::new(state))
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context(InboundGatewayBindSnafu)
    }
}

async fn inbound_handler<H: GatewayHandler>(
    State(state): State<Arc<InboundGatewayState<H>>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: http::Request<axum::body::Body>,
) -> http::Response<reqwest::Body> {
    let req = convert_request(req);
    let req_or_resp = state
        .handler
        .handle_request(req, GatewayDirection::Inbound, socket_addr)
        .await;
    match req_or_resp {
        RequestOrResponse::Request(req) => {
            let resp = forward_request(&state, req).await;
            state
                .handler
                .handle_response(resp, GatewayDirection::Inbound)
                .await
        }
        RequestOrResponse::Response(resp) => resp,
    }
}

async fn forward_request<H: GatewayHandler>(
    state: &InboundGatewayState<H>,
    req: http::Request<reqwest::Body>,
) -> http::Response<reqwest::Body> {
    let (parts, body) = req.into_parts();
    let dest_host = extract_destination_host(&parts, &GatewayDirection::Inbound);

    let Some(target_base_url) = state.target_base_urls.get(&dest_host) else {
        return state
            .handler
            .handle_error(
                GatewayForwardError::DestinationNotFound {
                    host: dest_host.to_string(),
                },
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
                    GatewayForwardError::ConvertRequest {
                        source: Box::new(e),
                    },
                    GatewayDirection::Inbound,
                )
                .await;
        }
    };

    match state.http_client.execute(req).await {
        Ok(resp) => resp.into(),
        Err(e) => {
            return state
                .handler
                .handle_error(
                    GatewayForwardError::Forward {
                        source: Box::new(e),
                    },
                    GatewayDirection::Inbound,
                )
                .await;
        }
    }
}

fn convert_request(req: http::Request<axum::body::Body>) -> http::Request<reqwest::Body> {
    let (parts, body) = req.into_parts();
    http::Request::from_parts(
        parts,
        reqwest::Body::wrap_stream(body.into_data_stream()),
    )
}
