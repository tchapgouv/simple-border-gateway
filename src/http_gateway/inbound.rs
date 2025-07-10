use std::{collections::BTreeMap, net::SocketAddr};

use axum::{
    extract::{ConnectInfo, State},
    Router,
};
use tokio::net::TcpListener;
use tracing::Level;

use crate::http_gateway::{
    util::shutdown_signal, GatewayDirection, GatewayError, GatewayHandler, RequestOrResponse,
};

#[derive(Clone)]
struct InboundGatewayState<H: GatewayHandler> {
    http_client: reqwest::Client,
    destination_base_urls: BTreeMap<String, String>,
    handler: H,
}

pub struct InboundGatewayBuilder<H: GatewayHandler> {
    listen_address: SocketAddr,
    destination_base_urls: BTreeMap<String, String>,
    handler: H,
    http_client: Option<reqwest::Client>,
}

impl<H: GatewayHandler> InboundGatewayBuilder<H> {
    pub fn new(
        listen_address: SocketAddr,
        destination_base_urls: BTreeMap<String, String>,
        handler: H,
    ) -> Self {
        Self {
            listen_address,
            destination_base_urls,
            handler,
            http_client: None,
        }
    }

    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub async fn build_and_run(self) -> Result<(), anyhow::Error> {
        let http_client = self.http_client.unwrap_or_default();

        let state = InboundGatewayState {
            http_client,
            destination_base_urls: self.destination_base_urls,
            handler: self.handler,
        };

        let listener = TcpListener::bind::<SocketAddr>(self.listen_address).await?;

        let router = Router::new()
            // TODO useful ?
            .layer(
                tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::TRACE))
                    .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::TRACE)),
            )
            .fallback(inbound_handler::<H>);

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
    // TODO handle destination base urls
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
        RequestOrResponse::Request(req) => forward_request(&mut state, req).await,
        RequestOrResponse::Response(resp) => {
            state
                .handler
                .handle_response(resp, GatewayDirection::Inbound)
                .await
        }
    }
}

async fn forward_request<H: GatewayHandler>(
    state: &mut InboundGatewayState<H>,
    req: http::Request<reqwest::Body>,
) -> http::Response<reqwest::Body> {
    match req.try_into() {
        Ok(req) => match state.http_client.execute(req).await {
            Ok(resp) => resp.into(),
            Err(e) => {
                return state
                    .handler
                    .handle_error(
                        GatewayError::Forward(e.to_string()),
                        GatewayDirection::Inbound,
                    )
                    .await
            }
        },
        Err(e) => {
            return state
                .handler
                .handle_error(
                    GatewayError::ConvertRequest(e.to_string()),
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
        .map_err(|e| GatewayError::ConvertRequest(e.to_string()))
}
