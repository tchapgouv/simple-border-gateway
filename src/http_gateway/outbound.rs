use std::net::SocketAddr;

use http::Method;
use http_body_util::BodyExt as _;
use hudsucker::{certificate_authority::RcgenAuthority, Proxy};
use log::error;
use rcgen::{CertificateParams, KeyPair};
use rustls::crypto::CryptoProvider;
use snafu::ResultExt;

use crate::http_gateway::{
    util::{create_status_response, shutdown_signal},
    ConvertRequestSnafu, ConvertResponseSnafu, GatewayCreateError, GatewayCreateSnafu,
    GatewayDirection, GatewayForwardError, GatewayHandler, RequestOrResponse,
};

pub struct OutboundGatewayBuilder<H: GatewayHandler> {
    listen_address: SocketAddr,
    ca_private_key: String,
    ca_certificate: String,
    crypto_provider: CryptoProvider,
    http_client: reqwest::Client,

    handler: H,
}

impl<H: GatewayHandler> OutboundGatewayBuilder<H> {
    pub fn new(
        listen_address: SocketAddr,
        ca_private_key: String,
        ca_certificate: String,
        crypto_provider: CryptoProvider,
        handler: H,
    ) -> Self {
        Self {
            listen_address,
            ca_private_key,
            ca_certificate,
            crypto_provider,
            handler,
            http_client: reqwest::Client::new(),
        }
    }

    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = http_client;
        self
    }

    pub async fn build_and_run(self) -> Result<(), GatewayCreateError> {
        let key_pair = KeyPair::from_pem(self.ca_private_key.as_str())
            .boxed()
            .context(GatewayCreateSnafu)?;
        let ca_cert = CertificateParams::from_ca_cert_pem(self.ca_certificate.as_str())
            .boxed()
            .context(GatewayCreateSnafu)?
            .self_signed(&key_pair)
            .boxed()
            .context(GatewayCreateSnafu)?;

        let crypto_provider = self.crypto_provider;

        let ca = RcgenAuthority::new(key_pair, ca_cert, 1_000, crypto_provider.clone());

        let builder = Proxy::builder()
            .with_addr(self.listen_address)
            .with_ca(ca)
            .with_rustls_client(crypto_provider);

        let proxy = builder
            .with_http_handler(HandlerAdapter::new(self.handler, self.http_client))
            .with_graceful_shutdown(shutdown_signal())
            .build()
            .boxed()
            .context(GatewayCreateSnafu)?;

        proxy.start().await.boxed().context(GatewayCreateSnafu)
    }
}

#[derive(Clone)]
struct HandlerAdapter<H: GatewayHandler> {
    handler: H,
    http_client: reqwest::Client,
}

impl<H: GatewayHandler> HandlerAdapter<H> {
    pub fn new(handler: H, http_client: reqwest::Client) -> Self {
        Self {
            handler,
            http_client,
        }
    }
}

impl<H: GatewayHandler> hudsucker::HttpHandler for HandlerAdapter<H> {
    // We never return a request here, otherwise hudsucker will execute
    // the request itself and our http_client will not be used.
    async fn handle_request(
        &mut self,
        ctx: &hudsucker::HttpContext,
        req: http::Request<hudsucker::Body>,
    ) -> hudsucker::RequestOrResponse {
        if req.method() == Method::CONNECT {
            return req.into();
        }

        let req = match convert_request(req) {
            Ok(req) => req,
            Err(e) => {
                return self.handle_gateway_error(ctx, e).await.into();
            }
        };

        let req_or_resp = self
            .handler
            .handle_request(req, GatewayDirection::Outbound, ctx.client_addr)
            .await;

        let resp = match req_or_resp {
            RequestOrResponse::Request(req) => {
                let req = match reqwest::Request::try_from(req) {
                    Ok(req) => req,
                    Err(e) => {
                        return self
                            .handle_gateway_error(
                                ctx,
                                GatewayForwardError::ConvertRequest {
                                    source: Box::new(e),
                                },
                            )
                            .await
                            .into();
                    }
                };

                match self.http_client.execute(req).await {
                    Ok(resp) => resp.into(),
                    Err(e) => {
                        return self
                            .handle_gateway_error(
                                ctx,
                                GatewayForwardError::Forward {
                                    source: Box::new(e),
                                },
                            )
                            .await
                            .into();
                    }
                }
            }
            RequestOrResponse::Response(resp) => resp,
        };
        match convert_response_to_hudsucker(resp) {
            Ok(resp) => resp,
            Err(e) => return self.handle_gateway_error(ctx, e).await.into(),
        }
        .into()
    }

    async fn handle_response(
        &mut self,
        ctx: &hudsucker::HttpContext,
        resp: http::Response<hudsucker::Body>,
    ) -> http::Response<hudsucker::Body> {
        let resp = match convert_response_to_reqwest(resp) {
            Ok(resp) => resp,
            Err(e) => return self.handle_gateway_error(ctx, e).await,
        };
        let resp = self
            .handler
            .handle_response(resp, GatewayDirection::Outbound)
            .await;
        match convert_response_to_hudsucker(resp) {
            Ok(res) => res,
            Err(e) => return self.handle_gateway_error(ctx, e).await,
        }
    }

    async fn handle_error(
        &mut self,
        ctx: &hudsucker::HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> http::Response<hudsucker::Body> {
        self.handle_gateway_error(
            ctx,
            GatewayForwardError::Forward {
                source: Box::new(err),
            },
        )
        .await
    }
}

impl<H: GatewayHandler> HandlerAdapter<H> {
    async fn handle_gateway_error(
        &mut self,
        _ctx: &hudsucker::HttpContext,
        err: GatewayForwardError,
    ) -> http::Response<hudsucker::Body> {
        match convert_response_to_hudsucker(
            self.handler
                .handle_error(err, GatewayDirection::Outbound)
                .await,
        ) {
            Ok(res) => res,
            Err(e) => {
                error!("Error converting error response: {e}");
                create_status_response(http::StatusCode::BAD_GATEWAY)
            }
        }
    }
}

fn convert_request(
    req: http::Request<hudsucker::Body>,
) -> Result<http::Request<reqwest::Body>, GatewayForwardError> {
    let (parts, body) = req.into_parts();
    let mut builder = http::Request::builder().method(parts.method).uri(parts.uri);
    for (name, value) in &parts.headers {
        builder = builder.header(name, value);
    }

    builder
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .boxed()
        .context(ConvertRequestSnafu {})
}

fn convert_response_to_hudsucker(
    resp: http::Response<reqwest::Body>,
) -> Result<http::Response<hudsucker::Body>, GatewayForwardError> {
    convert_response(resp, |body| {
        hudsucker::Body::from_stream(futures::StreamExt::map(body.into_data_stream(), |result| {
            result.map_err(std::io::Error::other)
        }))
    })
}

fn convert_response_to_reqwest(
    resp: http::Response<hudsucker::Body>,
) -> Result<http::Response<reqwest::Body>, GatewayForwardError> {
    convert_response(resp, |body| {
        reqwest::Body::wrap_stream(body.into_data_stream())
    })
}

fn convert_response<B1, B2>(
    resp: http::Response<B1>,
    convert_body: fn(B1) -> B2,
) -> Result<http::Response<B2>, GatewayForwardError> {
    let (parts, body) = resp.into_parts();
    let mut builder = http::Response::builder().status(parts.status);
    for (name, value) in &parts.headers {
        builder = builder.header(name, value);
    }

    builder
        .body(convert_body(body))
        .boxed()
        .context(ConvertResponseSnafu {})
}
