use std::net::SocketAddr;

use http::Method;
use http_body_util::BodyExt as _;
use hudsucker::{Proxy, certificate_authority::RcgenAuthority};
use rcgen::{Issuer, KeyPair};
use rustls::crypto::CryptoProvider;
use snafu::{ResultExt, Snafu};

use crate::http_gateway::{
    GatewayDirection, GatewayForwardError, GatewayHandler, RequestOrResponse, util::shutdown_signal,
};

#[derive(Debug, Snafu)]
pub enum OutboundGatewayCreateError {
    #[snafu(display("Failed to parse CA private key"))]
    ParsePrivateKey { source: rcgen::Error },
    #[snafu(display("Failed to parse CA certificate"))]
    ParseCertificate { source: rcgen::Error },
    #[snafu(display("Failed to bind or create outbound proxy"))]
    Proxy { source: hudsucker::Error },
}

pub struct OutboundGatewayBuilder<H: GatewayHandler> {
    listen_address: SocketAddr,
    ca_issuer: Issuer<'static, KeyPair>,
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
    ) -> Result<Self, OutboundGatewayCreateError> {
        let key_pair = KeyPair::from_pem(ca_private_key.as_str()).context(ParsePrivateKeySnafu)?;
        let ca_issuer = Issuer::from_ca_cert_pem(ca_certificate.as_str(), key_pair)
            .context(ParseCertificateSnafu)?;
        Ok(Self {
            listen_address,
            ca_issuer,
            crypto_provider,
            handler,
            http_client: reqwest::Client::new(),
        })
    }

    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = http_client;
        self
    }

    pub async fn build_and_run(self) -> Result<(), OutboundGatewayCreateError> {
        let ca = RcgenAuthority::new(self.ca_issuer, 1_000, self.crypto_provider.clone());

        let builder = Proxy::builder()
            .with_addr(self.listen_address)
            .with_ca(ca)
            .with_rustls_connector(self.crypto_provider);

        let proxy = builder
            .with_http_handler(HandlerAdapter::new(self.handler, self.http_client))
            .with_graceful_shutdown(shutdown_signal())
            .build()
            .context(ProxySnafu)?;

        proxy.start().await.context(ProxySnafu)
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

        let req = convert_request(req);

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
        convert_response_to_hudsucker(resp).into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &hudsucker::HttpContext,
        resp: http::Response<hudsucker::Body>,
    ) -> http::Response<hudsucker::Body> {
        let resp = convert_response_to_reqwest(resp);
        let resp = self
            .handler
            .handle_response(resp, GatewayDirection::Outbound)
            .await;
        convert_response_to_hudsucker(resp)
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
        convert_response_to_hudsucker(
            self.handler
                .handle_error(err, GatewayDirection::Outbound)
                .await,
        )
    }
}

fn convert_request(req: http::Request<hudsucker::Body>) -> http::Request<reqwest::Body> {
    let (mut parts, body) = req.into_parts();
    // hudsucker hands us the request with the version of the connection it arrived on
    // (which may be HTTP/2), but reqwest's client rejects an explicitly versioned request
    // that does not match its own transport. Let the client negotiate the version itself,
    // matching the previous rebuild which always defaulted to HTTP/1.1.
    parts.version = http::Version::HTTP_11;
    http::Request::from_parts(parts, reqwest::Body::wrap_stream(body.into_data_stream()))
}

fn convert_response_to_hudsucker(
    resp: http::Response<reqwest::Body>,
) -> http::Response<hudsucker::Body> {
    convert_response(resp, |body| {
        hudsucker::Body::from_stream(futures::StreamExt::map(body.into_data_stream(), |result| {
            result.map_err(std::io::Error::other)
        }))
    })
}

fn convert_response_to_reqwest(
    resp: http::Response<hudsucker::Body>,
) -> http::Response<reqwest::Body> {
    convert_response(resp, |body| {
        reqwest::Body::wrap_stream(body.into_data_stream())
    })
}

fn convert_response<B1, B2>(
    resp: http::Response<B1>,
    convert_body: fn(B1) -> B2,
) -> http::Response<B2> {
    let (parts, body) = resp.into_parts();
    http::Response::from_parts(parts, convert_body(body))
}
