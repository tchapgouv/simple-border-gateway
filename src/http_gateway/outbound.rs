use std::net::SocketAddr;

use http::Method;
use http_body_util::BodyExt as _;
use hudsucker::{Proxy, certificate_authority::RcgenAuthority};
use rcgen::{Issuer, KeyPair};
use rustls::crypto::CryptoProvider;
use snafu::{ResultExt, Snafu};

use crate::http_gateway::{
    GatewayDirection, GatewayForwardError, GatewayHandler, RequestOrResponse, headers,
    util::{remove_default_http_https_port, shutdown_signal},
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
    gateway_name: String,
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
            gateway_name: "http-gateway".to_string(),
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

    pub fn with_gateway_name(mut self, gateway_name: String) -> Self {
        self.gateway_name = gateway_name;
        self
    }

    pub async fn build_and_run(self) -> Result<(), OutboundGatewayCreateError> {
        let ca = RcgenAuthority::new(self.ca_issuer, 1_000, self.crypto_provider.clone());

        let builder = Proxy::builder()
            .with_addr(self.listen_address)
            .with_ca(ca)
            .with_rustls_connector(self.crypto_provider);

        let proxy = builder
            .with_http_handler(HandlerAdapter::new(
                self.handler,
                self.http_client,
                self.gateway_name.clone(),
            ))
            .with_graceful_shutdown(shutdown_signal())
            .build()
            .context(ProxySnafu)?;

        proxy.start().await.context(ProxySnafu)
    }
}

#[derive(Clone)]
struct HandlerAdapter<H: GatewayHandler> {
    handler: H,
    gateway_name: String,
    http_client: reqwest::Client,
}

impl<H: GatewayHandler> HandlerAdapter<H> {
    pub fn new(handler: H, http_client: reqwest::Client, gateway_name: String) -> Self {
        Self {
            handler,
            http_client,
            gateway_name,
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

        // `convert_request` rewrites the version for reqwest, so remember the protocol
        // the client actually used to report it in `Via`.
        let received_version = req.version();
        let req = convert_request(req);

        let req_or_resp = self
            .handler
            .handle_request(req, GatewayDirection::Outbound, ctx.client_addr)
            .await;

        let resp = match req_or_resp {
            RequestOrResponse::Request(req) => {
                let req = prepare_outbound_request(
                    &self.gateway_name,
                    req,
                    received_version,
                    ctx.client_addr,
                );
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
                    Ok(resp) => {
                        self.handler
                            .handle_response(resp.into(), GatewayDirection::Outbound)
                            .await
                    }
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
        convert_response_to_hudsucker(&self.gateway_name, resp).into()
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
        convert_response_to_hudsucker(&self.gateway_name, resp)
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
            &self.gateway_name,
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

/// Rewrite the headers of a request before it is handed to the origin server.
///
/// As a forward proxy, the gateway receives the request target in absolute form, so it
/// knows both the original scheme and the authority to reach. The `Host` field is
/// therefore rebuilt from that authority (RFC 9110 §7.2), the hop-by-hop headers are
/// dropped, and the original client is described for the origin server.
fn prepare_outbound_request(
    gateway_name: &str,
    req: http::Request<reqwest::Body>,
    version: http::Version,
    client_addr: SocketAddr,
) -> http::Request<reqwest::Body> {
    let (mut parts, body) = req.into_parts();
    let scheme = parts.uri.scheme_str().map(str::to_owned);
    let destination = parts
        .uri
        .authority()
        .map(|authority| remove_default_http_https_port(authority.as_str()).to_lowercase());

    headers::prepare_forwarded_request(
        gateway_name,
        &mut parts.headers,
        version,
        client_addr.ip(),
        scheme.as_deref(),
        destination.as_deref(),
    );

    http::Request::from_parts(parts, body)
}

fn convert_response_to_hudsucker(
    gateway_name: &str,
    resp: http::Response<reqwest::Body>,
) -> http::Response<hudsucker::Body> {
    let (mut parts, body) = resp.into_parts();
    // Behave like a proxy on the way back too: hop-by-hop headers are not relayed and
    // this gateway advertises itself in `Via`.
    headers::prepare_forwarded_response(gateway_name, &mut parts.headers, parts.version);
    http::Response::from_parts(
        parts,
        hudsucker::Body::from_stream(futures::StreamExt::map(body.into_data_stream(), |result| {
            result.map_err(std::io::Error::other)
        })),
    )
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
