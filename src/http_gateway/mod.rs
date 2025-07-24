pub mod inbound;
pub mod outbound;
pub mod util;

use std::error::Error as StdError;
use std::{future::Future, net::SocketAddr};

use http::{Request, Response, StatusCode};
use log::{debug, error};
use reqwest::Body;

use crate::http_gateway::util::create_status_response;

type BoxedStdError = Box<dyn StdError + Send>;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("Failed to create gateway: {0}")]
    CreateGateway(#[source] BoxedStdError),
    #[error("Failed to convert request: {0}")]
    ConvertRequest(#[source] BoxedStdError),
    #[error("Failed to convert response: {0}")]
    ConvertResponse(#[source] BoxedStdError),
    #[error("Failed to forward request: {0}")]
    Forward(#[source] BoxedStdError),
    #[error("Destination not found for host {0}")]
    DestinationNotFound(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum GatewayDirection {
    Inbound,
    Outbound,
}

/// Enum representing either an HTTP request or response.
#[derive(Debug)]
pub enum RequestOrResponse {
    /// HTTP Request
    Request(Request<Body>),
    /// HTTP Response
    Response(Response<Body>),
}

impl From<Request<Body>> for RequestOrResponse {
    fn from(req: Request<Body>) -> Self {
        Self::Request(req)
    }
}

impl From<Response<Body>> for RequestOrResponse {
    fn from(resp: Response<Body>) -> Self {
        Self::Response(resp)
    }
}

pub trait GatewayHandler: Clone + Send + Sync + 'static {
    /// This handler will be called for each HTTP request. It can either return a modified request,
    /// or a response. If a request is returned, it will be sent to the upstream server. If a
    /// response is returned, it will be sent to the client.
    fn handle_request(
        &mut self,
        req: Request<Body>,
        _direction: GatewayDirection,
        _client_addr: SocketAddr,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        async { req.into() }
    }

    /// This handler will be called for each HTTP response. It can modify a response before it is
    /// forwarded to the client.
    fn handle_response(
        &mut self,
        resp: Response<Body>,
        _direction: GatewayDirection,
    ) -> impl Future<Output = Response<Body>> + Send {
        async { resp }
    }

    /// This handler will be called if a proxy request fails. Default response is a 502 Bad Gateway.
    fn handle_error(
        &mut self,
        err: GatewayError,
        _direction: GatewayDirection,
    ) -> impl Future<Output = Response<Body>> + Send {
        async move {
            error!("{err}");
            debug!("{err:#?}");
            create_status_response(StatusCode::BAD_GATEWAY)
        }
    }
}
