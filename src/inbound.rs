use std::{collections::BTreeMap, net::SocketAddr};

use crate::{
    http_gateway::{
        util::create_status_response, GatewayDirection, GatewayHandler, RequestOrResponse,
    },
    matrix::{
        spec::AuthType,
        util::{create_matrix_response, NameResolver},
        xmatrix::verify_signature,
    },
    util::{get_matching_endpoint, to_bytes, RequestContext, REGEX_ALLOWED_ENDPOINTS},
};
use http::{Request, StatusCode};
use log::Level;
use reqwest::Body;
use ruma::{serde::Base64, server_util::authorization::XMatrix};

#[derive(Clone)]
pub struct InboundHandler {
    name_resolver: NameResolver,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
}

impl GatewayHandler for InboundHandler {
    async fn handle_request(
        &mut self,
        req: Request<Body>,
        direction: GatewayDirection,
        client_addr: SocketAddr,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();

        let ctx = RequestContext::new(parts, direction, client_addr, &mut self.name_resolver);

        let Some(endpoint) = get_matching_endpoint(&ctx.parts, &REGEX_ALLOWED_ENDPOINTS) else {
            ctx.log(Level::Warn, "404 - not found, unknown endpoint");
            return create_status_response(StatusCode::NOT_FOUND).into();
        };

        match endpoint.auth_type {
            AuthType::Unauthenticated => {
                ctx.log(Level::Info, "forward, unauthenticated endpoint");
                Request::from_parts(ctx.parts, body).into()
            }
            AuthType::CheckSignature => self.check_signature(ctx, body).await,
        }
    }
}

impl InboundHandler {
    pub fn new(
        name_resolver: NameResolver,
        public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
    ) -> Self {
        Self {
            name_resolver,
            public_key_map,
        }
    }

    async fn check_signature(&self, mut ctx: RequestContext, body: Body) -> RequestOrResponse {
        let Some(auth_header) = ctx.parts.headers.get("Authorization") else {
            ctx.log(Level::Warn, "401 - unauthorized, no authorization header");
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        };

        let Ok(x_matrix) = XMatrix::parse(auth_header.to_str().unwrap_or_default()) else {
            ctx.log(
                Level::Warn,
                "401 - unauthorized, invalid X-Matrix auth header",
            );
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        };

        // let's override the origin with the server name from the X-Matrix header
        ctx.origin_server_name = x_matrix.origin.clone().to_string();

        if !self
            .public_key_map
            .contains_key(ctx.origin_server_name.as_str())
        {
            ctx.log(Level::Warn, "401 - unauthorized, unauthorized server");
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        }

        let Some(body) = to_bytes(body, 1024 * 1024 * 10).await else {
            ctx.log(Level::Warn, "413 - req body too large");
            return create_status_response(StatusCode::PAYLOAD_TOO_LARGE).into();
        };

        let Ok(body) = String::from_utf8(body.to_vec()) else {
            ctx.log(Level::Warn, "400 - bad request, req body not utf8");
            return create_status_response(StatusCode::BAD_REQUEST).into();
        };

        match verify_signature(&self.public_key_map, &ctx.parts, x_matrix, &body) {
            Ok(()) => {
                ctx.log(
                    Level::Info,
                    "forward, authorized server and valid signature",
                );
                Request::from_parts(ctx.parts, Body::from(body)).into()
            }
            Err(e) => {
                ctx.log(
                    Level::Warn,
                    &format!("401 - unauthorized, authorized server but wrong signature: {e}"),
                );
                create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into()
            }
        }
    }
}
