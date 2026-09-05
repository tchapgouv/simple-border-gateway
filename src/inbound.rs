use std::{collections::BTreeMap, net::SocketAddr};

use crate::{
    http_gateway::{
        util::create_status_response, GatewayDirection, GatewayHandler, RequestOrResponse,
    },
    matrix::{
        spec::{Action, AuthType, DEFAULT_RULESET},
        util::{create_matrix_response, NameResolver},
        xmatrix::verify_signature,
    },
    util::{resolve_endpoint, to_bytes, CompiledRuleset, RequestContext},
};
use http::{Request, StatusCode};
use log::Level;
use reqwest::Body;
use ruma::serde::Base64;

#[derive(Clone)]
pub struct InboundHandler {
    name_resolver: NameResolver,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
    /// Per-server-name compiled ruleset.
    server_rulesets: BTreeMap<String, CompiledRuleset>,
    /// When true, every default endpoint is rejected unless an override rule explicitly allows it.
    reject_all_by_default: bool,
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

        // Call the main helper to resolve the endpoint with the active/applicable ruleset (with the default one for fallback), if it exist.
        // This will return on purpose the inbound and outbound action, but we are of course only interested in the inbound action here...
        let Some(resolved_endpoint) = resolve_endpoint(
            &ctx.parts,
            &ctx.origin_server_name,
            &self.server_rulesets,
            DEFAULT_RULESET.as_slice(),
        ) else {
            ctx.log(Level::Warn, "404 - not found, unknown endpoint");
            return create_status_response(StatusCode::NOT_FOUND).into();
        };

        // When reject all by default is set, every default endpoint requires an explicit allow.
        if self.reject_all_by_default && !resolved_endpoint.is_override {
            ctx.log(
                Level::Warn,
                "403 - forbidden, endpoint rejected by ruleset due to policy",
            );
            return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
        }

        // Verifying the auth type, and if a specific endpoint is authorized or not.
        match resolved_endpoint.endpoint.rule.auth_type {
            AuthType::Unauthenticated => {
                if resolved_endpoint.inbound_action == Action::Reject {
                    ctx.log(Level::Warn, "403 - forbidden, endpoint rejected by ruleset");
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
                ctx.log(Level::Info, "forward, unauthenticated endpoint");
                Request::from_parts(ctx.parts, body).into()
            }
            AuthType::CheckSignature => {
                self.check_signature(ctx, body, resolved_endpoint.inbound_action)
                    .await
            }
        }
    }
}

impl InboundHandler {
    pub fn new(
        name_resolver: NameResolver,
        public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
        server_rulesets: BTreeMap<String, CompiledRuleset>,
        reject_all_by_default: bool,
    ) -> Self {
        Self {
            name_resolver,
            public_key_map,
            server_rulesets,
            reject_all_by_default,
        }
    }

    async fn check_signature(
        &self,
        ctx: RequestContext,
        body: Body,
        inbound_action: Action,
    ) -> RequestOrResponse {
        let Some(x_matrix) = &ctx.xmatrix else {
            ctx.log(
                Level::Warn,
                "401 - unauthorized, unavailable or invalid X-Matrix auth header",
            );
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        };

        if !self
            .public_key_map
            .contains_key(ctx.origin_server_name.as_str())
        {
            ctx.log(Level::Warn, "401 - unauthorized, unauthorized server");
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        }

        if inbound_action == Action::Reject {
            ctx.log(Level::Warn, "403 - forbidden, endpoint rejected by ruleset");
            return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
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
