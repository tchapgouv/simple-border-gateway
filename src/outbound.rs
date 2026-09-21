use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};

use http::{Request, StatusCode};
use log::Level;
use reqwest::Body;
use snafu::{ResultExt, Whatever};

use crate::{
    config::EndpointConfig,
    http_gateway::{
        GatewayDirection, GatewayHandler, RequestOrResponse, util::create_status_response,
    },
    matrix::{
        spec::{Action, DEFAULT_RULESET, EndpointType},
        util::{NameResolver, create_matrix_response},
    },
    util::{
        CompiledRuleset, EndpointRouter, RequestContext, build_non_matrix_endpoint_routers,
        resolve_endpoint,
    },
};

#[derive(Clone)]
pub struct OutboundHandler {
    name_resolver: NameResolver,
    allowed_server_names: HashSet<String>,
    allowed_federation_domains: HashSet<String>,
    allowed_client_domains: HashSet<String>,
    /// Endpoint routers for non-matrix destinations, keyed by destination host.
    non_matrix_endpoints: BTreeMap<String, EndpointRouter>,
    /// Per-server-name compiled ruleset.
    server_rulesets: BTreeMap<String, CompiledRuleset>,
    /// When true, the default ruleset will reject everything that is not explicitly allowed by an override rule.
    reject_all_by_default: bool,
}

impl GatewayHandler for OutboundHandler {
    async fn handle_request(
        &self,
        req: Request<Body>,
        direction: GatewayDirection,
        client_addr: SocketAddr,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();
        let ctx = RequestContext::new(parts, direction, client_addr, &self.name_resolver).await;

        // Non-matrix endpoints are matched by destination host and bypass per-server
        // ruleset routing entirely.
        if let Some(router) = self.non_matrix_endpoints.get(&ctx.destination_host)
            && router.get(&ctx.parts).is_some()
        {
            ctx.log(
                Level::Info,
                "forward, destination matches an authorized non-matrix endpoint",
            );
            return Request::from_parts(ctx.parts, body).into();
        }

        // Call the main helper to resolve the endpoint with the active/applicable ruleset (with the default one for fallback), if it exist.
        // This will return on purpose the inbound and outbound action, but we are of course only interested in the outbound action here...
        let Some(resolved_endpoint) = resolve_endpoint(
            &ctx.parts,
            &ctx.destination_server_name,
            &self.server_rulesets,
            &DEFAULT_RULESET,
        ) else {
            ctx.log(Level::Warn, "404 - not found, unknown endpoint");
            return create_status_response(StatusCode::NOT_FOUND).into();
        };

        // When the reject all mode is enabled, we reject EVERYTHING not overridden.
        // No exceptions are made here, unlike the inbound mode.
        if !resolved_endpoint.is_override && self.reject_all_by_default {
            ctx.log(
                Level::Warn,
                "403 - forbidden, endpoint rejected by default ruleset due to policy",
            );
            return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
        }

        if resolved_endpoint.outbound_action == Action::Reject {
            ctx.log(Level::Warn, "403 - forbidden, endpoint rejected by ruleset");
            return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
        }

        match resolved_endpoint.endpoint.rule.endpoint_type {
            EndpointType::Federation => {
                if !self
                    .allowed_federation_domains
                    .contains(&ctx.destination_host)
                {
                    ctx.log(
                        Level::Warn,
                        "403 - forbidden, unauthorized federation domain",
                    );
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
                ctx.log(Level::Info, "forward, allowed federation request");
            }
            EndpointType::LegacyMedia => {
                if !self.allowed_client_domains.contains(&ctx.destination_host) {
                    ctx.log(Level::Warn, "403 - forbidden, unauthorized client domain");
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
                ctx.log(Level::Info, "forward, allowed legacy media request");
            }
            EndpointType::WellKnown => {
                if !self.allowed_server_names.contains(&ctx.destination_host) {
                    ctx.log(Level::Warn, "403 - forbidden, unauthorized base domain");
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
                ctx.log(Level::Info, "forward, allowed well known request");
            }
        }
        Request::from_parts(ctx.parts, body).into()
    }
}

impl OutboundHandler {
    pub fn new(
        name_resolver: NameResolver,
        allowed_federation_domains: BTreeMap<String, String>,
        allowed_client_domains: BTreeMap<String, String>,
        non_matrix_endpoints: Vec<EndpointConfig>,
        server_rulesets: BTreeMap<String, CompiledRuleset>,
        reject_all_by_default: bool,
    ) -> Result<Self, Whatever> {
        let mut allowed_server_names =
            HashSet::from_iter(allowed_federation_domains.values().cloned());
        allowed_server_names.extend(allowed_client_domains.values().cloned());

        let non_matrix_endpoints = build_non_matrix_endpoint_routers(&non_matrix_endpoints)
            .whatever_context("Failed to build non-matrix endpoints")?;

        Ok(Self {
            name_resolver,
            allowed_server_names,
            allowed_federation_domains: allowed_federation_domains.keys().cloned().collect(),
            allowed_client_domains: allowed_client_domains.keys().cloned().collect(),
            non_matrix_endpoints,
            server_rulesets,
            reject_all_by_default,
        })
    }
}
