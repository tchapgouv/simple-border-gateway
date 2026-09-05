use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};

use http::{Request, StatusCode};
use log::Level;
use regex::Regex;
use reqwest::Body;
use snafu::{ResultExt, Whatever};

use crate::{
    http_gateway::{
        util::create_status_response, GatewayDirection, GatewayHandler, RequestOrResponse,
    },
    matrix::{
        spec::{Action, EndpointType, DEFAULT_RULESET},
        util::{create_matrix_response, NameResolver},
    },
    util::{remove_default_ports_from_uri, resolve_endpoint, CompiledRuleset, RequestContext},
};

#[derive(Clone)]
pub struct OutboundHandler {
    name_resolver: NameResolver,
    allowed_server_names: HashSet<String>,
    allowed_federation_domains: HashSet<String>,
    allowed_client_domains: HashSet<String>,
    allowed_non_matrix_regexes: Vec<Regex>,
    /// Per-server-name compiled ruleset.
    server_rulesets: BTreeMap<String, CompiledRuleset>,
    /// When true, the default ruleset will reject everything that is not explicitly allowed by an override rule.
    reject_all_by_default: bool,
}

impl GatewayHandler for OutboundHandler {
    async fn handle_request(
        &mut self,
        req: Request<Body>,
        direction: GatewayDirection,
        client_addr: SocketAddr,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();
        let ctx = RequestContext::new(parts, direction, client_addr, &mut self.name_resolver);

        // Non-matrix regexes bypass per-server ruleset routing entirely
        let uri = remove_default_ports_from_uri(ctx.parts.uri.clone());
        for regex in &self.allowed_non_matrix_regexes {
            if regex.is_match(uri.as_str()) {
                ctx.log(Level::Info, "forward, destination uri matches regex");
                return Request::from_parts(ctx.parts, body).into();
            }
        }

        // Call the main helper to resolve the endpoint with the active/applicable ruleset (with the default one for fallback), if it exist.
        // This will return on purpose the inbound and outbound action, but we are of course only interested in the outbound action here...
        let Some(resolved_endpoint) = resolve_endpoint(
            &ctx.parts,
            &ctx.destination_server_name,
            &self.server_rulesets,
            DEFAULT_RULESET.as_slice(),
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
                if !self.allowed_server_names.contains(&ctx.destination_host)
                    && !self
                        .allowed_federation_domains
                        .contains(&ctx.destination_host)
                {
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
        allowed_non_matrix_regexes: Vec<String>,
        server_rulesets: BTreeMap<String, CompiledRuleset>,
        reject_all_by_default: bool,
    ) -> Result<Self, Whatever> {
        let mut allowed_server_names =
            HashSet::from_iter(allowed_federation_domains.values().cloned());
        allowed_server_names.extend(allowed_client_domains.values().cloned());

        let allowed_non_matrix_regexes = allowed_non_matrix_regexes
            .iter()
            .map(|regex| Regex::new(regex).whatever_context("Error parsing non matrix regex"))
            .collect::<Result<Vec<Regex>, Whatever>>()?;

        Ok(Self {
            name_resolver,
            allowed_server_names,
            allowed_federation_domains: allowed_federation_domains.keys().cloned().collect(),
            allowed_client_domains: allowed_client_domains.keys().cloned().collect(),
            allowed_non_matrix_regexes,
            server_rulesets,
            reject_all_by_default,
        })
    }
}
