use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};

use http::{Request, StatusCode};
use log::Level;
use regex::Regex;
use reqwest::Body;

use crate::{
    http_gateway::{
        util::create_status_response, GatewayDirection, GatewayHandler, RequestOrResponse,
    },
    matrix::{
        spec::EndpointType,
        util::{create_matrix_response, NameResolver},
    },
    util::{
        get_matching_endpoint, remove_default_ports_from_uri, RequestContext,
        REGEX_ALLOWED_ENDPOINTS,
    },
};

#[derive(Clone)]
pub struct OutboundHandler {
    name_resolver: NameResolver,
    allowed_server_names: HashSet<String>,
    allowed_federation_domains: HashSet<String>,
    allowed_client_domains: HashSet<String>,
    allowed_non_matrix_regexes: Vec<Regex>,
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

        if let Some(endpoint) = get_matching_endpoint(&ctx.parts, &REGEX_ALLOWED_ENDPOINTS) {
            match endpoint.endpoint_type {
                EndpointType::Federation => {
                    if !self
                        .allowed_federation_domains
                        .contains(&ctx.destination_server_name)
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
                    if !self
                        .allowed_client_domains
                        .contains(&ctx.destination_server_name)
                    {
                        ctx.log(Level::Warn, "403 - forbidden, unauthorized client domain");
                        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                    }
                    ctx.log(Level::Info, "forward, allowed legacy media request");
                }
                EndpointType::WellKnown => {
                    if !self
                        .allowed_server_names
                        .contains(&ctx.destination_server_name)
                    {
                        ctx.log(Level::Warn, "403 - forbidden, unauthorized base domain");
                        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                    }
                    ctx.log(Level::Info, "forward, allowed well known request");
                }
            }
            return Request::from_parts(ctx.parts, body).into();
        }

        let uri = remove_default_ports_from_uri(ctx.parts.uri.clone());
        for regex in &self.allowed_non_matrix_regexes {
            if regex.is_match(uri.as_str()) {
                ctx.log(Level::Info, "forward, destination uri matches regex");
                return Request::from_parts(ctx.parts, body).into();
            }
        }

        ctx.log(Level::Warn, "404 - not found, unknown endpoint");
        create_status_response(StatusCode::NOT_FOUND).into()
    }
}

impl OutboundHandler {
    pub fn new(
        name_resolver: NameResolver,
        allowed_federation_domains: BTreeMap<String, String>,
        allowed_client_domains: BTreeMap<String, String>,
        allowed_non_matrix_regexes: Vec<String>,
    ) -> Result<Self, anyhow::Error> {
        let mut allowed_server_names =
            HashSet::from_iter(allowed_federation_domains.values().cloned());
        allowed_server_names.extend(allowed_client_domains.values().cloned());

        let allowed_non_matrix_regexes = allowed_non_matrix_regexes
            .iter()
            .map(|regex| {
                Regex::new(regex)
                    .map_err(|e| anyhow::anyhow!("Error parsing non matrix regex: {e}"))
            })
            .collect::<Result<Vec<Regex>, anyhow::Error>>()?;

        Ok(Self {
            name_resolver,
            allowed_server_names,
            allowed_federation_domains: allowed_federation_domains.values().cloned().collect(),
            allowed_client_domains: allowed_client_domains.values().cloned().collect(),
            allowed_non_matrix_regexes,
        })
    }
}
