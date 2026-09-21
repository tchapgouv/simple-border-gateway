use std::collections::BTreeMap;
use std::net::SocketAddr;

use bytes::Bytes;
use http::{Method, request::Parts, uri::Scheme};
use http_body_util::{BodyExt, Limited};
use log::{Level, log};
use matchit::Router;
use reqwest::Body;
use ruma::api::federation::authentication::XMatrix;
use snafu::{ResultExt as _, Whatever};
use tracing::debug;

use crate::{
    config::{EndpointConfig, UpstreamProxyConfig},
    http_gateway::{
        GatewayDirection,
        util::{extract_destination_host, extract_origin_ip},
    },
    matrix::{
        spec::{Action, AuthType, EndpointType},
        util::NameResolver,
    },
};

// ring and aws_lc_rs are mutually exclusive.
#[cfg(all(feature = "aws_lc_rs", feature = "ring"))]
compile_error!("features `aws_lc_rs` and `ring` cannot be enabled at the same time");

#[cfg(feature = "aws_lc_rs")]
pub use rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use rustls::crypto::ring as crypto_provider;

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

/// Runtime representation of a filtering rule that owns its path string.
#[derive(Clone, Debug)]
pub struct RuntimeRule {
    pub method: Option<Method>,
    pub endpoint_type: EndpointType,
    pub auth_type: AuthType,
    pub inbound_action: Action,
    pub outbound_action: Action,
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub id: String,
    /// Path pattern matched by the router, using `{name}` placeholders.
    /// A trailing `{*name}` placeholder matches the remaining path segments.
    pub path: String,
    pub rule: RuntimeRule,
}

impl Endpoint {
    /// Build a new endpoint with the specified arguments.
    pub fn new(
        id: &str,
        path: &str,
        method: Option<Method>,
        auth_type: AuthType,
        endpoint_type: EndpointType,
        inbound_action: Action,
        outbound_action: Action,
    ) -> Result<Self, Whatever> {
        validate_path(path)?;
        Ok(Self {
            id: id.to_string(),
            path: path.to_string(),
            rule: RuntimeRule {
                method,
                endpoint_type,
                auth_type,
                inbound_action,
                outbound_action,
            },
        })
    }

    /// Build a new allowed (inbound and outbound) endpoint with the specified arguments.
    /// Mainly added to avoid allowing by hand all default actions
    pub fn new_allowed(
        id: &str,
        path: &str,
        method: Option<Method>,
        auth_type: AuthType,
        endpoint_type: EndpointType,
    ) -> Result<Self, Whatever> {
        Self::new(
            id,
            path,
            method,
            auth_type,
            endpoint_type,
            Action::Allow,
            Action::Allow,
        )
    }

    /// Build an allowed endpoint using signed federation defaults.
    pub fn new_allowed_signed_fed(
        id: &str,
        path: &str,
        method: Option<Method>,
    ) -> Result<Self, Whatever> {
        Self::new_allowed(
            id,
            path,
            method,
            AuthType::CheckSignature,
            EndpointType::Federation,
        )
    }
}

/// A set of endpoints compiled into a `matchit` router for path matching.
/// Several endpoints can share the same path as long as they match different methods.
#[derive(Clone)]
pub struct EndpointRouter {
    router: Router<Vec<Endpoint>>,
    endpoint_count: usize,
}

impl EndpointRouter {
    /// Compile endpoints into a router, grouping together endpoints that share a path.
    pub fn new(endpoints: Vec<Endpoint>) -> Result<Self, Whatever> {
        let endpoint_count = endpoints.len();
        let mut groups: Vec<(String, Vec<Endpoint>)> = Vec::new();
        for endpoint in endpoints {
            if let Some((_, group)) = groups.iter_mut().find(|(path, _)| path == &endpoint.path) {
                group.push(endpoint);
            } else {
                let path = endpoint.path.clone();
                groups.push((path, vec![endpoint]));
            }
        }

        let mut router = Router::new();
        for (path, group) in groups {
            if let Err(e) = router.insert(path.clone(), group) {
                snafu::whatever!("Failed to compile endpoint path pattern '{path}': {e}");
            }
        }

        Ok(Self {
            router,
            endpoint_count,
        })
    }

    /// An empty router, matching no path.
    pub fn empty() -> Self {
        Self {
            router: Router::new(),
            endpoint_count: 0,
        }
    }

    /// Number of endpoints held by this router, including endpoints sharing a path.
    pub fn len(&self) -> usize {
        self.endpoint_count
    }

    /// Whether this router holds no endpoint.
    pub fn is_empty(&self) -> bool {
        self.endpoint_count == 0
    }

    /// Find the endpoint matching the request path and method, if any.
    pub fn get(&self, parts: &Parts) -> Option<&Endpoint> {
        let matched = self.router.at(parts.uri.path()).ok()?;
        matched
            .value
            .iter()
            .find(|endpoint| match &endpoint.rule.method {
                Some(expected) => *expected == parts.method,
                None => true,
            })
    }
}

/// A compiled ruleset combining additional endpoint definitions with action overrides.
#[derive(Clone)]
pub struct CompiledRuleset {
    pub additional_endpoints: EndpointRouter,
    pub action_overrides: BTreeMap<String, (Action, Action)>,
}

impl Default for CompiledRuleset {
    fn default() -> Self {
        Self {
            additional_endpoints: EndpointRouter::empty(),
            action_overrides: BTreeMap::new(),
        }
    }
}

/// Result of endpoint resolution.
/// Contains the matched endpoint and the action to take for inbound and outbound requests.
/// Will also return if this endpoint is an override of a default endpoint in the ruleset.
pub(crate) struct ResolvedEndpoint<'a> {
    pub(crate) endpoint: &'a Endpoint,
    pub(crate) inbound_action: Action,
    pub(crate) outbound_action: Action,
    pub(crate) is_override: bool,
}

fn validate_path(path: &str) -> Result<(), Whatever> {
    let mut probe: Router<()> = Router::new();
    if let Err(e) = probe.insert(path, ()) {
        snafu::whatever!("Invalid endpoint path pattern '{path}': {e}");
    }
    Ok(())
}

/// Convert additional endpoint configs into a compiled endpoint router.
/// Actions default to Reject/Reject since they are expected to be set via override_rules.
pub fn build_endpoint_router_from_endpoint_configs(
    endpoints: &[EndpointConfig],
) -> Result<EndpointRouter, Whatever> {
    let endpoints = endpoints
        .iter()
        .map(|e| {
            let method = e
                .method
                .as_deref()
                .map(|m| {
                    Method::from_bytes(m.as_bytes())
                        .whatever_context(format!("Invalid method '{}' in endpoint '{}'", m, e.id))
                })
                .transpose()?;

            Ok(Endpoint {
                id: e.id.clone(),
                path: e.path.clone(),
                rule: RuntimeRule {
                    method,
                    endpoint_type: e.endpoint_type,
                    auth_type: e.auth_type,
                    inbound_action: Action::Reject,
                    outbound_action: Action::Reject,
                },
            })
        })
        .collect::<Result<Vec<_>, Whatever>>()?;

    EndpointRouter::new(endpoints)
        .whatever_context("Failed to compile additional endpoints into a router")
}

/// Compile override rules into a map of endpoint ID → (inbound_action, outbound_action).
pub fn compile_override_rules(
    rules: &[crate::config::OverrideRuleConfig],
) -> Result<BTreeMap<String, (Action, Action)>, Whatever> {
    let mut map = BTreeMap::new();
    for r in rules {
        let inbound_action = match r.inbound_action.as_deref() {
            None | Some("reject") | Some("disallow") => Action::Reject,
            Some("allow") => Action::Allow,
            Some(other) => snafu::whatever!(
                "Unknown inbound_action '{}' for endpoint '{}' (expected 'allow' or 'reject')",
                other,
                r.endpoint
            ),
        };

        let outbound_action = match r.outbound_action.as_deref() {
            None | Some("reject") | Some("disallow") => Action::Reject,
            Some("allow") => Action::Allow,
            Some(other) => snafu::whatever!(
                "Unknown outbound_action '{}' for endpoint '{}' (expected 'allow' or 'reject')",
                other,
                r.endpoint
            ),
        };

        map.insert(r.endpoint.clone(), (inbound_action, outbound_action));
    }
    Ok(map)
}

/// Resolve an endpoint for a server and apply its action overrides.
pub(crate) fn resolve_endpoint<'a>(
    parts: &Parts,
    external_server_name: &str,
    server_rulesets: &'a BTreeMap<String, CompiledRuleset>,
    default_ruleset: &'a EndpointRouter,
) -> Option<ResolvedEndpoint<'a>> {
    // Use override rules if the server has a configured ruleset, otherwise fall through to the
    // default ruleset
    let ruleset = server_rulesets.get(external_server_name);

    debug!(
        "Ruleset lookup for external server '{external_server_name}': found ruleset: {}, additional endpoints: {}",
        ruleset.is_some(),
        ruleset.map_or(0, |ruleset| ruleset.additional_endpoints.len())
    );

    // Two-tier lookup, additional endpoints take precedence, then fall back to the default
    // ruleset
    let (endpoint, is_from_additional) =
        match ruleset.and_then(|ruleset| ruleset.additional_endpoints.get(parts)) {
            Some(endpoint) => (endpoint, true),
            None => (default_ruleset.get(parts)?, false),
        };

    // Determine effective actions: check the override rules by endpoint ID, otherwise use the
    // endpoint's defaults
    let action_override = ruleset
        .and_then(|ruleset| ruleset.action_overrides.get(&endpoint.id))
        .copied();
    let (inbound_action, outbound_action) =
        action_override.unwrap_or((endpoint.rule.inbound_action, endpoint.rule.outbound_action));
    // Is this an override? This is useful to know for logging, but also if we are in reject all mode,
    // as all non overriden endpoints will be rejected
    // An additional endpoint is automatically considered as a override...
    let is_override = is_from_additional || action_override.is_some();

    debug!(
        "Matched endpoint: {}, is_from_additional: {is_from_additional}, has_override: {}, inbound_action: {inbound_action:?}, outbound_action: {outbound_action:?}",
        endpoint.id,
        action_override.is_some()
    );

    Some(ResolvedEndpoint {
        endpoint,
        inbound_action,
        outbound_action,
        is_override,
    })
}

pub(crate) async fn to_bytes(body: Body, limit: usize) -> Option<Bytes> {
    Limited::new(body, limit)
        .collect()
        .await
        .map(|col| col.to_bytes())
        .ok()
}

pub(crate) struct RequestContext {
    pub(crate) parts: Parts,
    pub(crate) xmatrix: Option<XMatrix>,
    pub(crate) origin_server_name: String,
    pub(crate) destination_server_name: String,
    pub(crate) destination_host: String,
    log_prefix: String,
}

impl RequestContext {
    pub(crate) async fn new(
        parts: Parts,
        direction: GatewayDirection,
        client_addr: SocketAddr,
        name_resolver: &NameResolver,
    ) -> Self {
        let xmatrix = parts
            .headers
            .get("Authorization")
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_str| XMatrix::parse(auth_str).ok());

        let origin_server_name = if let Some(xmatrix) = &xmatrix {
            xmatrix.origin.to_string()
        } else {
            // Origin server name not available in auth header, let's try to guess it from the client IP
            let origin_ip = extract_origin_ip(&parts, &direction, &client_addr);
            name_resolver.ip_to_server_name(&origin_ip).await
        };

        let destination_host = extract_destination_host(&parts, &direction).to_string();
        Self {
            parts,
            xmatrix,
            origin_server_name,
            destination_server_name: name_resolver.domain_to_server_name(&destination_host),
            destination_host,
            log_prefix: match direction {
                GatewayDirection::Inbound => "IN ",
                GatewayDirection::Outbound => "OUT",
            }
            .to_string(),
        }
    }

    pub(crate) fn log(&self, level: Level, msg: &str) {
        log!(
            level,
            "{0}: {1} -> {2} {3} {4} : {5}",
            self.log_prefix,
            self.origin_server_name,
            self.destination_server_name,
            self.parts.method,
            self.parts.uri.path_and_query().map_or("", |p| p.as_str()),
            msg,
        );
    }
}

#[allow(
    clippy::unwrap_used,
    reason = "we only remove default ports from a validated uri so no new untrusted input"
)]
pub(crate) fn remove_default_ports_from_uri(uri: http::Uri) -> String {
    let mut parts = uri.into_parts();
    if let Some(authority) = parts.authority.clone() {
        let host = authority.host().to_string();
        if let Some(port) = authority.port_u16()
            && (port == 443 && parts.scheme == Some(Scheme::HTTPS)
                || port == 80 && parts.scheme == Some(Scheme::HTTP))
        {
            parts.authority = Some(http::uri::Authority::from_maybe_shared(host).unwrap());
        }
    }
    http::Uri::from_parts(parts).unwrap().to_string()
}

pub fn read_pem(path_or_content: &str) -> Result<String, Whatever> {
    let bytes = if path_or_content.starts_with("----") {
        path_or_content.as_bytes().to_vec()
    } else {
        std::fs::read(path_or_content).whatever_context("Failed to read PEM file")?
    };
    String::from_utf8(bytes).whatever_context("Failed to convert PEM content to UTF-8")
}

pub fn create_http_client(
    additional_root_certs: Vec<String>,
    upstream_proxy_config: Option<UpstreamProxyConfig>,
) -> Result<reqwest::Client, Whatever> {
    let mut builder = reqwest::Client::builder();
    if let Some(upstream_proxy_config) = upstream_proxy_config {
        let mut proxy_builder = reqwest::Proxy::all(upstream_proxy_config.url)
            .whatever_context("Failed to create reqwest proxy config")?;
        if upstream_proxy_config.username.is_some() || upstream_proxy_config.password.is_some() {
            proxy_builder = proxy_builder.basic_auth(
                upstream_proxy_config.username.as_deref().unwrap_or(""),
                upstream_proxy_config.password.as_deref().unwrap_or(""),
            );
        }
        builder = builder.proxy(proxy_builder);
    }
    builder = builder.tls_certs_merge(
        additional_root_certs
            .into_iter()
            .map(|content| {
                reqwest::tls::Certificate::from_pem(
                    read_pem(&content)
                        .whatever_context("Failed to read PEM")?
                        .as_bytes(),
                )
                .whatever_context("Failed to parse PEM")
            })
            .collect::<Result<Vec<_>, Whatever>>()?,
    );
    // dns resolver dns overrides ?
    builder
        .build()
        .whatever_context("Failed to build reqwest client")
}
