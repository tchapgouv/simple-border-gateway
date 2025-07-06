use std::collections::{BTreeMap, HashSet};

use http::{Method, StatusCode};
use http_body_util::BodyExt as _;
use log::Level;
use regex::Regex;

use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::{
    config::UpstreamProxyConfig,
    matrix_spec::{
        Endpoint, CLIENT_WELLKNOWN_ENDPOINT, FEDERATION_ENDPOINTS, MEDIA_CLIENT_LEGACY_ENDPOINTS,
        SERVER_WELLKNOWN_ENDPOINT,
    },
    util::{
        create_http_client, create_matrix_response, create_status_response, normalize_uri,
        set_req_scheme_and_authority, NameResolver, ReqContext,
    },
};

const OUTBOUND_PREFIX: &str = "OUT";

#[allow(clippy::unwrap_used, reason = "lazy static regex")]
static REPLACE_VARIABLES_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new("\\{[^\\}]*}").unwrap());
static REGEX_CLIENT_WELLKNOWN_ENDPOINT: std::sync::LazyLock<RegexEndpoint> =
    std::sync::LazyLock::new(|| RegexEndpoint::from(CLIENT_WELLKNOWN_ENDPOINT));
static REGEX_SERVER_WELLKNOWN_ENDPOINT: std::sync::LazyLock<RegexEndpoint> =
    std::sync::LazyLock::new(|| RegexEndpoint::from(SERVER_WELLKNOWN_ENDPOINT));
static REGEX_FEDERATION_ENDPOINTS: std::sync::LazyLock<Vec<RegexEndpoint>> =
    std::sync::LazyLock::new(|| Vec::from_iter(FEDERATION_ENDPOINTS.map(RegexEndpoint::from)));
static REGEX_MEDIA_CLIENT_LEGACY_ENDPOINTS: std::sync::LazyLock<Vec<RegexEndpoint>> =
    std::sync::LazyLock::new(|| {
        Vec::from_iter(MEDIA_CLIENT_LEGACY_ENDPOINTS.map(RegexEndpoint::from))
    });

#[derive(Clone)]
struct RegexEndpoint {
    regex: Regex,
    endpoint: Endpoint,
}

impl RegexEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        // escape dots so they don't get interpreted
        let mut regex = endpoint.path.replace(".", "\\.");
        // replace variables in brackets with .*
        regex = REPLACE_VARIABLES_RE.replace_all(&regex, ".*").to_string();
        #[allow(
            clippy::unwrap_used,
            reason = " inputs statically defined in matrix_spec.rs"
        )]
        let regex = Regex::new(&regex).unwrap();
        RegexEndpoint { regex, endpoint }
    }
}

#[derive(Clone)]
pub(crate) struct GatewayHandler {
    http_client: reqwest::Client,
    name_resolver: NameResolver,
    allowed_servernames: HashSet<String>,
    allowed_federation_domains: BTreeMap<String, String>,
    allowed_client_domains: BTreeMap<String, String>,
    allowed_non_matrix_regexes: Vec<Regex>,
    _for_tests_only_mock_server_host: Option<String>,
}

impl GatewayHandler {
    pub(crate) fn new(
        name_resolver: NameResolver,
        allowed_federation_domains: BTreeMap<String, String>,
        allowed_client_domains: BTreeMap<String, String>,
        allowed_non_matrix_regexes: Vec<String>,
        upstream_proxy_config: Option<UpstreamProxyConfig>,
        _for_tests_only_mock_server_host: Option<String>,
    ) -> Result<Self, anyhow::Error> {
        let http_client = create_http_client(upstream_proxy_config)?;
        let allowed_non_matrix_regexes = allowed_non_matrix_regexes
            .iter()
            .map(|regex| {
                Regex::new(regex)
                    .map_err(|e| anyhow::anyhow!("Error parsing non matrix regex: {e}"))
            })
            .collect::<Result<Vec<Regex>, anyhow::Error>>()?;

        let mut allowed_servernames =
            HashSet::from_iter(allowed_federation_domains.values().cloned());
        allowed_servernames.extend(allowed_client_domains.values().cloned());

        Ok(GatewayHandler {
            http_client,
            name_resolver,
            allowed_servernames,
            allowed_federation_domains,
            allowed_client_domains,
            allowed_non_matrix_regexes,
            _for_tests_only_mock_server_host,
        })
    }

    async fn forward_request(
        &self,
        req_ctx: &mut ReqContext,
        body: Body,
        success_log_text: &str,
    ) -> RequestOrResponse {
        let response = req_ctx.forward_request(body.into_data_stream(), None).await;

        match convert_response(response) {
            Ok(resp) => {
                req_ctx.log(Level::Info, success_log_text);
                resp.into()
            }
            Err(e) => {
                req_ctx.log(
                    Level::Warn,
                    &format!("503 - error converting response: {e}"),
                );
                create_status_response(StatusCode::BAD_GATEWAY).into()
            }
        }
    }
}

fn is_valid_request(req: &http::Request<Body>, allowed_endpoints: &[RegexEndpoint]) -> bool {
    for endpoint in allowed_endpoints {
        if is_valid_request_for_endpoint(req, endpoint) {
            return true;
        }
    }
    false
}

fn is_valid_request_for_endpoint(req: &http::Request<Body>, endpoint: &RegexEndpoint) -> bool {
    if endpoint.regex.is_match(req.uri().to_string().as_str()) {
        if let Some(expected_method) = &endpoint.endpoint.method {
            if expected_method == req.method() {
                return true;
            }
        } else {
            return true;
        }
    }
    false
}

impl HttpHandler for GatewayHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        mut req: http::Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == Method::CONNECT {
            req.into()
        } else {
            let mut req_ctx = ReqContext::new(
                &req,
                ctx.client_addr,
                self.http_client.clone(),
                self.name_resolver.clone(),
                OUTBOUND_PREFIX.to_string(),
            );

            // TODO we can probably do better to inject the mock server host
            if let Some(mock_server_host) = &self._for_tests_only_mock_server_host {
                set_req_scheme_and_authority(&mut req, "http", mock_server_host);
            }

            // Servers need to be able to discover other servers via well-known endpoints
            if is_valid_request_for_endpoint(&req, &REGEX_SERVER_WELLKNOWN_ENDPOINT) {
                if self.allowed_servernames.contains(&req_ctx.destination) {
                    return self
                        .forward_request(
                            &mut req_ctx,
                            req.into_body(),
                            "200 - forward, valid and allowed server well-known request",
                        )
                        .await;
                } else {
                    req_ctx.log(
                        Level::Warn,
                        "forbid, not an allowed well-known server request",
                    );
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
            }

            if is_valid_request(&req, &REGEX_FEDERATION_ENDPOINTS) {
                if self
                    .allowed_federation_domains
                    .contains_key(&req_ctx.destination)
                {
                    return self
                        .forward_request(
                            &mut req_ctx,
                            req.into_body(),
                            "200 - forward, valid and allowed federation request",
                        )
                        .await;
                } else {
                    req_ctx.log(Level::Warn, "forbid, not an allowed federation request");
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
            }

            // Servers need to be able to discover the client API of other servers too because of the legacy media API endpoints
            if is_valid_request_for_endpoint(&req, &REGEX_CLIENT_WELLKNOWN_ENDPOINT) {
                if self.allowed_servernames.contains(&req_ctx.destination) {
                    return self
                        .forward_request(
                            &mut req_ctx,
                            req.into_body(),
                            "200 - forward, valid and allowed client well-known request",
                        )
                        .await;
                } else {
                    req_ctx.log(
                        Level::Warn,
                        "forbid, not an allowed well-known client request",
                    );
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
            }

            if is_valid_request(&req, &REGEX_MEDIA_CLIENT_LEGACY_ENDPOINTS) {
                if self
                    .allowed_client_domains
                    .contains_key(&req_ctx.destination)
                {
                    return self
                        .forward_request(
                            &mut req_ctx,
                            req.into_body(),
                            "200 - forward, valid and allowed media client legacy request",
                        )
                        .await;
                } else {
                    req_ctx.log(
                        Level::Warn,
                        "forbid, not an allowed media client legacy request",
                    );
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
            }

            let normalized_uri = normalize_uri(req.uri());
            for regex in &self.allowed_non_matrix_regexes {
                if regex.is_match(normalized_uri.as_str()) {
                    return self
                        .forward_request(
                            &mut req_ctx,
                            req.into_body(),
                            "200 - forward,destination uri matches regex",
                        )
                        .await;
                }
            }

            req_ctx.log(Level::Warn, "404 - not found, unknown request");
            create_status_response(StatusCode::NOT_FOUND).into()
        }
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: http::Response<Body>,
    ) -> http::Response<Body> {
        res
    }
}

pub(crate) fn convert_response(
    response: http::Response<reqwest::Body>,
) -> Result<http::Response<hudsucker::Body>, anyhow::Error> {
    let (parts, body) = response.into_parts();
    let mut builder = http::Response::builder().status(parts.status);

    #[allow(clippy::unwrap_used, reason = "should never happen")]
    let headers = builder.headers_mut().unwrap();
    for (name, value) in &parts.headers {
        headers.insert(name, value.clone());
    }

    let stream = futures::StreamExt::map(body.into_data_stream(), |result| {
        result.map_err(std::io::Error::other)
    });

    builder
        .body(hudsucker::Body::from_stream(stream))
        .map_err(|e| anyhow::anyhow!("Error building response: {}", e))
}
