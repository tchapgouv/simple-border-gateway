use std::collections::HashSet;

use http::{Method, StatusCode};
use log::{info, warn};
use regex::Regex;

use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::{
    matrix_spec::{
        Endpoint, CLIENT_WELLKNOWN_ENDPOINT, FEDERATION_ENDPOINTS, MEDIA_CLIENT_LEGACY_ENDPOINTS,
        SERVER_WELLKNOWN_ENDPOINT,
    },
    util::{
        convert_hudsucker_request_to_reqwest_request,
        convert_reqwest_response_to_hudsucker_response, create_forbidden_response,
        create_http_client,
    },
};

static ENDPOINT_PATTERN_RE: std::sync::LazyLock<Regex> =
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
        let regex_str = ENDPOINT_PATTERN_RE.replace_all(endpoint.path, ".*");
        let regex = Regex::new(&regex_str).unwrap();
        RegexEndpoint { regex, endpoint }
    }
}

#[derive(Clone)]
pub(crate) struct LogHandler {
    http_client: Option<reqwest::Client>,
    allowed_servernames: HashSet<String>,
    allowed_federation_domains: HashSet<String>,
    allowed_client_domains: HashSet<String>,
    allowed_external_domains: HashSet<String>,
    _for_tests_only_mock_server_host: Option<String>,
}

impl LogHandler {
    pub(crate) fn new(
        allowed_servernames: Vec<String>,
        allowed_federation_domains: Vec<String>,
        allowed_client_domains: Vec<String>,
        allowed_external_domains: Vec<String>,
        upstream_proxy: Option<String>,
        _for_tests_only_mock_server_host: Option<String>,
    ) -> Self {
        LogHandler {
            http_client: upstream_proxy
                .map(|upstream_proxy| create_http_client(Some(upstream_proxy))),
            allowed_servernames: HashSet::from_iter(allowed_servernames),
            allowed_federation_domains: HashSet::from_iter(allowed_federation_domains),
            allowed_client_domains: HashSet::from_iter(allowed_client_domains),
            allowed_external_domains: HashSet::from_iter(allowed_external_domains),
            _for_tests_only_mock_server_host,
        }
    }

    async fn forward_outgoing_request(
        &self,
        req: http::Request<Body>,
    ) -> Result<RequestOrResponse, Box<dyn core::error::Error>> {
        // `http_client` is defined if an upstream proxy is configured
        // In this case, we need to execute the request with reqwest `http_client`,
        // which is already configured to u
        if let Some(http_client) = &self.http_client {
            let request = convert_hudsucker_request_to_reqwest_request(req, http_client).await?;
            let response = http_client.execute(request).await?;
            Ok(convert_reqwest_response_to_hudsucker_response(response)
                .await?
                .into())
        } else {
            Ok(req.into())
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

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: http::Request<Body>,
    ) -> RequestOrResponse {
        let method = req.method().clone();
        if method != Method::CONNECT {
            let uri = req.uri().clone();
            let destination = uri.host().unwrap_or("");

            if let Some(host) = &self._for_tests_only_mock_server_host {
                let parts = uri.clone().into_parts();
                let mut builder = http::uri::Builder::new()
                    .scheme("http")
                    .authority(host.as_str());
                if let Some(path_and_query) = parts.path_and_query {
                    builder = builder.path_and_query(path_and_query);
                }
                *req.uri_mut() = builder.build().unwrap();
            }

            let path_and_query = req
                .uri()
                .path_and_query()
                .map_or("", |p| p.as_str())
                .to_owned();
            if self.allowed_external_domains.contains(destination) {
                info!(
                    "{destination} {method} {path_and_query} : destination in allowed_external_domains, forward",
                );
                return self.forward_outgoing_request(req).await.unwrap();
            }

            if is_valid_request_for_endpoint(&req, &REGEX_SERVER_WELLKNOWN_ENDPOINT) {
                if self.allowed_servernames.contains(destination) {
                    info!(
                        "{destination} {method} {path_and_query} : valid and allowed server well-known request, forward",
                    );
                    return self.forward_outgoing_request(req).await.unwrap();
                } else {
                    warn!(
                        "{destination} {method} {path_and_query} : not an allowed well-known server request, block",
                    );
                    return create_forbidden_response("M_FORBIDDEN", None).into();
                }
            }

            if is_valid_request_for_endpoint(&req, &REGEX_CLIENT_WELLKNOWN_ENDPOINT) {
                if self.allowed_servernames.contains(destination) {
                    info!(
                        "{destination} {method} {path_and_query} : valid and allowed client well-known request, forward",
                    );
                    return self.forward_outgoing_request(req).await.unwrap();
                } else {
                    warn!(
                        "{destination} {method} {path_and_query} : not an allowed well-known client request, block",
                    );
                    return create_forbidden_response("M_FORBIDDEN", None).into();
                }
            }

            if is_valid_request(&req, &REGEX_FEDERATION_ENDPOINTS) {
                if self.allowed_federation_domains.contains(destination) {
                    info!(
                        "{destination} {method} {path_and_query} : valid and allowed federation request, forward",
                    );
                    return self.forward_outgoing_request(req).await.unwrap();
                } else {
                    warn!(
                        "{destination} {method} {path_and_query} : not an allowed federation request, block",
                    );
                    return create_forbidden_response("M_FORBIDDEN", None).into();
                }
            }

            if is_valid_request(&req, &REGEX_MEDIA_CLIENT_LEGACY_ENDPOINTS) {
                if self.allowed_client_domains.contains(destination) {
                    info!(
                        "{destination} {method} {path_and_query} : valid and allowed media client legacy request, forward",
                    );
                    return self.forward_outgoing_request(req).await.unwrap();
                } else {
                    warn!(
                        "{destination} {method} {path_and_query} : not an allowed media client legacy request, block",
                    );
                    return create_forbidden_response("M_FORBIDDEN", None).into();
                }
            }

            warn!("{destination} {method} {path_and_query} : unknown request, block",);

            http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
                .unwrap()
                .into()
        } else {
            req.into()
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
