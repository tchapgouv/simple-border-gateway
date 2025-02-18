use std::collections::HashSet;

use http::{Method, StatusCode};
use lazy_static::lazy_static;
use log::{info, warn};
use regex::Regex;

use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::{
    matrix_spec::{
        Endpoint, CLIENT_WELLKNOWN_ENDPOINT, FEDERATION_ENDPOINTS, MEDIA_CLIENT_LEGACY_ENDPOINTS,
        SERVER_WELLKNOWN_ENDPOINT,
    },
    util::create_forbidden_response,
};

lazy_static! {
    static ref ENDPOINT_PATTERN_RE: Regex = Regex::new("\\{[^\\}]*}").unwrap();
    static ref REGEX_CLIENT_WELLKNOWN_ENDPOINT: RegexEndpoint = RegexEndpoint::from(CLIENT_WELLKNOWN_ENDPOINT);
    static ref REGEX_SERVER_WELLKNOWN_ENDPOINT: RegexEndpoint = RegexEndpoint::from(SERVER_WELLKNOWN_ENDPOINT);
    static ref REGEX_FEDERATION_ENDPOINTS: Vec<RegexEndpoint> =
        Vec::from_iter(FEDERATION_ENDPOINTS.map(RegexEndpoint::from));
    static ref REGEX_MEDIA_CLIENT_LEGACY_ENDPOINTS: Vec<RegexEndpoint> =
        Vec::from_iter(MEDIA_CLIENT_LEGACY_ENDPOINTS.map(RegexEndpoint::from));
}

#[derive(Clone)]
struct RegexEndpoint {
    regex: Regex,
    endpoint: Endpoint,
}

impl RegexEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        let regex_str = ENDPOINT_PATTERN_RE.replace_all(&endpoint.path, ".*");
        let regex = Regex::new(&regex_str).unwrap();
        RegexEndpoint { regex, endpoint }
    }
}

#[derive(Clone)]
pub(crate) struct LogHandler {
    allowed_servernames: HashSet<String>,
    allowed_federation_domains: HashSet<String>,
    allowed_client_domains: HashSet<String>,
    allowed_external_domains: HashSet<String>,
}

impl LogHandler {
    pub(crate) fn new(
        allowed_servernames: Vec<String>,
        allowed_federation_domains: Vec<String>,
        allowed_client_domains: Vec<String>,
        allowed_external_domains: Vec<String>,
    ) -> Self {
        LogHandler {
            allowed_servernames: HashSet::from_iter(allowed_servernames),
            allowed_federation_domains: HashSet::from_iter(allowed_federation_domains),
            allowed_client_domains: HashSet::from_iter(allowed_client_domains),
            allowed_external_domains: HashSet::from_iter(allowed_external_domains),
        }
    }
}

fn is_valid_request(req: &http::Request<Body>, allowed_endpoints: &[RegexEndpoint]) -> bool {
    for endpoint in allowed_endpoints {
        if is_valid_request_for_endpoint(req, endpoint) {
            return true;
        }
    }
    return false;
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
    return false;
}

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: http::Request<Body>,
    ) -> RequestOrResponse {
        let method = req.method();
        if method != Method::CONNECT {
            let destination = req.uri().host().unwrap_or("");
            let path_and_query = req
                .uri()
                .path_and_query()
                .map_or("", |p| p.as_str())
                .to_owned();
            if self.allowed_external_domains.contains(destination) {
                info!(
                    "{destination} {method} {path_and_query} : destination in allowed_external_domains, forward",
                );
                return req.into();
            }

            if is_valid_request_for_endpoint(&req, &REGEX_SERVER_WELLKNOWN_ENDPOINT) {
                if self.allowed_servernames.contains(destination) {
                    info!(
                        "{destination} {method} {path_and_query} : valid and allowed server well-known request, forward",
                    );
                    return req.into();
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
                    return req.into();
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
                    return req.into();
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
                    return req.into();
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
