use std::collections::HashSet;

use http::{Method, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use lazy_static::lazy_static;
use log::{info, warn};
use regex::Regex;

use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::{
    matrix_spec::{
        Endpoint, CLIENT_WELLKNOWN_ENDPOINT, FEDERATION_ENDPOINTS, MEDIA_CLIENT_LEGACY_ENDPOINTS,
        SERVER_WELLKNOWN_ENDPOINT,
    },
    util::{create_forbidden_response, create_http_client},
};

lazy_static! {
    static ref ENDPOINT_PATTERN_RE: Regex = Regex::new("\\{[^\\}]*}").unwrap();
    static ref REGEX_CLIENT_WELLKNOWN_ENDPOINT: RegexEndpoint =
        RegexEndpoint::from(CLIENT_WELLKNOWN_ENDPOINT);
    static ref REGEX_SERVER_WELLKNOWN_ENDPOINT: RegexEndpoint =
        RegexEndpoint::from(SERVER_WELLKNOWN_ENDPOINT);
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
        let regex_str = ENDPOINT_PATTERN_RE.replace_all(endpoint.path, ".*");
        let regex = Regex::new(&regex_str).unwrap();
        RegexEndpoint { regex, endpoint }
    }
}

#[derive(Clone)]
pub(crate) struct LogHandler {
    http_client: reqwest::Client,
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
            http_client: create_http_client(upstream_proxy),
            allowed_servernames: HashSet::from_iter(allowed_servernames),
            allowed_federation_domains: HashSet::from_iter(allowed_federation_domains),
            allowed_client_domains: HashSet::from_iter(allowed_client_domains),
            allowed_external_domains: HashSet::from_iter(allowed_external_domains),
            _for_tests_only_mock_server_host,
        }
    }

    async fn execute_request_with_reqwest(
        &self,
        req: http::Request<Body>,
    ) -> Result<http::Response<Body>, Box<dyn std::error::Error>> {
        let request = self
            .convert_hudsucker_request_to_reqwest_request(req)
            .await?;
        let response = self.http_client.execute(request).await?;
        Ok(self
            .convert_reqwest_response_to_hudsucker_response(response)
            .await?
            .into())
    }

    async fn convert_hudsucker_request_to_reqwest_request(
        &self,
        req: http::Request<Body>,
    ) -> Result<reqwest::Request, Box<dyn std::error::Error>> {
        // Extract URI components
        let uri = req.uri();
        let method = req.method().clone();

        // Build the URL
        let url_str = if uri.scheme().is_none() || uri.authority().is_none() {
            // If scheme or authority is missing, assume it's a relative URL
            format!(
                "{}://{}{}",
                uri.scheme().unwrap_or(&http::uri::Scheme::HTTP),
                uri.authority()
                    .unwrap_or(&http::uri::Authority::from_static("localhost")),
                uri.path_and_query().map(|p| p.as_str()).unwrap_or("")
            )
        } else {
            // Full URL is available
            uri.to_string()
        };

        // Create reqwest request builder
        let mut request_builder = self
            .http_client
            .request(method, url_str.parse::<reqwest::Url>()?);

        // Copy headers
        for (name, value) in req.headers() {
            request_builder = request_builder.header(name, value.clone());
        }

        // Handle body using streaming approach
        let (_, body) = req.into_parts();

        // Convert hudsucker Body to reqwest streaming body
        if !body.is_end_stream() {
            let stream = futures::StreamExt::map(body.into_data_stream(), |result| {
                result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            });
            request_builder = request_builder.body(reqwest::Body::wrap_stream(stream));
        }

        let request = request_builder.build()?;
        Ok(request)
    }

    async fn convert_reqwest_response_to_hudsucker_response(
        &self,
        response: reqwest::Response,
    ) -> Result<http::Response<Body>, Box<dyn std::error::Error>> {
        // Build the response
        let status = response.status();
        let mut response_builder = http::Response::builder().status(status);

        // Copy headers
        let headers = response_builder.headers_mut().unwrap();
        for (name, value) in response.headers() {
            headers.insert(name, value.clone());
        }

        // Handle the response body
        let body = if response.content_length().is_none_or(|length| length > 0) {
            Body::from_stream(futures::StreamExt::map(response.bytes_stream(), |result| {
                result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            }))
        } else {
            Body::empty()
        };

        Ok(response_builder
            .body(body)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?)
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
                return self.execute_request_with_reqwest(req).await.unwrap().into();
            }

            if is_valid_request_for_endpoint(&req, &REGEX_SERVER_WELLKNOWN_ENDPOINT) {
                if self.allowed_servernames.contains(destination) {
                    info!(
                        "{destination} {method} {path_and_query} : valid and allowed server well-known request, forward",
                    );
                    return self.execute_request_with_reqwest(req).await.unwrap().into();
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
                    return self.execute_request_with_reqwest(req).await.unwrap().into();
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
                    return self.execute_request_with_reqwest(req).await.unwrap().into();
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
                    return self.execute_request_with_reqwest(req).await.unwrap().into();
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
