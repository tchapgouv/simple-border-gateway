use axum_extra::headers::Header;
use http::{HeaderName, HeaderValue, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::Body as _;
use serde_json::{json, Value};

use crate::config::UpstreamProxyConfig;

#[cfg(feature = "aws_lc_rs")]
pub(crate) use hudsucker::rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub(crate) use hudsucker::rustls::crypto::ring as crypto_provider;

pub(crate) fn create_forbidden_json(errcode: &str, error_msg: Option<&str>) -> Value {
    if let Some(error_msg_val) = error_msg {
        json!({"errcode": errcode, "error": error_msg_val})
    } else {
        json!({"errcode": errcode})
    }
}

pub(crate) fn create_empty_response<B>(status: StatusCode) -> http::Response<B>
where
    B: Default,
{
    http::Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(B::default())
        .unwrap()
}

pub(crate) fn create_forbidden_response<B>(
    errcode: &str,
    error_msg: Option<&str>,
) -> http::Response<B>
where
    B: From<String>,
{
    http::Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "application/json")
        .body(B::from(
            crate::util::create_forbidden_json(errcode, error_msg).to_string(),
        ))
        .unwrap()
}

static X_FORWARDED_HOST_HEADER: &str = "x-forwarded-host";
static X_FORWARDED_HOST_HEADER_NAME: HeaderName = HeaderName::from_static(X_FORWARDED_HOST_HEADER);

pub(crate) struct XForwardedHost(pub String);

impl Header for XForwardedHost {
    fn name() -> &'static HeaderName {
        &X_FORWARDED_HOST_HEADER_NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i axum::http::HeaderValue>,
    {
        let value = values
            .next()
            .ok_or_else(axum_extra::headers::Error::invalid)?;
        let string = value.to_str().unwrap().to_string();
        Ok(XForwardedHost(string))
    }

    fn encode<E: Extend<axum::http::HeaderValue>>(&self, values: &mut E) {
        let value = HeaderValue::from_str(&self.0).unwrap();
        values.extend(std::iter::once(value));
    }
}

pub(crate) fn create_http_client(
    upstream_proxy_config: Option<UpstreamProxyConfig>,
) -> reqwest::Client {
    install_crypto_provider();
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(upstream_proxy_config) = upstream_proxy_config {
        builder = builder.proxy(reqwest::Proxy::all(upstream_proxy_config.url).unwrap());
        if let Some(ca_pem) = upstream_proxy_config.ca_pem {
            builder = builder
                .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap());
        }
    }
    builder.build().unwrap()
}

pub(crate) fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

pub(crate) async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

pub(crate) async fn convert_hudsucker_request_to_reqwest_request(
    req: http::Request<hudsucker::Body>,
    http_client: &reqwest::Client,
) -> Result<reqwest::Request, Box<dyn core::error::Error>> {
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
    let mut request_builder = http_client.request(method, url_str.parse::<reqwest::Url>()?);

    // Copy headers
    for (name, value) in req.headers() {
        request_builder = request_builder.header(name, value.clone());
    }

    // Handle body using streaming approach
    let (_, body) = req.into_parts();

    // Convert hudsucker Body to reqwest streaming body
    if !body.is_end_stream() {
        let stream = futures::StreamExt::map(body.into_data_stream(), |result| {
            result.map_err(std::io::Error::other)
        });
        request_builder = request_builder.body(reqwest::Body::wrap_stream(stream));
    }

    let request = request_builder.build()?;
    Ok(request)
}

pub(crate) async fn convert_reqwest_response_to_hudsucker_response(
    response: reqwest::Response,
) -> Result<http::Response<hudsucker::Body>, Box<dyn core::error::Error>> {
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
        hudsucker::Body::from_stream(futures::StreamExt::map(response.bytes_stream(), |result| {
            result.map_err(std::io::Error::other)
        }))
    } else {
        hudsucker::Body::empty()
    };

    response_builder
        .body(body)
        .map_err(|e| Box::new(e) as Box<dyn core::error::Error>)
}

pub(crate) fn set_req_authority_for_tests<B>(req: &mut http::Request<B>, authority: &str) {
    let parts = req.uri().clone().into_parts();
    let mut builder = http::uri::Builder::new()
        .scheme("http")
        .authority(authority);
    if let Some(path_and_query) = parts.path_and_query {
        builder = builder.path_and_query(path_and_query);
    }
    *req.uri_mut() = builder.build().unwrap();
}
