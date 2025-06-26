use axum_extra::headers::Header;
use http::{HeaderName, HeaderValue, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::Body as _;
use regex::Regex;
use serde_json::{json, Value};

use crate::config::UpstreamProxyConfig;

#[cfg(feature = "aws_lc_rs")]
pub use hudsucker::rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use hudsucker::rustls::crypto::ring as crypto_provider;

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

static X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
static X_FORWARDED_FOR_HEADER_NAME: HeaderName = HeaderName::from_static(X_FORWARDED_FOR_HEADER);

pub(crate) struct XForwardedFor(pub String);

impl Header for XForwardedFor {
    fn name() -> &'static HeaderName {
        &X_FORWARDED_FOR_HEADER_NAME
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
        Ok(XForwardedFor(string))
    }

    fn encode<E: Extend<axum::http::HeaderValue>>(&self, values: &mut E) {
        let value = HeaderValue::from_str(&self.0).unwrap();
        values.extend(std::iter::once(value));
    }
}

pub(crate) fn create_http_client(
    upstream_proxy_config: Option<UpstreamProxyConfig>,
) -> Result<reqwest::Client, reqwest::Error> {
    install_crypto_provider();
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(upstream_proxy_config) = upstream_proxy_config {
        let mut proxy_config = reqwest::Proxy::all(upstream_proxy_config.url)?;
        if let Some(auth) = upstream_proxy_config.auth {
            proxy_config = proxy_config.basic_auth(auth.username.as_str(), auth.password.as_str());
        }
        builder = builder.proxy(proxy_config);
        if let Some(ca_pem) = upstream_proxy_config.ca_pem {
            builder =
                builder.add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes())?);
        }
    }
    builder.build()
}

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

pub async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

pub(crate) async fn convert_hudsucker_request_to_reqwest_request(
    req: http::Request<hudsucker::Body>,
    http_client: &reqwest::Client,
) -> Result<reqwest::Request, Box<dyn core::error::Error>> {
    let uri = req.uri();
    let method = req.method().clone();

    let mut request_builder = http_client.request(method, uri.to_string().parse::<reqwest::Url>()?);

    for (name, value) in req.headers() {
        request_builder = request_builder.header(name, value.clone());
    }

    let (_, body) = req.into_parts();

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
    let status = response.status();
    let mut response_builder = http::Response::builder().status(status);

    let headers = response_builder.headers_mut().unwrap();
    for (name, value) in response.headers() {
        headers.insert(name, value.clone());
    }

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

pub fn set_req_scheme_and_authority<B>(req: &mut http::Request<B>, scheme: &str, authority: &str) {
    let parts = req.uri().clone().into_parts();
    let mut builder = http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority);
    if let Some(path_and_query) = parts.path_and_query {
        builder = builder.path_and_query(path_and_query);
    }
    *req.uri_mut() = builder.build().unwrap();
}

pub(crate) fn normalize_uri(uri: &http::Uri) -> String {
    let uri_str = uri.to_string();
    match fluent_uri::Uri::parse(uri_str.clone()) {
        Ok(fluent_uri) => fluent_uri.normalize().to_string(),
        Err(_) => uri_str,
    }
}

static REMOVE_DEFAULT_PORTS_REGEX: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(:443|:80)$").unwrap());

pub(crate) fn remove_default_ports(host: &str) -> String {
    REMOVE_DEFAULT_PORTS_REGEX.replace_all(host, "").to_string()
}
