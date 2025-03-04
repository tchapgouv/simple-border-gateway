use axum_extra::headers::Header;
use http::{HeaderName, HeaderValue, StatusCode};
use serde_json::{json, Value};

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

pub(crate) fn create_http_client(upstream_proxy: Option<String>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(upstream_proxy) = upstream_proxy {
        builder = builder.proxy(reqwest::Proxy::all(upstream_proxy).unwrap());
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
