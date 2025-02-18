use axum_extra::headers::Header;
use http::{HeaderName, HeaderValue, StatusCode};
use serde_json::{json, Value};

pub(crate) fn create_forbidden_json(errcode: &str, error_msg: Option<&str>) -> Value {
    return if let Some(error_msg_val) = error_msg {
        json!({"errcode": errcode, "error": error_msg_val})
    } else {
        json!({"errcode": errcode})
    };
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

static X_FORWARDED_HOST_HEADER: &'static str = "x-forwarded-host";
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

#[cfg(feature = "rustls")]
pub(crate) fn create_http_client() -> reqwest::Client {
    reqwest::Client::builder().use_rustls_tls().build().unwrap()
}

#[cfg(feature = "native-tls")]
pub(crate) fn create_http_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}
