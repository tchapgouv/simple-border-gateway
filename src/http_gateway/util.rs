use http::StatusCode;

#[cfg(feature = "aws_lc_rs")]
pub use hudsucker::rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use hudsucker::rustls::crypto::ring as crypto_provider;

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

pub async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

pub(crate) fn read_pem(path_or_content: &str) -> Result<String, anyhow::Error> {
    let bytes = if path_or_content.starts_with("----") {
        path_or_content.as_bytes().to_vec()
    } else {
        std::fs::read(path_or_content)?
    };
    Ok(String::from_utf8(bytes)?)
}

pub(crate) fn create_response<B: From<String>>(
    status: StatusCode,
    body_and_content_type: Option<(B, &str)>,
) -> Result<http::Response<B>, http::Error> {
    let builder = http::Response::builder().status(status);
    if let Some((body, content_type)) = body_and_content_type {
        return builder.header("Content-Type", content_type).body(body);
    }
    builder.body(B::from("".to_string()))
}

pub(crate) fn create_status_response<B: From<String>>(status: StatusCode) -> http::Response<B> {
    #[allow(clippy::unwrap_used, reason = "no intrusted input")]
    create_response(status, None).unwrap()
}
