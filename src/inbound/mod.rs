use std::{collections::BTreeMap, future::Future};

use router::create_router;
use ruma::serde::Base64;

mod handlers;
mod router;

#[derive(Clone)]
pub(crate) struct GatewayState {
    http_client: reqwest::Client,
    destination_base_urls: BTreeMap<String, String>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
}

pub(crate) async fn create_proxy<F>(
    listening_addr: &str,
    shutdown_signal: F,
    destination_base_urls: BTreeMap<String, String>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
    allow_all_client_traffic: bool,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let state = GatewayState {
        http_client: create_http_client(),
        destination_base_urls: destination_base_urls,
        public_key_map: public_key_map,
    };

    let listener =
        tokio::net::TcpListener::bind::<std::net::SocketAddr>(listening_addr.parse().unwrap())
            .await
            .unwrap();
    axum::serve(
        listener,
        create_router(state, allow_all_client_traffic).into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await
    .unwrap();
}

#[cfg(feature = "rustls")]
fn create_http_client() -> reqwest::Client {
    reqwest::Client::builder().use_rustls_tls().build().unwrap()
}

#[cfg(feature = "native-tls")]
fn create_http_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}
