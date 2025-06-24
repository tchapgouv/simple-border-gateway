use std::{collections::BTreeMap, future::Future};

use router::create_router;
use ruma::serde::Base64;

use crate::util::create_http_client;

mod handlers;
mod router;

#[derive(Clone)]
pub(crate) struct GatewayState {
    http_client: reqwest::Client,
    destination_base_urls: BTreeMap<String, String>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
}

pub async fn create_proxy<F>(
    listening_addr: &str,
    shutdown_signal: F,
    destination_base_urls: BTreeMap<String, String>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: Future<Output = ()> + Send + 'static,
{
    let state = GatewayState {
        http_client: create_http_client(None)?,
        destination_base_urls,
        public_key_map,
    };

    let listener =
        tokio::net::TcpListener::bind::<std::net::SocketAddr>(listening_addr.parse().unwrap())
            .await
            .unwrap();
    Ok(
        axum::serve(listener, create_router(state).into_make_service())
            .with_graceful_shutdown(shutdown_signal)
            .await
            .unwrap(),
    )
}
