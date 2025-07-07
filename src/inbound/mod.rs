use std::{collections::BTreeMap, net::SocketAddr};

use router::create_router;
use ruma::serde::Base64;
use tokio::net::TcpListener;

use crate::util::{shutdown_signal, NameResolver};

mod handlers;
mod router;

#[derive(Clone)]
pub(crate) struct GatewayState {
    http_client: reqwest::Client,
    name_resolver: NameResolver,
    destination_base_urls: BTreeMap<String, String>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
}

pub async fn create_proxy(
    listening_addr: &str,
    http_client: reqwest::Client,
    name_resolver: NameResolver,
    destination_base_urls: BTreeMap<String, String>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
) -> Result<(), anyhow::Error> {
    let state = GatewayState {
        http_client,
        name_resolver,
        destination_base_urls,
        public_key_map,
    };

    let listener = TcpListener::bind::<SocketAddr>(listening_addr.parse()?).await?;
    axum::serve(
        listener,
        create_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| anyhow::anyhow!("Error starting inbound proxy: {}", e))
}
