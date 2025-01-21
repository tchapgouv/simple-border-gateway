use std::{collections::BTreeMap, future::Future};

use router::create_router;
use ruma::serde::Base64;

use crate::config::InternalHomeserver;

mod handlers;
mod router;

#[derive(Clone)]
pub(crate) struct GatewayState {
    http_client: reqwest::Client,
    destination_homeservers: BTreeMap<String, InternalHomeserver>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
}

pub(crate) async fn create_proxy<F>(
    listening_addr: &str,
    shutdown_signal: F,
    destination_homeservers: BTreeMap<String, InternalHomeserver>,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let state = GatewayState {
        http_client: reqwest::Client::new(),
        destination_homeservers: destination_homeservers,
        public_key_map: public_key_map,
    };

    let listener =
        tokio::net::TcpListener::bind::<std::net::SocketAddr>(listening_addr.parse().unwrap())
            .await
            .unwrap();
    axum::serve(listener, create_router(state).into_make_service())
        .with_graceful_shutdown(shutdown_signal)
        .await
        .unwrap();
}
