use std::convert::Infallible;

use axum::{
    handler::Handler,
    routing::{self, any, MethodRouter},
    Router,
};
use http::Method;
use tower_http::trace;
use tracing::Level;

use crate::matrix_spec::{AuthType, CLIENT_GLOBAL_ENDPOINT, FEDERATION_ENDPOINTS};

use super::{
    handlers::{forbidden_handler, forward_handler, verify_signature_handler},
    GatewayState,
};

pub(crate) fn create_router(state: GatewayState, allow_all_client_traffic: bool) -> Router {
    let mut r = Router::new().layer(
        trace::TraceLayer::new_for_http()
            .make_span_with(trace::DefaultMakeSpan::new().level(Level::TRACE))
            .on_response(trace::DefaultOnResponse::new().level(Level::TRACE)),
    );

    for endpoint in FEDERATION_ENDPOINTS {
        r = match endpoint.auth_type {
            AuthType::Unauthenticated => r.route(
                &endpoint.path,
                get_method_router(endpoint.method, forward_handler),
            ),
            AuthType::CheckSignature => r.route(
                &endpoint.path,
                get_method_router(endpoint.method, verify_signature_handler),
            ),
            // AuthType::Forbidden => r.route(
            //     &endpoint.path,
            //     get_method_router(endpoint.method, forbidden_handler),
            // ),
        };
    }

    if allow_all_client_traffic {
        r = r.route(CLIENT_GLOBAL_ENDPOINT, any(forward_handler));
    }

    r = r.fallback(forbidden_handler);

    r.with_state(state)
}

pub fn get_method_router<H, T, S>(method: Option<Method>, handler: H) -> MethodRouter<S, Infallible>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    match method {
        Some(Method::GET) => routing::get(handler),
        Some(Method::POST) => routing::post(handler),
        Some(Method::PUT) => routing::put(handler),
        Some(Method::HEAD) => routing::head(handler),
        Some(Method::DELETE) => routing::delete(handler),
        Some(Method::OPTIONS) => routing::options(handler),
        Some(Method::PATCH) => routing::patch(handler),
        Some(Method::TRACE) => routing::trace(handler),
        Some(Method::CONNECT) => routing::connect(handler),
        Some(_) | None => routing::any(handler),
    }
}
