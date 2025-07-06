use std::{collections::BTreeMap, net::SocketAddr};

use crate::util::{create_matrix_response, create_status_response, ReqContext};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use log::Level;
use ruma::{
    server_util::authorization::XMatrix,
    signatures::{verify_json, PublicKeyMap},
    CanonicalJsonObject, CanonicalJsonValue,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::GatewayState;

const INBOUND_PREFIX: &str = "IN ";

fn create_req_context(
    req: &Request<Body>,
    socket_addr: SocketAddr,
    state: &mut GatewayState,
) -> ReqContext {
    ReqContext::new(
        req,
        socket_addr,
        state.http_client.clone(),
        state.name_resolver.clone(),
        INBOUND_PREFIX.to_string(),
    )
}

async fn forward_request(
    mut req_ctx: ReqContext,
    body: Body,
    success_log_text: &str,
    state: &mut GatewayState,
) -> http::Response<Body> {
    let Some(dest_base_url) = state.destination_base_urls.get(&req_ctx.destination) else {
        req_ctx.log(Level::Warn, "404 - destination unknown");
        return create_status_response(StatusCode::NOT_FOUND);
    };

    let response = req_ctx
        .forward_request(body.into_data_stream(), Some(dest_base_url))
        .await;

    match convert_response(response) {
        Ok(convert_res) => {
            req_ctx.log(Level::Info, success_log_text);
            convert_res
        }
        Err(e) => {
            req_ctx.log(
                Level::Warn,
                &format!("503 - error converting response: {e}"),
            );
            create_status_response(StatusCode::BAD_GATEWAY)
        }
    }
}

pub(crate) async fn forbidden_handler(
    State(mut state): State<GatewayState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> http::Response<Body> {
    let mut req_ctx = create_req_context(&req, socket_addr, &mut state);
    req_ctx.log(Level::Warn, "403 - always forbid");
    create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN")
}

pub(crate) async fn forward_handler(
    State(mut state): State<GatewayState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> http::Response<Body> {
    let req_ctx = create_req_context(&req, socket_addr, &mut state);
    forward_request(req_ctx, req.into_body(), "200 - always forward", &mut state).await
}

pub(crate) async fn verify_signature_handler(
    State(mut state): State<GatewayState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> http::Response<Body> {
    let mut req_ctx = create_req_context(&req, socket_addr, &mut state);

    let Some(auth_header) = req_ctx.headers.get("Authorization") else {
        req_ctx.log(Level::Warn, "403 - forbid, no authorization header");
        // TODO create_forbidden_response or not ? synapse behavior to check
        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN");
    };

    let Ok(x_matrix) = XMatrix::parse(auth_header.to_str().unwrap_or_default()) else {
        req_ctx.log(Level::Warn, "403 - forbid, invalid X-Matrix auth header");
        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN");
    };

    // let's override the origin with the server name from the X-Matrix header
    req_ctx.origin = x_matrix.origin.clone().to_string();
    if !state.public_key_map.contains_key(req_ctx.origin.as_str()) {
        req_ctx.log(Level::Warn, "403 - forbid, unauthorized server");
        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN");
    }

    let Ok(body) = to_bytes(req.into_body(), 1024 * 1024 * 10).await else {
        req_ctx.log(Level::Warn, "403 - forbid, req body too large");
        return create_status_response(StatusCode::FORBIDDEN);
    };

    let Ok(body) = String::from_utf8(body.to_vec()) else {
        req_ctx.log(Level::Warn, "403 - forbid, req body not utf8");
        return create_status_response(StatusCode::FORBIDDEN);
    };

    match verify_signature(&state.public_key_map, &req_ctx, x_matrix, &body) {
        Ok(_) => {
            forward_request(
                req_ctx,
                Body::from(body),
                "200 - forward, authorized server and signature ok",
                &mut state,
            )
            .await
        }
        Err(e) => {
            req_ctx.log(
                Level::Warn,
                &format!("403 - forbid, authorized server but wrong signature: {e}"),
            );
            #[allow(clippy::unwrap_used, reason = "no intrusted input")]
            create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN")
        }
    }
}

#[derive(Deserialize, Serialize)]
struct SignedRequest {
    method: String,
    uri: String,
    origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<Value>,
    signatures: BTreeMap<String, BTreeMap<String, String>>,
}

fn verify_signature(
    public_key_map: &PublicKeyMap,
    req_ctx: &ReqContext,
    x_matrix: XMatrix,
    body: &str,
) -> Result<(), anyhow::Error> {
    let content_json: Option<Value> = serde_json::from_str(body).ok();

    let signatures = BTreeMap::from([(
        x_matrix.origin.to_string(),
        BTreeMap::from([(x_matrix.key.to_string(), x_matrix.sig.to_string())]),
    )]);

    let signed_req = SignedRequest {
        method: req_ctx.method.to_string(),
        uri: req_ctx.path_and_query().to_string(),
        origin: x_matrix.origin.as_str().to_owned(),
        destination: x_matrix.destination.map(|d| d.to_string()),
        content: content_json,
        signatures,
    };

    let json_value = serde_json::to_value(signed_req)
        .map_err(|e| anyhow::anyhow!("Failed to convert signed request to JSON: {e}"))?;

    let canonical_signed_json: CanonicalJsonValue = json_value
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert JSON to canonical JSON: {e}"))?;

    let canonical_signed_json: &CanonicalJsonObject = canonical_signed_json.as_object().ok_or(
        anyhow::anyhow!("Failed to convert canonical JSON value to object"),
    )?;

    verify_json(public_key_map, canonical_signed_json)
        .map_err(|e| anyhow::anyhow!("Failed to verify signature: {e}"))
}

fn convert_response(
    resp: http::Response<reqwest::Body>,
) -> Result<http::Response<Body>, http::Error> {
    let mut builder = http::Response::builder().status(resp.status());
    for (name, value) in resp.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Body::from_stream(resp.into_body().into_data_stream()))
}
