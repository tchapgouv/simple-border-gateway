use std::collections::BTreeMap;

use crate::util::{
    create_empty_response, create_forbidden_response, remove_default_ports, XForwardedFor,
    XForwardedHost,
};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, Uri},
};
use axum_extra::TypedHeader;
use http::StatusCode;
use log::{info, warn};
use ruma::{
    server_util::authorization::XMatrix,
    signatures::{verify_json, Error, PublicKeyMap},
    CanonicalJsonValue,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::GatewayState;

static INBOUND_PREFIX: &str = "IN :";

pub(crate) async fn forbidden_handler(
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedFor(origin)): TypedHeader<XForwardedFor>,
    TypedHeader(XForwardedHost(destination)): TypedHeader<XForwardedHost>,
) -> http::Response<Body> {
    let destination = remove_default_ports(&destination);

    warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : always forbid");
    create_forbidden_response("M_FORBIDDEN", None)
}

pub(crate) async fn forward_handler(
    State(state): State<GatewayState>,
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedFor(origin)): TypedHeader<XForwardedFor>,
    TypedHeader(XForwardedHost(destination)): TypedHeader<XForwardedHost>,
    headers: HeaderMap,
    request: Request<Body>,
) -> http::Response<Body> {
    let destination = remove_default_ports(&destination);

    info!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : always forward");
    forward_incoming_request(
        state,
        method,
        uri.path_and_query().map_or("", |p| p.as_str()),
        &destination,
        &origin,
        headers,
        request.into_body(),
    )
    .await
}

pub(crate) async fn verify_signature_handler(
    State(state): State<GatewayState>,
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedFor(origin)): TypedHeader<XForwardedFor>,
    TypedHeader(XForwardedHost(destination)): TypedHeader<XForwardedHost>,
    headers: HeaderMap,
    body: String,
) -> http::Response<Body> {
    let destination = remove_default_ports(&destination);

    let Some(auth_header) = headers.get("Authorization") else {
        warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : forbid, no authorization header");
        return create_empty_response(StatusCode::FORBIDDEN);
    };

    let x_matrix = match XMatrix::parse(auth_header.to_str().unwrap_or_default()) {
        Ok(x_matrix) => x_matrix,
        Err(e) => {
            warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : forbid, invalid X-Matrix auth header, {e}");
            return create_empty_response(StatusCode::FORBIDDEN);
        }
    };

    let origin = x_matrix.origin.clone();
    if !state.public_key_map.contains_key(origin.as_str()) {
        warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : forbid, unauthorized server");
        return create_empty_response(StatusCode::FORBIDDEN);
    }

    match verify_signature(
        &state.public_key_map,
        &method,
        &uri,
        x_matrix,
        body.as_str(),
    ) {
        Ok(_) => {
            info!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : forward, authorized server and signature ok");
            forward_incoming_request(
                state,
                method,
                uri.path_and_query().map_or("", |p| p.as_str()),
                &destination,
                origin.as_str(),
                headers,
                Body::from(body),
            )
            .await
        }
        Err(e) => {
            warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : forbid, authorized server but wrong signature, {e}");
            create_empty_response(StatusCode::FORBIDDEN)
        }
    }
}

#[derive(Deserialize, Serialize)]
struct SignedRequest {
    method: String,
    uri: String,
    origin: String,
    destination: Option<String>,
    content: Option<Value>,
    signatures: BTreeMap<String, BTreeMap<String, String>>,
}

fn verify_signature(
    public_key_map: &PublicKeyMap,
    method: &Method,
    uri: &Uri,
    x_matrix: XMatrix,
    body: &str,
) -> Result<(), Error> {
    let content_json: Option<Value> = serde_json::from_str(body).unwrap_or(None);

    let signatures = BTreeMap::from([(
        x_matrix.origin.to_string(),
        BTreeMap::from([(x_matrix.key.to_string(), x_matrix.sig.to_string())]),
    )]);

    let signed_req = SignedRequest {
        method: method.to_string(),
        uri: uri.path_and_query().map_or("", |p| p.as_str()).to_owned(),
        origin: x_matrix.origin.as_str().to_owned(),
        destination: x_matrix.destination.map(|d| d.to_string()),
        content: content_json,
        signatures,
    };

    let canonical_signed_json: CanonicalJsonValue = serde_json::to_value(signed_req)
        .unwrap() // TODO
        .try_into()
        .unwrap(); // TODO

    verify_json(public_key_map, canonical_signed_json.as_object().unwrap()) // TODO
}

pub(crate) async fn forward_incoming_request(
    state: GatewayState,
    method: Method,
    path_and_query: &str,
    destination: &str,
    origin: &str,
    headers: HeaderMap,
    body: Body,
) -> http::Response<Body> {
    let dest_base_url = if let Some(dest_base_url) =
        state.destination_base_urls.clone().get(destination)
    {
        dest_base_url.clone()
    } else {
        warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {path_and_query} : block, destination unknown");
        return create_empty_response(StatusCode::BAD_GATEWAY);
    };

    let res = state
        .http_client
        .request(method.clone(), format!("{dest_base_url}{path_and_query}"))
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await;

    match res {
        Ok(resp) => convert_response(resp).unwrap(), // TODO
        Err(e) => {
            warn!("{INBOUND_PREFIX} {method} {path_and_query} : block, error forwarding the req to {dest_base_url}, {e}");
            create_empty_response(StatusCode::BAD_GATEWAY)
        }
    }
}

fn convert_response(resp: reqwest::Response) -> Result<http::Response<Body>, http::Error> {
    let mut builder = http::Response::builder().status(resp.status());
    for (name, value) in resp.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Body::from_stream(resp.bytes_stream()))
}
