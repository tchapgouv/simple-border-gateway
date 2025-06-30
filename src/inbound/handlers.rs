use std::collections::BTreeMap;

use crate::util::{create_forbidden_response, create_response, XForwardedFor, XForwardedHost};
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
    State(mut state): State<GatewayState>,
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedFor(origin)): TypedHeader<XForwardedFor>,
    TypedHeader(XForwardedHost(destination)): TypedHeader<XForwardedHost>,
) -> http::Response<Body> {
    let destination = state.server_name_resolver.from_domain(&destination);

    warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 403 - always forbid");
    create_forbidden_response("M_FORBIDDEN", None)
}

pub(crate) async fn forward_handler(
    State(mut state): State<GatewayState>,
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedFor(origin)): TypedHeader<XForwardedFor>,
    TypedHeader(XForwardedHost(destination)): TypedHeader<XForwardedHost>,
    headers: HeaderMap,
    request: Request<Body>,
) -> http::Response<Body> {
    let destination = state.server_name_resolver.from_domain(&destination);

    let res = forward_incoming_request(
        state,
        &method,
        uri.path_and_query().map_or("", |p| p.as_str()),
        &destination,
        &origin,
        headers,
        request.into_body(),
    )
    .await;
    match res {
        Ok(res) => {
            info!(
                "{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 200 - always forward"
            );
            res
        }
        Err(e) => {
            warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 503 - error forwarding to {destination}, {e}");
            create_response(StatusCode::BAD_GATEWAY, None)
        }
    }
}

pub(crate) async fn verify_signature_handler(
    State(mut state): State<GatewayState>,
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedFor(origin)): TypedHeader<XForwardedFor>,
    TypedHeader(XForwardedHost(destination)): TypedHeader<XForwardedHost>,
    headers: HeaderMap,
    body: String,
) -> http::Response<Body> {
    let destination = state.server_name_resolver.from_domain(&destination);

    let Some(auth_header) = headers.get("Authorization") else {
        warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 403 - forbid, no authorization header");
        // TODO create_forbidden_response or not ? synapse behavior to check
        return create_response(StatusCode::FORBIDDEN, None);
    };

    let x_matrix = match XMatrix::parse(auth_header.to_str().unwrap_or_default()) {
        Ok(x_matrix) => x_matrix,
        Err(e) => {
            warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 403 - forbid, invalid X-Matrix auth header, {e}");
            return create_response(StatusCode::FORBIDDEN, None);
        }
    };

    let origin = x_matrix.origin.clone();
    if !state.public_key_map.contains_key(origin.as_str()) {
        warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 403 - forbid, unauthorized server");
        return create_response(StatusCode::FORBIDDEN, None);
    }

    match verify_signature(
        &state.public_key_map,
        &method,
        &uri,
        x_matrix,
        body.as_str(),
    ) {
        Ok(_) => {
            let res = forward_incoming_request(
                state,
                &method,
                uri.path_and_query().map_or("", |p| p.as_str()),
                &destination,
                origin.as_str(),
                headers,
                Body::from(body),
            )
            .await;
            match res {
                Ok(res) => {
                    info!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 200 - authorized server and signature ok");
                    res
                }
                Err(e) => {
                    warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 503 - error forwarding to {destination}, {e}");
                    create_response(StatusCode::BAD_GATEWAY, None)
                }
            }
        }
        Err(e) => {
            warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {uri} : 403 - forbid, authorized server but wrong signature, {e}");
            create_response(StatusCode::FORBIDDEN, None) // TODO create_forbidden_response
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
    method: &Method,
    path_and_query: &str,
    destination: &str,
    origin: &str,
    headers: HeaderMap,
    body: Body,
) -> Result<http::Response<Body>, http::Error> {
    let dest_base_url = if let Some(dest_base_url) =
        state.destination_base_urls.clone().get(destination)
    {
        dest_base_url.clone()
    } else {
        warn!("{INBOUND_PREFIX} {origin} -> {destination} {method} {path_and_query} : 404 - destination unknown");
        return Ok(create_response(StatusCode::NOT_FOUND, None));
    };

    let res = state
        .http_client
        .request(method.clone(), format!("{dest_base_url}{path_and_query}"))
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await;

    match res {
        Ok(resp) => convert_response(resp),
        Err(e) => {
            warn!("{INBOUND_PREFIX} {method} {path_and_query} : 503 - error forwarding the req to {dest_base_url}, {e}");
            Ok(create_response(StatusCode::BAD_GATEWAY, None))
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
