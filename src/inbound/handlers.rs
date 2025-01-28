use std::collections::BTreeMap;

// use crate::membership;
use crate::util::{create_empty_response, create_forbidden_response, XForwardedHost};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, Uri},
};
use axum_extra::{headers::Authorization, TypedHeader};
use http::StatusCode;
use log::{info, warn};
use regex::Regex;
use ruma::{
    server_util::authorization::XMatrix,
    signatures::{verify_json, Error, PublicKeyMap},
    CanonicalJsonValue,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use lazy_static::lazy_static;

use super::GatewayState;

lazy_static! {
    static ref REMOVE_DEFAULT_PORTS_REGEX: Regex = Regex::new(r"(:443|:80)$").unwrap();
}

pub(crate) async fn forbidden_handler(
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedHost(x_forwarded_host)): TypedHeader<XForwardedHost>,
) -> http::Response<Body> {
    warn!("{x_forwarded_host} {method} {uri} : forbidden request");
    create_forbidden_response("errcode", None)
}

pub(crate) async fn forward_handler(
    State(state): State<GatewayState>,
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedHost(x_forwarded_host)): TypedHeader<XForwardedHost>,
    headers: HeaderMap,
    request: Request<Body>,
) -> http::Response<Body> {
    forward_incoming_request(
        state,
        method,
        uri.path_and_query().map_or("", |p| p.as_str()),
        x_forwarded_host,
        headers,
        request.into_body(),
    )
    .await
}

pub(crate) async fn verify_signature_handler(
    State(state): State<GatewayState>,
    method: Method,
    uri: Uri,
    TypedHeader(XForwardedHost(x_forwarded_host)): TypedHeader<XForwardedHost>,
    TypedHeader(Authorization(x_matrix)): TypedHeader<Authorization<XMatrix>>,
    headers: HeaderMap,
    body: String,
) -> http::Response<Body> {
    let origin = x_matrix.origin.clone();
    if !state.public_key_map.contains_key(origin.as_str()) {
        warn!("{x_forwarded_host} {method} {uri} : unauthorized server {origin}, forbid request");
        return create_empty_response(StatusCode::FORBIDDEN);
    }

    match verify_signature(
        &state.public_key_map,
        &method,
        &uri,
        x_matrix,
        body.as_str(),
    )
    .await
    {
        Ok(_) => {
            info!("{x_forwarded_host} {method} {uri} : authorized server {origin} signature ok");
            forward_incoming_request(
                state,
                method,
                uri.path_and_query().map_or("", |p| p.as_str()),
                x_forwarded_host,
                headers,
                Body::from(body),
            )
            .await
        }
        Err(e) => {
            warn!("{x_forwarded_host} {method} {uri} : authorized server {origin} but wrong signature, forbid request, {e}");
            return create_empty_response(StatusCode::FORBIDDEN);
        }
    }
}

#[derive(Deserialize, Serialize)]
struct SignedRequest {
    method: String,
    uri: String,
    origin: String,
    destination: String,
    content: Option<Value>,
    signatures: BTreeMap<String, BTreeMap<String, String>>,
}

async fn verify_signature(
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
        destination: x_matrix
            .destination
            .map_or("tout.im".to_string(), |d| d.to_string()), // TODO default
        content: content_json,
        signatures,
    };

    let canonical_signed_json: CanonicalJsonValue = serde_json::to_value(signed_req)
        .unwrap() // TODO
        .try_into()
        .unwrap(); // TODO

    verify_json(&public_key_map, canonical_signed_json.as_object().unwrap()) // TODO
}

pub(crate) async fn forward_incoming_request(
    state: GatewayState,
    method: Method,
    path_and_query: &str,
    x_forwarded_host: String,
    headers: HeaderMap,
    body: Body,
) -> http::Response<Body> {
    let x_forwarded_host = REMOVE_DEFAULT_PORTS_REGEX
        .replace_all(x_forwarded_host.as_str(), "")
        .to_string();

    let dest_base_url = match state
        .destination_base_urls
        .clone()
        .get(x_forwarded_host.as_str())
    {
        Some(dest_base_url) => dest_base_url.clone(),
        None => {
            warn!(
                "{x_forwarded_host} {method} {path_and_query} : destination unknown, block request"
            );
            return create_empty_response(StatusCode::BAD_GATEWAY);
        }
    };

    info!("{x_forwarded_host} {method} {path_and_query} : forward request to {dest_base_url}");
    let res = state
        .http_client
        .request(method.clone(), format!("{dest_base_url}{path_and_query}"))
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await;

    match res {
        Ok(resp) => return convert_response(resp).unwrap(), // TODO
        Err(e) => {
            warn!("{method} {path_and_query} : error forwarding the req to {dest_base_url} {e}");
            create_empty_response(StatusCode::BAD_GATEWAY)
        }
    }
}

fn convert_response(resp: reqwest::Response) -> Result<http::Response<Body>, http::Error> {
    let mut builder = http::Response::builder()
        .status(resp.status())
        .version(resp.version());
    for (name, value) in resp.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Body::from_stream(resp.bytes_stream()))
}
