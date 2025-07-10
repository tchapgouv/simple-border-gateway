use http::request::Parts;
use ruma::{
    server_util::authorization::XMatrix,
    signatures::{verify_json, PublicKeyMap},
    CanonicalJsonObject, CanonicalJsonValue,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

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

pub(crate) fn verify_signature(
    public_key_map: &PublicKeyMap,
    parts: &Parts,
    x_matrix: XMatrix,
    body: &str,
) -> Result<(), anyhow::Error> {
    // TODO: parse xmatrix header here directly?
    let content_json: Option<Value> = serde_json::from_str(body).ok();

    let signatures = BTreeMap::from([(
        x_matrix.origin.to_string(),
        BTreeMap::from([(x_matrix.key.to_string(), x_matrix.sig.to_string())]),
    )]);

    let signed_req = SignedRequest {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
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
