use http::header::HOST;
use http::StatusCode;
use ruma::serde::Base64;
use simple_border_gateway::inbound;
use simple_border_gateway::util::shutdown_signal;
// use ruma::signatures::{sign_json, Ed25519KeyPair};
// use ruma::{CanonicalJsonObject, CanonicalJsonValue};
use std::collections::BTreeMap;
// use serde_json::json;

const WELL_FORMED_PUBKEY: &[u8] = &[
    0x19, 0xBF, 0x44, 0x09, 0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1, 0x67, 0xDC, 0x3B, 0x96,
    0xC8, 0x50, 0x86, 0xAA, 0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD, 0x70, 0x31, 0x66, 0xE1,
];

#[tokio::test]
async fn test_well_known_endpoint() {
    let mock_server = httpmock::MockServer::start();

    let mock = mock_server.mock(|when, then| {
        when.method("GET")
            .path("/.well-known/matrix/server")
            .header("Host", "example.com")
            .header("X-Forwarded-Host", "example.com");
        then.status(200)
            .header("content-type", "application/json")
            .body("{}");
    });

    let mut destination_base_urls = BTreeMap::new();
    destination_base_urls.insert("example.com".to_string(), mock_server.base_url());

    let mut public_key_map: BTreeMap<String, BTreeMap<String, Base64>> = BTreeMap::new();
    let mut mock_server_key: BTreeMap<String, Base64> = BTreeMap::new();
    mock_server_key.insert(
        "ed25519:test".to_string(),
        Base64::new(WELL_FORMED_PUBKEY.to_vec()),
    );
    public_key_map.insert("example.com".to_string(), mock_server_key);

    tokio::spawn(async move {
        inbound::create_proxy(
            "0.0.0.0:8888",
            shutdown_signal(),
            destination_base_urls,
            public_key_map,
        )
        .await
        .expect("Failed to create inbound proxy");
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let response = client
        .get("http://0.0.0.0:8888/.well-known/matrix/server")
        .header(HOST, "example.com")
        .header("X-Forwarded-Host", "example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    mock.assert();
}

// #[tokio::test]
// async fn test_authenticated_request_with_valid_signature() {
//     use crate::util::{install_crypto_provider, shutdown_signal};
//     use http::{header::HOST, StatusCode};
//     use ruma::serde::Base64;
//     use std::collections::BTreeMap;

//     // Generate a valid signature for the request using ruma
//     let request_method = "GET";
//     let request_uri = "/_matrix/federation/v1/query/profile";
//     let origin_name = "example.org";
//     let destination_name = "example.com";

//     // Install crypto provider for signature generation
//     install_crypto_provider();

//     // Create a keypair for signing requests
//     let keypair = Ed25519KeyPair::from_der(
//         &Ed25519KeyPair::generate().unwrap(),
//         "".to_owned(),
//     )
//     .unwrap();

//     let public_key = keypair.public_key().to_vec();
//     let key_id = format!("ed25519:{}", keypair.version());

//     // Create a mock server to handle the request
//     let mock_server = httpmock::MockServer::start();

//     // Set up the mock to expect an authenticated request
//     let mock = mock_server.mock(|when, then| {
//         when.method(request_method)
//             .path(request_uri);
//             // .header("Host", destination_name)
//             // .header("X-Forwarded-Host", destination_name);
//         then.status(200)
//             .header("content-type", "application/json")
//             .body("{\"profile\": {\"displayname\": \"Test User\"}}");
//     });

//     // Set up the destination base URLs
//     let mut destination_base_urls = BTreeMap::new();
//     destination_base_urls.insert("example.com".to_string(), mock_server.base_url());

//     // Set up the public key map with our dynamically generated public key
//     let mut public_key_map: BTreeMap<String, BTreeMap<String, Base64>> = BTreeMap::new();
//     let mut server_keys: BTreeMap<String, Base64> = BTreeMap::new();
//     server_keys.insert(
//         key_id.clone(),
//         Base64::new(public_key.clone()),
//     );
//     public_key_map.insert("example.org".to_string(), server_keys);

//     // Start the proxy server
//     tokio::spawn(async move {
//         inbound::create_proxy(
//             "0.0.0.0:9997",
//             shutdown_signal(),
//             destination_base_urls,
//             public_key_map,
//             false,
//         )
//         .await;
//     });

//     // Wait for the server to start
//     tokio::time::sleep(std::time::Duration::from_millis(100)).await;

//     // Create a client
//     let client = reqwest::Client::new();

//     // Create the JSON object to sign
//     let mut request_map = BTreeMap::new();
//     request_map.insert("method".to_string(), CanonicalJsonValue::String(request_method.to_string()));
//     request_map.insert("uri".to_string(), CanonicalJsonValue::String(request_uri.to_string()));
//     request_map.insert("origin".to_string(), CanonicalJsonValue::String(origin_name.to_string()));
//     request_map.insert("destination".to_string(), CanonicalJsonValue::String(destination_name.to_string()));

//     // Create a canonical JSON object using BTreeMap
//     let mut canonical_signed_json = CanonicalJsonObject::from(request_map);

//     // Sign the JSON using the keypair
//     sign_json(origin_name, &keypair, &mut canonical_signed_json).unwrap();

//     // Extract signature from the signed JSON object - access the nested maps properly
//     let signatures = &canonical_signed_json["signatures"];
//     if let CanonicalJsonValue::Object(sigs_obj) = signatures {
//         if let Some(server_sigs) = sigs_obj.get(origin_name) {
//             if let CanonicalJsonValue::Object(server_obj) = server_sigs {
//                 if let Some(CanonicalJsonValue::String(sig_value)) = server_obj.get(&key_id) {
//                     let signature = sig_value.clone();

//                     // Create X-Matrix authorization header
//                     let auth_header = format!(
//                         "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
//                         origin_name, destination_name, key_id, signature
//                     );

//                     // Send the request with the valid signature
//                     let response = client
//                         .get(format!("http://0.0.0.0:9997{}", request_uri))
//                         .header(HOST, destination_name)
//                         .header("X-Forwarded-Host", destination_name)
//                         .header("Authorization", auth_header.clone())
//                         .send()
//                         .await
//                         .unwrap();

//                     // Get status before consuming the body
//                     let status = response.status();
//                     println!("Response status: {}", status);

//                     // Get and print the body
//                     let body = response.text().await.unwrap();
//                     println!("Response body: {}", body);
//                     println!("Authorization header: {}", auth_header);

//                     // Verify the response
//                     assert_eq!(status, StatusCode::OK);
//                     // We've already printed the body for debugging
//                     // assert_eq!(body, "{\"profile\": {\"displayname\": \"Test User\"}}");

//                     // Verify that the mock was called
//                     mock.assert();
//                 } else {
//                     panic!("Could not find signature for key ID");
//                 }
//             }
//         }
//     }
// }
