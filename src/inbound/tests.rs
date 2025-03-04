#[cfg(test)]
use crate::inbound;
use crate::util::{install_crypto_provider, shutdown_signal};
use http::header::HOST;
use http::StatusCode;
use ruma::serde::Base64;
use std::collections::BTreeMap;

// const WELL_FORMED_DOC: &[u8] = &[
//     0x30, 0x72, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
//     0xD4, 0xEE, 0x72, 0xDB, 0xF9, 0x13, 0x58, 0x4A, 0xD5, 0xB6, 0xD8, 0xF1, 0xF7, 0x69, 0xF8, 0xAD,
//     0x3A, 0xFE, 0x7C, 0x28, 0xCB, 0xF1, 0xD4, 0xFB, 0xE0, 0x97, 0xA8, 0x8F, 0x44, 0x75, 0x58, 0x42,
//     0xA0, 0x1F, 0x30, 0x1D, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x09, 0x14,
//     0x31, 0x0F, 0x0C, 0x0D, 0x43, 0x75, 0x72, 0x64, 0x6C, 0x65, 0x20, 0x43, 0x68, 0x61, 0x69, 0x72,
//     0x73, 0x81, 0x21, 0x00, 0x19, 0xBF, 0x44, 0x09, 0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1,
//     0x67, 0xDC, 0x3B, 0x96, 0xC8, 0x50, 0x86, 0xAA, 0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD,
//     0x70, 0x31, 0x66, 0xE1,
// ];

const WELL_FORMED_PUBKEY: &[u8] = &[
    0x19, 0xBF, 0x44, 0x09, 0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1, 0x67, 0xDC, 0x3B, 0x96,
    0xC8, 0x50, 0x86, 0xAA, 0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD, 0x70, 0x31, 0x66, 0xE1,
];

#[tokio::test]
async fn test_well_known_endpoint() {
    install_crypto_provider();

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
            "0.0.0.0:9999",
            shutdown_signal(),
            destination_base_urls,
            public_key_map,
            false,
        )
        .await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let response = client
        .get("http://0.0.0.0:9999/.well-known/matrix/server")
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

//     // Install crypto provider for signature generation
//     install_crypto_provider();

//     // Create a keypair for signing requests
//     let keypair = Ed25519KeyPair::from_der(WELL_FORMED_DOC, "".to_owned()).unwrap();
//     let public_key = keypair.public_key().to_vec();
//     let key_id = format!("ed25519:{}", keypair.version());

//     // Create a mock server to handle the request
//     let mock_server = httpmock::MockServer::start();

//     // Set up the mock to expect an authenticated request
//     let mock = mock_server.mock(|when, then| {
//         when.method("GET")
//             .path("/_matrix/federation/v1/query/profile")
//             .header("Host", "example.com")
//             .header("X-Forwarded-Host", "example.com");
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

//     // Generate a valid signature for the request using ruma
//     let request_method = "GET";
//     let request_uri = "/_matrix/federation/v1/query/profile";
//     let origin_name = "example.org";
//     let destination_name = "example.com";

//     // Create a federation request to sign
//     let request = ruma::federation::Request {
//         method: request_method,
//         uri: request_uri,
//         origin: origin_name,
//         destination: destination_name,
//         content: None, // No content for GET request
//     };

//     // Sign the request with our keypair
//     let auth_header = ruma::federation::create_authorization_header(
//         origin_name,
//         &key_id,
//         &keypair,
//         &request
//     );

//     // Send the request with the valid signature
//     let response = client
//         .get(format!("http://0.0.0.0:9997{}", request_uri))
//         .header(HOST, destination_name)
//         .header("X-Forwarded-Host", destination_name)
//         .header("Authorization", auth_header)
//         .send()
//         .await
//         .unwrap();

//     // Verify the response
//     assert_eq!(response.status(), StatusCode::OK);
//     let body = response.text().await.unwrap();
//     assert_eq!(body, "{\"profile\": {\"displayname\": \"Test User\"}}");

//     // Verify that the mock was called
//     mock.assert();
// }
