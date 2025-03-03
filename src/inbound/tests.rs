#[cfg(test)]
mod tests {
    use crate::inbound;
    use crate::util::{install_crypto_provider, shutdown_signal};
    use http::header::HOST;
    use http::StatusCode;
    use ruma::serde::Base64;
    use std::collections::BTreeMap;

    const WELL_FORMED_PUBKEY: &[u8] = &[
        0x19, 0xBF, 0x44, 0x09, 0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1, 0x67, 0xDC, 0x3B,
        0x96, 0xC8, 0x50, 0x86, 0xAA, 0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD, 0x70, 0x31,
        0x66, 0xE1,
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
}
