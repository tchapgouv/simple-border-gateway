use httpmock::MockServer;
use reqwest::StatusCode;
pub(crate) fn set_req_authority_for_tests<B>(req: &mut http::Request<B>, authority: &str) {
    let parts = req.uri().clone().into_parts();
    let mut builder = http::uri::Builder::new()
        .scheme("http")
        .authority(authority);
    if let Some(path_and_query) = parts.path_and_query {
        builder = builder.path_and_query(path_and_query);
    }
    *req.uri_mut() = builder.build().unwrap();
}

pub(crate) fn get_well_known_endpoint_mock(mock_server: &MockServer) -> httpmock::Mock {
    mock_server.mock(|when, then| {
        when.method("GET").path("/.well-known/matrix/server");
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"m.server\": \"example.com:443\"}");
    })
}

pub(crate) async fn verify_well_known_response(response: reqwest::Response) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(body, "{\"m.server\": \"example.com:443\"}");
}
