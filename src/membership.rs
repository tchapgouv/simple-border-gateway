use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::IntoResponse,
    routing::put,
    Router,
};
use http::Request;
use hudsucker::RequestOrResponse;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;

use crate::inbound::{self, GatewayState};

pub(crate) fn add_routes(router: Router<GatewayState>) -> Router<GatewayState> {
    router.route(
        "/_matrix/federation/v2/invite/:room_id/:event_id",
        put(invite_v2),
    )
}

#[derive(Deserialize)]
struct RoomMemberEvent {
    origin: String,
    // sender: String,
    // state_key: String,
}

#[derive(Deserialize)]
struct InviteRequest {
    event: RoomMemberEvent,
}

async fn invite_v2(
    State(state): State<GatewayState>,
    uri: Uri,
    headers: HeaderMap,
    invite_req_str: String,
) -> impl IntoResponse {
    let invite_req: InviteRequest = serde_json::from_str(invite_req_str.as_str()).unwrap(); // TODO unwrap
    let origin = invite_req.event.origin;
    if origin == "matrix.org" {
        println!("forbid!");
        create_forbidden_response("M_FORBIDDEN", None)
    } else {
        match get_destination_hostname(&headers.clone()) {
            Ok(destination_hostname) => {
                inbound::forward_incoming_request(
                    state,
                    destination_hostname,
                    Method::PUT,
                    uri.path(),
                    headers,
                    axum::body::Body::from(invite_req_str),
                )
                .await
            }
            Err(err_resp) => err_resp,
        }

    }
}

pub async fn filter_outgoing_req(req: Request<hudsucker::Body>) -> RequestOrResponse {
    lazy_static! {
        static ref JOIN_RE: Regex =
            Regex::new(r".*/send_join/(?<room_id>.+)/(?<user_id>.+)").unwrap();
    }

    if let Some(join_params) = JOIN_RE.captures(req.uri().path()) {
        let room_id = join_params.name("room_id").unwrap().as_str();
        if room_id.ends_with(":matrix.org") {
            return RequestOrResponse::Response(create_forbidden_response(
                "M_FORBIDDEN",
                None,
            ));
        }
    }
    RequestOrResponse::Request(req)
}

// #[cfg(test)]
// mod tests {
//     use std::collections::HashMap;

//     use axum_test::TestServer;
//     use reqwest::StatusCode;
//     use serde_json::json;

//     use crate::inbound::{self, GatewayState};

//     #[tokio::test]
//     async fn test_inboumd_invite_v2() {
//         let state = GatewayState {
//             http_client: reqwest::Client::new(),
//             destination_rewrite_urls: HashMap::new(),
//         };

//         let server = TestServer::new(inbound::create_router(state)).unwrap();

//         // Get the request.
//         let response = server
//             .put("/_matrix/federation/v2/invite/!aa:matrix.org/$143273582443PhrSn")
//             .json(&json!(
//                 {
//                     "event": {
//                         "content": {
//                             "membership": "invite"
//                         },
//                         "origin": "matrix.org",
//                         "origin_server_ts": 1,
//                         "sender": "@test:matrix.org",
//                         "state_key": "@test:test2.org",
//                         "type": "m.room.member"
//                     },
//                     "invite_room_state": [],
//                     "room_version": "9"
//                 }
//             ))
//             .await;

//         assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
//     }
// }
