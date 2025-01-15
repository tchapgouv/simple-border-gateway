use axum::{
    routing::{any, get, post, put},
    Router,
};
use tower_http::trace;
use tracing::Level;

use super::{handlers::{forbidden_handler, forward_handler, verify_signature_handler}, GatewayState};

pub(crate) fn create_router(state: GatewayState) -> Router {
    let mut r = Router::new().layer(
        trace::TraceLayer::new_for_http()
            .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
            .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
    );

    // Reference spec v1.13

    // 2. Server discovery

    // 2.1 Resolving server names
    r = r.route("/.well-known/matrix/server", get(forward_handler));
    r = r.route("/_matrix/federation/v1/version", get(forward_handler));

    // 2.3 Retrieving server keys
    r = r.route("/_matrix/key/v2/server", get(forward_handler));
    r = r.route("/_matrix/key/v2/query", post(forward_handler));
    r = r.route("/_matrix/key/v2/query/{server_name}", get(forward_handler));

    // 4. Transactions
    r = r.route(
        "/_matrix/federation/v1/send/{txnId}",
        put(verify_signature_handler),
    );

    // 5. PDUs

    // 5.1.5. Retrieving event authorization information
    r = r.route(
        "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
        get(verify_signature_handler),
    );

    // 8. Backfilling and retrieving missing events
    r = r.route(
        "/_matrix/federation/v1/backfill/{roomId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/get_missing_events/{roomId}",
        post(verify_signature_handler),
    );

    // 9. Retrieving events
    r = r.route(
        "/_matrix/federation/v1/event/{eventId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/state/{roomId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/state_ids/{roomId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/timestamp_to_event/{roomId}",
        get(verify_signature_handler),
    );

    // 10. Joining Rooms
    r = r.route(
        "/_matrix/federation/v1/make_join/{roomId}/{userId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
        post(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v2/send_join/{roomId}/{eventId}",
        post(verify_signature_handler),
    );

    // 11. Knocking upon a room
    r = r.route(
        "/_matrix/federation/v1/make_knock/{roomId}/{userId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/send_knock/{roomId}/{eventId}",
        put(verify_signature_handler),
    );

    // 12. Inviting to a room
    r = r.route(
        "/_matrix/federation/v1/invite/{roomId}/{eventId}",
        put(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v2/invite/{roomId}/{eventId}",
        put(verify_signature_handler),
    );

    // 13. Leaving Rooms (Rejecting Invites)
    r = r.route(
        "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
        put(verify_signature_handler),
    ); // DEPRECATED
    r = r.route(
        "/_matrix/federation/v2/send_leave/{roomId}/{eventId}",
        put(verify_signature_handler),
    );

    // 14. Third-party invites
    // 14.2 Cases where an association doesn’t exist for a third-party identifier
    r = r.route("/_matrix/federation/v1/3pid/onbind", put(forward_handler));
    r = r.route(
        "/_matrix/federation/v1/exchange_third_party_invite/{roomId}",
        put(verify_signature_handler),
    );

    // 15. Public Room Directory
    r = r.route(
        "/_matrix/federation/v1/publicRooms",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/publicRooms",
        post(verify_signature_handler),
    );

    // 16. Spaces
    r = r.route(
        "/_matrix/federation/v1/hierarchy/{roomId}",
        get(verify_signature_handler),
    );

    // 20. Querying for information
    r = r.route(
        "/_matrix/federation/v1/query/directory",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/query/profile",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/query/{queryType}",
        get(verify_signature_handler),
    );

    // 21. OpenID
    r = r.route(
        "/_matrix/federation/v1/openid/userinfo",
        get(forward_handler),
    );

    // 22. Device Management
    r = r.route(
        "/_matrix/federation/v1/user/devices/{userId}",
        get(verify_signature_handler),
    );

    // 23. End-to-End Encryption
    r = r.route(
        "/_matrix/federation/v1/user/keys/claim",
        post(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/user/keys/query",
        post(verify_signature_handler),
    );

    // 25. Content Repository
    r = r.route(
        "/_matrix/federation/v1/media/download/{mediaId}",
        get(verify_signature_handler),
    );
    r = r.route(
        "/_matrix/federation/v1/media/thumbnail/{mediaId}",
        get(verify_signature_handler),
    );

    // 25bis. Legacy Content Repository
    r = r.route("/_matrix/media/{*path}", any(forward_handler));

    // r = crate::membership::add_routes(r);

    r = r.fallback(forbidden_handler);

    r.with_state(state)
}
