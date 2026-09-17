use crate::util::{Endpoint, EndpointRouter};
use http::Method;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum EndpointType {
    #[default]
    Federation,
    WellKnown,
    LegacyMedia,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum AuthType {
    Unauthenticated,
    #[default]
    CheckSignature,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Action {
    Allow,
    Reject,
}

// Built-in default ruleset containing all standard Matrix federation endpoints.
// Override rules from external toml files take precedence over these defaults.
// Those endpoints are ALL allowed.
pub(crate) static DEFAULT_ENDPOINTS: Lazy<Vec<Endpoint>> = Lazy::new(|| {
    use AuthType::*;
    use EndpointType::*;

    vec![
        // 2.1 Resolving server names
        Endpoint::new_allowed(
            "well_known_server",
            "/.well-known/matrix/server",
            Some(Method::GET),
            Unauthenticated,
            WellKnown,
        )
        .expect("Invalid endpoint definition"),
        // 2.2 Server implementation
        Endpoint::new_allowed(
            "federation_version",
            "/_matrix/federation/v1/version",
            Some(Method::GET),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 2.3 Retrieving server keys
        Endpoint::new_allowed(
            "key_v2_server",
            "/_matrix/key/v2/server",
            Some(Method::GET),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed(
            "key_v2_query_post",
            "/_matrix/key/v2/query",
            Some(Method::POST),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed(
            "key_v2_query_get",
            "/_matrix/key/v2/query/{server_name}",
            Some(Method::GET),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 4. Transactions
        Endpoint::new_allowed_signed_fed(
            "send_transaction",
            "/_matrix/federation/v1/send/{txnId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        // 5.1.5 Retrieving event authorization information
        Endpoint::new_allowed_signed_fed(
            "event_auth",
            "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        // 8. Backfilling and retrieving missing events
        Endpoint::new_allowed_signed_fed(
            "backfill",
            "/_matrix/federation/v1/backfill/{roomId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "get_missing_events",
            "/_matrix/federation/v1/get_missing_events/{roomId}",
            Some(Method::POST),
        )
        .expect("Invalid endpoint definition"),
        // 9. Retrieving events
        Endpoint::new_allowed_signed_fed(
            "get_event",
            "/_matrix/federation/v1/event/{eventId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "get_state",
            "/_matrix/federation/v1/state/{roomId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "get_state_ids",
            "/_matrix/federation/v1/state_ids/{roomId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "timestamp_to_event",
            "/_matrix/federation/v1/timestamp_to_event/{roomId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        // 10. Joining rooms
        Endpoint::new_allowed_signed_fed(
            "make_join",
            "/_matrix/federation/v1/make_join/{roomId}/{userId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "send_join_v1",
            "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "send_join_v2",
            "/_matrix/federation/v2/send_join/{roomId}/{eventId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        // 11. Knocking
        Endpoint::new_allowed_signed_fed(
            "make_knock",
            "/_matrix/federation/v1/make_knock/{roomId}/{userId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "send_knock",
            "/_matrix/federation/v1/send_knock/{roomId}/{eventId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        // 12. Inviting
        Endpoint::new_allowed_signed_fed(
            "invite_v1",
            "/_matrix/federation/v1/invite/{roomId}/{eventId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "invite_v2",
            "/_matrix/federation/v2/invite/{roomId}/{eventId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        // 13. Leaving rooms
        Endpoint::new_allowed_signed_fed(
            "make_leave",
            "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "send_leave_v1",
            "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "send_leave_v2",
            "/_matrix/federation/v2/send_leave/{roomId}/{eventId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        // 14. Third-party invites
        Endpoint::new_allowed(
            "3pid_onbind",
            "/_matrix/federation/v1/3pid/onbind",
            Some(Method::PUT),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "exchange_third_party_invite",
            "/_matrix/federation/v1/exchange_third_party_invite/{roomId}",
            Some(Method::PUT),
        )
        .expect("Invalid endpoint definition"),
        // 15. Public room directory
        Endpoint::new_allowed_signed_fed(
            "public_rooms_get",
            "/_matrix/federation/v1/publicRooms",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "public_rooms_post",
            "/_matrix/federation/v1/publicRooms",
            Some(Method::POST),
        )
        .expect("Invalid endpoint definition"),
        // 16. Spaces
        Endpoint::new_allowed_signed_fed(
            "spaces_hierarchy",
            "/_matrix/federation/v1/hierarchy/{roomId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        // 20. Querying for information
        Endpoint::new_allowed_signed_fed(
            "query_directory",
            "/_matrix/federation/v1/query/directory",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "query_profile",
            "/_matrix/federation/v1/query/profile",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "query_generic",
            "/_matrix/federation/v1/query/{queryType}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        // 21. OpenID
        Endpoint::new_allowed(
            "openid_userinfo",
            "/_matrix/federation/v1/openid/userinfo",
            Some(Method::GET),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 22. Device management
        Endpoint::new_allowed_signed_fed(
            "user_devices",
            "/_matrix/federation/v1/user/devices/{userId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        // 23. End-to-end encryption
        Endpoint::new_allowed_signed_fed(
            "user_keys_claim",
            "/_matrix/federation/v1/user/keys/claim",
            Some(Method::POST),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "user_keys_query",
            "/_matrix/federation/v1/user/keys/query",
            Some(Method::POST),
        )
        .expect("Invalid endpoint definition"),
        // 25. Content repository
        Endpoint::new_allowed_signed_fed(
            "media_download",
            "/_matrix/federation/v1/media/download/{mediaId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        Endpoint::new_allowed_signed_fed(
            "media_thumbnail",
            "/_matrix/federation/v1/media/thumbnail/{mediaId}",
            Some(Method::GET),
        )
        .expect("Invalid endpoint definition"),
        // 25bis. Legacy content repository (any method)
        Endpoint::new_allowed(
            "legacy_media",
            "/_matrix/media/{*path}",
            None,
            Unauthenticated,
            LegacyMedia,
        )
        .expect("Invalid endpoint definition"),
        // Needed for legacy content repository discovery
        Endpoint::new_allowed(
            "well_known_client",
            "/.well-known/matrix/client",
            Some(Method::GET),
            Unauthenticated,
            WellKnown,
        )
        .expect("Invalid endpoint definition"),
    ]
});

// The default ruleset compiled into a router, used as the fallback for every server.
pub(crate) static DEFAULT_RULESET: Lazy<EndpointRouter> = Lazy::new(|| {
    EndpointRouter::new((*DEFAULT_ENDPOINTS).clone()).expect("Invalid default ruleset")
});

#[cfg(test)]
mod tests {
    use super::{DEFAULT_ENDPOINTS, EndpointType};

    #[test]
    fn only_discovery_endpoints_are_well_known() {
        let well_known_ids: Vec<&str> = DEFAULT_ENDPOINTS
            .iter()
            .filter(|endpoint| endpoint.rule.endpoint_type == EndpointType::WellKnown)
            .map(|endpoint| endpoint.id.as_str())
            .collect();

        assert_eq!(well_known_ids, ["well_known_server", "well_known_client"]);
    }
}
