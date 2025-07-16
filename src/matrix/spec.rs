// Reference spec v1.15

use http::Method;

#[derive(Clone, PartialEq)]
pub(crate) enum EndpointType {
    Federation,
    WellKnown,
    LegacyMedia,
}

#[derive(Clone, PartialEq)]
pub(crate) enum AuthType {
    Unauthenticated,
    CheckSignature,
}

#[derive(Clone)]
pub(crate) struct Endpoint {
    pub(crate) path: &'static str,
    pub(crate) method: Option<Method>,
    pub(crate) endpoint_type: EndpointType,
    pub(crate) auth_type: AuthType,
}

impl Endpoint {
    pub(crate) const fn new(path: &'static str, method: Option<Method>) -> Self {
        Self {
            path,
            method,
            endpoint_type: EndpointType::Federation,
            auth_type: AuthType::CheckSignature,
        }
    }
}

pub(crate) const ENDPOINTS: [Endpoint; 39] = [
    // 2. Server discovery

    // 2.1 Resolving server names
    Endpoint {
        path: "/.well-known/matrix/server",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::WellKnown,
    },
    // 2.2 Server implementation
    Endpoint {
        path: "/_matrix/federation/v1/version",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    // 2.3 Retrieving server keys
    Endpoint {
        path: "/_matrix/key/v2/server",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/key/v2/query",
        method: Some(Method::POST),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/key/v2/query/{server_name}",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    // 4. Transactions
    Endpoint::new("/_matrix/federation/v1/send/{txnId}", Some(Method::PUT)),
    // 5. PDUs

    // 5.1.5. Retrieving event authorization information
    Endpoint::new(
        "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
        Some(Method::GET),
    ),
    // 8. Backfilling and retrieving missing events
    Endpoint::new(
        "/_matrix/federation/v1/backfill/{roomId}",
        Some(Method::GET),
    ),
    Endpoint::new(
        "/_matrix/federation/v1/get_missing_events/{roomId}",
        Some(Method::POST),
    ),
    // 9. Retrieving events
    Endpoint::new("/_matrix/federation/v1/event/{eventId}", Some(Method::GET)),
    Endpoint::new("/_matrix/federation/v1/state/{roomId}", Some(Method::GET)),
    Endpoint::new(
        "/_matrix/federation/v1/state_ids/{roomId}",
        Some(Method::GET),
    ),
    Endpoint::new(
        "/_matrix/federation/v1/timestamp_to_event/{roomId}",
        Some(Method::GET),
    ),
    // 10. Joining Rooms
    Endpoint::new(
        "/_matrix/federation/v1/make_join/{roomId}/{userId}",
        Some(Method::GET),
    ),
    // DEPRECATED
    Endpoint::new(
        "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
        Some(Method::PUT),
    ),
    Endpoint::new(
        "/_matrix/federation/v2/send_join/{roomId}/{eventId}",
        Some(Method::PUT),
    ),
    // 11. Knocking upon a room
    Endpoint::new(
        "/_matrix/federation/v1/make_knock/{roomId}/{userId}",
        Some(Method::GET),
    ),
    Endpoint::new(
        "/_matrix/federation/v1/send_knock/{roomId}/{eventId}",
        Some(Method::PUT),
    ),
    // 12. Inviting to a room
    Endpoint::new(
        "/_matrix/federation/v1/invite/{roomId}/{eventId}",
        Some(Method::PUT),
    ),
    Endpoint::new(
        "/_matrix/federation/v2/invite/{roomId}/{eventId}",
        Some(Method::PUT),
    ),
    // 13. Leaving Rooms (Rejecting Invites)
    Endpoint::new(
        "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
        Some(Method::GET),
    ),
    // DEPRECATED
    Endpoint::new(
        "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
        Some(Method::PUT),
    ),
    Endpoint::new(
        "/_matrix/federation/v2/send_leave/{roomId}/{eventId}",
        Some(Method::PUT),
    ),
    // 14. Third-party invites
    // 14.2 Cases where an association doesn’t exist for a third-party identifier
    Endpoint {
        path: "/_matrix/federation/v1/3pid/onbind",
        method: Some(Method::PUT),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint::new(
        "/_matrix/federation/v1/exchange_third_party_invite/{roomId}",
        Some(Method::PUT),
    ),
    // 15. Public Room Directory
    Endpoint::new("/_matrix/federation/v1/publicRooms", Some(Method::GET)),
    Endpoint::new("/_matrix/federation/v1/publicRooms", Some(Method::POST)),
    // 16. Spaces
    Endpoint::new(
        "/_matrix/federation/v1/hierarchy/{roomId}",
        Some(Method::GET),
    ),
    // 20. Querying for information
    Endpoint::new("/_matrix/federation/v1/query/directory", Some(Method::GET)),
    Endpoint::new("/_matrix/federation/v1/query/profile", Some(Method::GET)),
    Endpoint::new(
        "/_matrix/federation/v1/query/{queryType}",
        Some(Method::GET),
    ),
    // 21. OpenID
    Endpoint {
        path: "/_matrix/federation/v1/openid/userinfo",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    // 22. Device Management
    Endpoint::new(
        "/_matrix/federation/v1/user/devices/{userId}",
        Some(Method::GET),
    ),
    // 23. End-to-End Encryption
    Endpoint::new("/_matrix/federation/v1/user/keys/claim", Some(Method::POST)),
    Endpoint::new("/_matrix/federation/v1/user/keys/query", Some(Method::POST)),
    // 25. Content Repository
    Endpoint::new(
        "/_matrix/federation/v1/media/download/{mediaId}",
        Some(Method::GET),
    ),
    Endpoint::new(
        "/_matrix/federation/v1/media/thumbnail/{mediaId}",
        Some(Method::GET),
    ),
    // 25bis. Legacy Content Repository (part of the client spec)
    Endpoint {
        path: "/_matrix/media/{*path}",
        method: None,
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::LegacyMedia,
    },
    // Needed because of legacy content repository endpoint
    Endpoint {
        path: "/.well-known/matrix/client",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::WellKnown,
    },
];
