// Reference spec v1.13

use http::Method;

#[derive(Clone)]
pub(crate) enum AuthType {
    Unauthenticated,
    CheckSignature,
    // Forbidden,
}

#[derive(Clone)]
pub(crate) struct Endpoint {
    pub(crate) path: &'static str,
    pub(crate) method: Option<Method>,
    pub(crate) auth_type: AuthType,
}

pub(crate) const FEDERATION_ENDPOINTS: [Endpoint; 36] = [
    // 2. Server discovery

    // 2.1 Resolving server names
    Endpoint {
        path: "/_matrix/federation/v1/version",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
    },
    // 2.3 Retrieving server keys
    Endpoint {
        path: "/_matrix/key/v2/server",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
    },
    Endpoint {
        path: "/_matrix/key/v2/query",
        method: Some(Method::POST),
        auth_type: AuthType::Unauthenticated,
    },
    Endpoint {
        path: "/_matrix/key/v2/query/{server_name}",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
    },
    // 4. Transactions
    Endpoint {
        path: "/_matrix/federation/v1/send/{txnId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
    },
    // 5. PDUs

    // 5.1.5. Retrieving event authorization information
    Endpoint {
        path: "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    // 8. Backfilling and retrieving missing events
    Endpoint {
        path: "/_matrix/federation/v1/backfill/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/get_missing_events/{roomId}",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
    },
    // 9. Retrieving events
    Endpoint {
        path: "/_matrix/federation/v1/event/{eventId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/state/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/state_ids/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/timestamp_to_event/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    // 10. Joining Rooms
    Endpoint {
        path: "/_matrix/federation/v1/make_join/{roomId}/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v2/send_join/{roomId}/{eventId}",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
    },
    // 11. Knocking upon a room
    Endpoint {
        path: "/_matrix/federation/v1/make_knock/{roomId}/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/send_knock/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
    },
    // 12. Inviting to a room
    Endpoint {
        path: "/_matrix/federation/v1/invite/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v2/invite/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
    },
    // 13. Leaving Rooms (Rejecting Invites)
    Endpoint {
        path: "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    // DEPRECATED
    Endpoint {
        path: "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v2/send_leave/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
    },
    // 14. Third-party invites
    // 14.2 Cases where an association doesn’t exist for a third-party identifier
    Endpoint {
        path: "/_matrix/federation/v1/3pid/onbind",
        method: Some(Method::PUT),
        auth_type: AuthType::Unauthenticated,
    },
    Endpoint {
        path: "/_matrix/federation/v1/exchange_third_party_invite/{roomId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
    },
    // 15. Public Room Directory
    Endpoint {
        path: "/_matrix/federation/v1/publicRooms",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/publicRooms",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
    },
    // 16. Spaces
    Endpoint {
        path: "/_matrix/federation/v1/hierarchy/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    // 20. Querying for information
    Endpoint {
        path: "/_matrix/federation/v1/query/directory",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/query/profile",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/query/{queryType}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    // 21. OpenID
    Endpoint {
        path: "/_matrix/federation/v1/openid/userinfo",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
    },
    // 22. Device Management
    Endpoint {
        path: "/_matrix/federation/v1/user/devices/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    // 23. End-to-End Encryption
    Endpoint {
        path: "/_matrix/federation/v1/user/keys/claim",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/user/keys/query",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
    },
    // 25. Content Repository
    Endpoint {
        path: "/_matrix/federation/v1/media/download/{mediaId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
    Endpoint {
        path: "/_matrix/federation/v1/media/thumbnail/{mediaId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
    },
];

pub(crate) const SERVER_WELLKNOWN_ENDPOINT: Endpoint = Endpoint {
    // 2. Server discovery

    // 2.1 Resolving server names
    path: "/.well-known/matrix/server",
    method: Some(Method::GET),
    auth_type: AuthType::Unauthenticated,
};

pub(crate) const CLIENT_WELLKNOWN_ENDPOINT: Endpoint = Endpoint {
    path: "/.well-known/matrix/client",
    method: Some(Method::GET),
    auth_type: AuthType::Unauthenticated,
};

pub(crate) const MEDIA_CLIENT_LEGACY_ENDPOINTS: [Endpoint; 1] = [
    // 25bis. Legacy Content Repository
    Endpoint {
        path: "/_matrix/media/{*path}",
        method: None,
        auth_type: AuthType::Unauthenticated,
    },
];
