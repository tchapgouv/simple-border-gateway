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
    Endpoint {
        path: "/_matrix/federation/v1/send/{txnId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 5. PDUs

    // 5.1.5. Retrieving event authorization information
    Endpoint {
        path: "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 8. Backfilling and retrieving missing events
    Endpoint {
        path: "/_matrix/federation/v1/backfill/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/get_missing_events/{roomId}",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 9. Retrieving events
    Endpoint {
        path: "/_matrix/federation/v1/event/{eventId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/state/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/state_ids/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/timestamp_to_event/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 10. Joining Rooms
    Endpoint {
        path: "/_matrix/federation/v1/make_join/{roomId}/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // DEPRECATED
    Endpoint {
        path: "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v2/send_join/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 11. Knocking upon a room
    Endpoint {
        path: "/_matrix/federation/v1/make_knock/{roomId}/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/send_knock/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 12. Inviting to a room
    Endpoint {
        path: "/_matrix/federation/v1/invite/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v2/invite/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 13. Leaving Rooms (Rejecting Invites)
    Endpoint {
        path: "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // DEPRECATED
    Endpoint {
        path: "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v2/send_leave/{roomId}/{eventId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 14. Third-party invites
    // 14.2 Cases where an association doesn’t exist for a third-party identifier
    Endpoint {
        path: "/_matrix/federation/v1/3pid/onbind",
        method: Some(Method::PUT),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/exchange_third_party_invite/{roomId}",
        method: Some(Method::PUT),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 15. Public Room Directory
    Endpoint {
        path: "/_matrix/federation/v1/publicRooms",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/publicRooms",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 16. Spaces
    Endpoint {
        path: "/_matrix/federation/v1/hierarchy/{roomId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 20. Querying for information
    Endpoint {
        path: "/_matrix/federation/v1/query/directory",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/query/profile",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/query/{queryType}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 21. OpenID
    Endpoint {
        path: "/_matrix/federation/v1/openid/userinfo",
        method: Some(Method::GET),
        auth_type: AuthType::Unauthenticated,
        endpoint_type: EndpointType::Federation,
    },
    // 22. Device Management
    Endpoint {
        path: "/_matrix/federation/v1/user/devices/{userId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 23. End-to-End Encryption
    Endpoint {
        path: "/_matrix/federation/v1/user/keys/claim",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/user/keys/query",
        method: Some(Method::POST),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    // 25. Content Repository
    Endpoint {
        path: "/_matrix/federation/v1/media/download/{mediaId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
    Endpoint {
        path: "/_matrix/federation/v1/media/thumbnail/{mediaId}",
        method: Some(Method::GET),
        auth_type: AuthType::CheckSignature,
        endpoint_type: EndpointType::Federation,
    },
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
