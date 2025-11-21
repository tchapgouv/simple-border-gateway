# Simple Border Gateway for Matrix federation

This software aims to help opening a private federation hosted on a segmented network securely to other Matrix homeservers.

## Scope

### All traffic

Verify that the request path and verb is valid per the Matrix federation spec, else forbid it.

### Inbound traffic

Incoming authenticated requests are verified against a list of allowed homeservers.

The signature of the requests is verified against the public key of the server, which needs to be specified in the gateway config.

This public key is not really meant to change outside of operational error where it would be lost, hence we don't fetch it dynamically.

This helps against MITM attacks, where the request to fetch the public key could be intercepted and changed.

### Outbound traffic

Outgoing requests are verified against a list of domains corresponding to allowed homeservers endpoints.

Those domains are for now statically defined. We currently don't fetch them from .well-known endpoints,
but we should probably do it.

We should probably pin the CA root certificate to help against MITM attacks.

Signature of authenticated requests are not checked since they are coming from our owned trusted servers.

### Deploy the service

See the [HOWTO guide](./docs/HOWTO.md) for full deployment instructions.
