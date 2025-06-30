# Simple Border Gateway for Matrix federation

This software aims to help opening a private federation hosted on a segmented network securely to other Matrix homeservers.

## Scope

Verify that the request path is a valid Matrix federation path per the spec, else forbid it.

### Inbound traffic

Incoming authenticated requests are verified against a list of allowed homeservers.

The signature of the requests is verified against the public key of the server, which needs to be specified in the gateway config.

This public key is not really meant to change outside of operational error where it would be lost, hence we don't fetch it dynamically.

This protects against MITM attack, where the request to fetch the public key would be intercepted and changed.

### Outbound traffic

## Contributing

This software is still WIP and we are still refactoring quite often
so for now we'd rather get code suggestions as issues or discussions rather than PRs.

You are however very welcome for any PR improving the CI or the documentation :)
