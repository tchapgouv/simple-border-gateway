# Simple Border Gateway for Matrix federation

## Overview

**Simple Border Gateway** provides a controlled interface between a **private Matrix federation** and **external homeservers**.

It inspects and validates all federation traffic, enforcing **certificate pinning**, **domain allow-listing**, and **schema verification** on both inbound and outbound requests.

The gateway is designed for environments where homeservers are deployed in restricted networks but still need selective federation with trusted external domains. All federation communication passes through this service, ensuring that no direct connections occur between internal and external servers.

The service exposes two distinct proxy endpoints:

- **Inbound proxy**  
  Entry point for **external homeservers**. All federation requests coming from outside your private network must go through this endpoint.

- **Outbound proxy**  
  HTTP proxy used by **internal Synapse federation workers**. All outbound federation traffic is routed through this proxy so the gateway can validate, filter, or block requests before they leave the restricted network.

## Requirements

Before deploying the **Simple Border Gateway**, make sure that all **outgoing federation requests** are handled by a **dedicated worker**. This worker must be configured to use the gateway as an **HTTP & HTTPS proxy**, allowing the gateway to inspect, validate, or reject outbound federation traffic as needed.

An example configuration inside the `homeserver.yaml` file of your Synapse instance:

```yaml
### Federation ###
# This will disable federation sending on the main Synapse instance
send_federation: false
federation_sender_instances:
  - federation-sender
federation_receiver_instances:
  - federation-receiver
# Make sure outbound federation traffic only goes through a specified subset of workers
outbound_federation_restricted_to:
  - federation-sender
worker_replication_secret: "your_secret"

```

An example of a worker configuration: 

```yaml
worker_app: synapse.app.federation_sender
worker_name: federation-sender

worker_listeners:
  - type: http
    port: 8034
    resources:
      - names: [federation]

worker_log_config: /conf/workers/federation-sender.log.config

```

## Deploy the service

The **Simple Border Gateway** can be deployed in any environment that supports long-running services. For quick testing or small-scale setups, **Docker Compose** is the most convenient option.

Production deployments can also use **systemd**, **Nomad**, or **Kubernetes**, depending on your infrastructure. This documentation however focuses on the Docker Compose approach for simplicity.

Example configuration:

```yaml
  border-gateway:
    container_name: border-gateway
    image: gateway:dev
    build:
      context: ./projects/infra/simple-border-gateway
      dockerfile: ./Dockerfile
    restart: unless-stopped
    volumes:
      - ./docker/gateway/config.toml:/data/config.toml:ro
      - ./docker/gateway/ca.pem:/data/ca.pem:ro
      - ./docker/gateway/ca.crt:/data/ca.crt:ro
    ports:
      - 8000
      - 3128
    hostname: gateway.proxy
    networks:
      - local-env-net-gateway
```

If you simply want to **run the gateway manually** to verify that it starts correctly, you can build and launch it directly from the project folder using Docker:

```bash
docker build . -t simple-border-gateway:0.0.1
docker run -v ./data:/data simple-border-gateway:0.0.1 --config-file /data/config.toml
```

💡 You can also compile the binary directly using Cargo using `cargo run` if you prefer to run it outside Docker. If you choose this approach, note that the project was developed and tested against **Rust Stable 1.90.0**. It’s **recommended** to use the same version to avoid potential build or compatibility issues.

## Configure the service

The Simple Border Gateway uses a single configuration file (TOML) to define its listening interfaces, certificate setup, and the list of trusted homeservers.

Below is a breakdown of the main sections:

- **`[inbound_proxy]`**: Defines where the gateway listens for **incoming federation requests (from external servers)**.
    - `listen_address`: the network address and port to accept incoming HTTP requests from external homeservers.
- **`[outbound_proxy]`**: Configures the **proxy endpoint** used by internal homeservers for outgoing federation.

- `listen_address`: the address where internal workers connect to send outbound federation traffic.
- `ca_priv_key` / `ca_cert`:  PEM-encoded private key and certificate for the local Certificate Authority (CA).
    
    These are used by the outbound proxy to dynamically sign short-lived certificates for target domains, allowing inspection and policy enforcement on encrypted HTTPS traffic.
    
    💡 CA certificates protected with a password are not currently supported.
    
- `additional_root_certs`: optional list of extra CA certificates trusted by the gateway. It can either be a path or the certificate, directly.
- `allowed_non_matrix_regexes_dangerous`: optional patterns allowing specific non-Matrix endpoints, besides the federations traffic.
- **`[outbound_proxy.upstream_proxy]`:** (Optional) Defines an upstream proxy if outbound traffic must be chained through another proxy layer.
- **`[[internal_homeservers]]`:** Declares homeservers that belong to the private federation.
    
    Each entry includes:
    
    - `server_name`: Matrix server name used in federation headers.
    - `federation_domain`: public-facing domain for federation.
    - `target_base_url`: internal base URL where the gateway forwards traffic for that homeserver.
    
    💡 You don’t need to specify verify keys here, the gateway does not validate keys for internal homeservers.
    

**`[[external_homeservers]]`:** Lists explicitly trusted external homeservers.

- `server_name`: expected Matrix server name.
- `federation_domain` / `client_domain`: domains used for federation and client APIs.
- `verify_keys`: mapping of trusted signing keys used to validate incoming requests.

💡 You need to specify the federation domains in the configuration as the gateway, in its version 0.1.0, does not rely on the `/.well-known/matrix/server` endpoint. 

Here is an example of a working configuration: 

```toml
[inbound_proxy]
listen_adress = "0.0.0.0:8000"

[outbound_proxy]
listen_adress = "0.0.0.0:3128"
ca_priv_key = "ca.pem"
ca_cert = "ca.crt"

additional_root_certs = ["/data/ca_cit.crt"]

allowed_non_matrix_regexes_dangerous = [
    "https://ntfy\\.sh/.*"
]

[outbound_proxy.upstream_proxy]
url = "https://127.0.0.1:3128"

[[internal_homeservers]]
server_name = "tenantA.tchap.io"
federation_domain = "tenanta.tchap.io"
target_base_url = "https://tenanta.tchap.io"

[[internal_homeservers]]
server_name = "tenantB.tchap.io"
federation_domain = "tenantb.tchap.io"
target_base_url = "https://tenantb.tchap.io"

[[external_homeservers]]
server_name = "matrix.org"
federation_domain = "matrix-federation.matrix.org"
client_domain = "matrix-client.matrix.org"
verify_keys = { "ed25519:a_RXGa" = "l8Hft5qXKn1vfHrg3p4+W8gELQVo8N13JkluMfmn2sQ" }

```

## Expose the service

Depending on the mode (**outbound** or **inbound**), the way you expose the Simple Border Gateway differs.

### Outbound

To ensure all **external homeservers** reach your federation **through the gateway**, expose the gateway’s public endpoint via `/.well-known/matrix/server`.

If your homeserver is behind **Nginx**, you can add the following example configuration to return the gateway’s federation address:

```toml
location ~ ^/.well-known/matrix/server$ {
    return 200 '{"m.server":"inbound.tchap.io:443"}';
}
```

This tells remote homeservers to send all federation traffic to the gateway URL, which corresponds to the inbound side of your gateway.

### Inbound

Depending on your setup, you can redirect federation traffic from your **federation worker only** to the gateway. For example, when using **Docker Compose**, you can configure a proxy to force outbound federation requests through the gateway:

```yaml
    container_name: federation-sender-tenantB
    environment:
      HTTP_PROXY: "http://gateway.proxy:3128"
      HTTPS_PROXY: "https://outbound.gateway.tchap.io:4443"
      NO_PROXY: "localhost,127.0.0.1,db,redis,.tchap.io"
```

You can also set up the proxy configuration inside the worker configuration file: 

```yaml
http_proxy: http://USERNAME:PASSWORD@10.0.1.1:8080/
https_proxy: http://USERNAME:PASSWORD@proxy.example.com:8080/
no_proxy_hosts:
  - master.hostname.example.com
  - 10.1.0.0/16
  - 172.30.0.0/16
```

You can find more information on how to setup the proxy [here](http://element-hq.github.io/synapse/latest/setup/forward_proxy.html).

💡 Synapse homeservers use HTTPS for inter-server communications, even within the same network. It’s strongly recommended to expose your gateway under a valid TLS-enabled domain name.

💡 The gateway is **only designed to act as a border with external servers**. Internal homeservers within the same private federation **must bypass the proxy entirely**, as internal-to-internal federation will **not function** through the gateway.