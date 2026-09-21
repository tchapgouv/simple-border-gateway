# Simple Border Gateway for Matrix federation

The service exposes two distinct proxy endpoints:

- **Inbound proxy**  
  Entry point for **external homeservers**. All federation requests coming from outside your private network will go through this endpoint.

- **Outbound proxy**  
  HTTP forward proxy. All outbound federation traffic is routed through this proxy so the gateway can validate, filter, or block requests before they leave the restricted network.

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
docker build . -t simple-border-gateway:latest
docker run -v ./data:/data simple-border-gateway:latest --config-file /data/config.toml
```

**You can also compile the binary directly using Cargo using `cargo run` if you prefer to run it outside Docker.**

## Configure the service

The Simple Border Gateway uses a single configuration file (TOML) to define its listening interfaces, certificate setup, and the list of trusted homeservers.

Below is a breakdown of the main sections:

- **`[inbound_proxy]`**: Defines where the gateway listens for **incoming federation requests (from external servers)**.
    - `listen_address`: the network address and port to accept incoming HTTP requests from external homeservers.
- **`[outbound_proxy]`**: Configures the **proxy endpoint** used by internal homeservers for outgoing federation.

- `listen_address`: the address where internal workers connect to send outbound federation traffic.
- `ca_priv_key` / `ca_cert`:  PEM-encoded private key and certificate for the local Certificate Authority (CA).
    
    These are used by the outbound proxy to dynamically sign short-lived certificates for target domains, allowing inspection and policy enforcement on encrypted HTTPS traffic. **CA certificates protected with a password are not currently supported**.
    
- `additional_root_certs`: optional list of extra CA certificates trusted by the gateway. It can either be a path or the certificate, directly.
- `hazmat_non_matrix_endpoints`: optional list of endpoints allowed on specific non-Matrix domains, besides the federation traffic. Each entry defines an `id`, the destination `domain` it applies to (**required**), a `path` pattern (`{name}` matches a single path segment, a trailing `{*name}` matches all remaining segments) and an optional `method`. A request is forwarded when its destination host matches `domain` and its path (and method, if set) matches the endpoint. This can be useful if other traffic needs to go through the gateway, like push notifications.
- **`[outbound_proxy.upstream_proxy]`:** (Optional) Defines an upstream proxy if outbound traffic must be chained through another proxy layer.
- **`[[internal_homeservers]]`:** Declares homeservers that belong to the private federation.
    
    Each entry includes:
    
    - `server_name`: Matrix server name used in federation headers.
    - `federation_domain`: public-facing domain for federation.
    - `target_base_url`: internal base URL where the gateway forwards traffic for that homeserver.
  
**`[[external_homeservers]]`:** Lists explicitly trusted external homeservers.

- `server_name`: expected Matrix server name.
- `federation_domain` / `client_domain`: domains used for federation and client APIs.
- `verify_keys`: mapping of trusted signing keys used to validate incoming requests.

**You need to specify the federation domains in the configuration as the gateway, in its version 0.1.0, does not rely on the `/.well-known/matrix/server` endpoint.**

Here is an example of a working configuration: 

```toml
[inbound_proxy]
listen_adress = "0.0.0.0:8000"

[outbound_proxy]
listen_adress = "0.0.0.0:3128"
ca_priv_key = "ca.pem"
ca_cert = "ca.crt"

additional_root_certs = ["/data/ca_cit.crt"]

[[outbound_proxy.hazmat_non_matrix_endpoints]]
id = "webpush_mozilla"
domain = "updates.push.services.mozilla.com"
path = "{*anything}"
method = "POST"

[outbound_proxy.upstream_proxy]
url = "https://127.0.0.1:3128"

[[internal_homeservers]]
server_name = "servera.tchap.io"
federation_domain = "inbound.servera.tchap.io"
target_base_url = "https://servera.tchap.io"

[[external_homeservers]]
server_name = "matrix.org"
federation_domain = "matrix-federation.matrix.org"
client_domain = "matrix-client.matrix.org"
verify_keys = { "ed25519:a_RXGa" = "l8Hft5qXKn1vfHrg3p4+W8gELQVo8N13JkluMfmn2sQ" }

```

## Expose the service

Depending on the mode (**outbound** or **inbound**), the way you expose the Simple Border Gateway differs.

### Inbound

To ensure all **external homeservers** reach your federation **through the gateway**, expose the gateway’s public endpoint via `/.well-known/matrix/server`.

If your homeserver is behind **Nginx**, you can add the following example configuration to return the gateway’s federation address:

```nginx
location ~ ^/.well-known/matrix/server$ {
    return 200 '{"m.server":"inbound.servera.tchap.io:443"}';
}
```

This tells remote homeservers to send all federation traffic to the gateway URL, which corresponds to the inbound side of your gateway. 

**Synapse homeservers use HTTPS for inter-server communications, even within the same network. It’s strongly recommended to expose your gateway under a valid TLS-enabled domain name.**

### Outbound

In order to use the gateway with your installation, you need to configure Synapse to use it as an HTTPS proxy for outgoing federation traffic.

You have multiple ways of proceeding:

- Setting it up on all workers, or on the single Synapse instance in a monolithic deployment.
- Setting it up only on dedicated workers, such as the `Federation senders`, if you have one configured.

Regardless of the approach, the HTTPS proxy must point to the outbound endpoint of your deployed gateway. Example configuration in the homeserver configuration of Synapse:

```yaml
  http_proxy: http://bordergateway:3128
  # Synapse will mainly use HTTPS
  https_proxy: http://bordergateway:3128
  no_proxy_hosts:
    - localhost
    - 127.0.0.1
    - db
    - redis
    ...
```

You can also find more information on how to setup the proxy [here](http://element-hq.github.io/synapse/latest/setup/forward_proxy.html). There are several ways to set it up, either from the Synapse configuration, or your deployment stack using environment variables, such as `HTTP_PROXY` and `HTTPS_PROXY`.

Alternatively, if you are interested in setting up workers for your Synapse installation, you can do it [here](https://element-hq.github.io/synapse/latest/workers.html)