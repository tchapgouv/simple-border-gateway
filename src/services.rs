use crate::cli::Cli;
use crate::http_gateway::inbound::InboundGatewayBuilder;
use crate::http_gateway::outbound::OutboundGatewayBuilder;
use crate::inbound::InboundHandler;
use crate::matrix::util::NameResolver;
use crate::outbound::OutboundHandler;
use crate::util::{
    CompiledRuleset, build_endpoint_router_from_endpoint_configs, compile_override_rules,
    create_http_client, crypto_provider, read_pem,
};
use log::{debug, error, info};
use snafu::{Report, ResultExt, Whatever};
use tokio::task::JoinHandle;

use std::collections::BTreeMap;
use std::process::exit;

use crate::config::BorderGatewayConfig;
use ruma::{serde::Base64, signatures::PublicKeyMap};

/// A service whose configuration has been fully validated and compiled, ready to be spawned.
///
/// All fallible configuration work (regex compilation, address parsing, certificate
/// loading, ...) happens while building these, which lets a config reload reject a bad
/// configuration before the currently running services are stopped.
pub enum PreparedService {
    Inbound(InboundGatewayBuilder<InboundHandler>),
    Outbound(Box<OutboundGatewayBuilder<OutboundHandler>>),
}

/// Validates the configuration and builds the corresponding services without starting them.
pub fn prepare_services(
    config: BorderGatewayConfig,
    cli: &Cli,
) -> Result<Vec<PreparedService>, Whatever> {
    debug!("Configuration loaded");
    let mut domain_server_name_map = BTreeMap::new();
    let mut target_base_urls: BTreeMap<String, String> = BTreeMap::new();

    for hs in config.internal_homeservers {
        debug!(
            "Internal homeserver {} with federation domain {} and target base url {}",
            hs.server_name, hs.federation_domain, hs.target_base_url
        );
        domain_server_name_map.insert(hs.federation_domain.clone(), hs.server_name.clone());
        target_base_urls.insert(hs.federation_domain, hs.target_base_url.clone());
        // This is useful for well known endpoints
        target_base_urls.insert(hs.server_name, hs.target_base_url);
    }

    let mut named_rulesets: BTreeMap<String, CompiledRuleset> = BTreeMap::new();
    for ruleset in &config.rulesets {
        let additional_endpoints =
            build_endpoint_router_from_endpoint_configs(&ruleset.additional_endpoints)
                .whatever_context(format!(
                    "Failed to build additional endpoints for ruleset '{}'",
                    ruleset.name
                ))?;
        let action_overrides =
            compile_override_rules(&ruleset.override_rules).whatever_context(format!(
                "Failed to compile override rules for ruleset '{}'",
                ruleset.name
            ))?;
        named_rulesets.insert(
            ruleset.name.clone(),
            CompiledRuleset {
                additional_endpoints,
                action_overrides,
            },
        );
    }

    let mut allowed_federation_domains: BTreeMap<String, String> = BTreeMap::new();
    let mut allowed_client_domains: BTreeMap<String, String> = BTreeMap::new();
    let mut public_key_map: PublicKeyMap = BTreeMap::new();
    let mut server_rulesets: BTreeMap<String, CompiledRuleset> = BTreeMap::new();

    for hs in config.external_homeservers {
        debug!(
            "External homeserver {} with federation domain {} and client domain {}",
            hs.server_name, hs.federation_domain, hs.client_domain
        );
        domain_server_name_map.insert(hs.federation_domain.clone(), hs.server_name.clone());
        allowed_federation_domains.insert(hs.federation_domain, hs.server_name.clone());
        domain_server_name_map.insert(hs.client_domain.clone(), hs.server_name.clone());
        allowed_client_domains.insert(hs.client_domain, hs.server_name.clone());

        let mut verify_keys: BTreeMap<String, Base64> = BTreeMap::new();
        for (k, v) in hs.verify_keys {
            verify_keys.insert(
                k,
                Base64::parse(v).whatever_context("Failed to parse verify key as base64")?,
            );
        }

        let compiled_ruleset = match &hs.ruleset {
            Some(name) => match named_rulesets.get(name) {
                Some(e) => {
                    info!(
                        "Using override ruleset '{}' for homeserver '{}'",
                        name, hs.server_name
                    );
                    e.clone()
                }
                None => {
                    snafu::whatever!(
                        "Homeserver '{}' references unknown ruleset '{}'",
                        hs.server_name,
                        name
                    )
                }
            },
            None => {
                info!("Using default ruleset for homeserver '{}'", hs.server_name);
                CompiledRuleset::default()
            }
        };
        server_rulesets.insert(hs.server_name.clone(), compiled_ruleset);

        public_key_map.insert(hs.server_name, verify_keys);
    }

    let mut services = vec![];
    let name_resolver = NameResolver::new(domain_server_name_map);

    if let Some(inbound_config) = config.inbound_proxy {
        if cli.outbound_only {
            info!(
                "Inbound proxy is configured but --outbound-only is set, inbound proxy will not be started"
            );
        } else {
            let http_client = create_http_client(inbound_config.additional_root_certs, None)
                .whatever_context("Failed to create inbound http client")?;
            let handler = InboundHandler::new(
                name_resolver.clone(),
                public_key_map,
                server_rulesets.clone(),
                cli.reject_all_by_default,
            );

            let listen_address = inbound_config
                .listen_address
                .parse()
                .whatever_context("Failed to parse inbound listen address")?;

            services.push(PreparedService::Inbound(
                InboundGatewayBuilder::new(listen_address, target_base_urls, handler)
                    .with_http_client(http_client),
            ));
            info!("Inbound proxy initialized");
        }
    }

    if let Some(outbound_config) = config.outbound_proxy {
        if cli.inbound_only {
            info!(
                "Outbound proxy is configured but --inbound-only is set, outbound proxy will not be started"
            );
        } else {
            let http_client = create_http_client(
                outbound_config.additional_root_certs,
                outbound_config.upstream_proxy,
            )
            .whatever_context("Failed to create outbound http client")?;
            let handler = OutboundHandler::new(
                name_resolver,
                allowed_federation_domains,
                allowed_client_domains,
                outbound_config.hazmat_non_matrix_endpoints,
                server_rulesets,
                cli.reject_all_by_default,
            )
            .whatever_context("Failed to create outbound handler")?;

            let ca_private_key = read_pem(outbound_config.ca_priv_key.as_str())
                .whatever_context("Can't read CA private key for outbound proxy")?;
            let ca_cert = read_pem(&outbound_config.ca_cert)
                .whatever_context("Can't read CA certificate for outbound proxy")?;

            let listen_address = outbound_config
                .listen_address
                .parse()
                .whatever_context("Failed to parse outbound listen address")?;

            let builder = OutboundGatewayBuilder::new(
                listen_address,
                ca_private_key,
                ca_cert,
                crypto_provider::default_provider(),
                handler,
            )
            .whatever_context("Failed to create outbound gateway")?
            .with_http_client(http_client);
            services.push(PreparedService::Outbound(Box::new(builder)));
            info!("Outbound proxy initialized");
        }
    }
    Ok(services)
}

/// Spawns the given prepared services, returning their task handles.
pub fn spawn_services(services: Vec<PreparedService>) -> Vec<JoinHandle<()>> {
    services
        .into_iter()
        .map(|service| match service {
            PreparedService::Inbound(builder) => tokio::spawn(async move {
                if let Err(err) = builder.build_and_run().await {
                    error!("Failed to create inbound proxy");
                    error!("{}", Report::from_error(err));
                    exit(1);
                }
            }),
            PreparedService::Outbound(builder) => tokio::spawn(async move {
                if let Err(err) = builder.build_and_run().await {
                    error!("Failed to create outbound proxy");
                    error!("{}", Report::from_error(err));
                    exit(1);
                }
            }),
        })
        .collect()
}

/// Aborts the given tasks and awaits their termination.
///
/// `JoinHandle::abort` only requests cancellation; the task may still be running
/// (and holding resources such as its listening socket) when it returns. Awaiting
/// the handles guarantees the tasks have actually stopped and released their
/// resources before new services are started, avoiding `EADDRINUSE` on reload.
pub async fn stop_services(tasks: Vec<JoinHandle<()>>) {
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        // An aborted task resolves with a cancellation error, which is expected.
        let _ = task.await;
    }
}
