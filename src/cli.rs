use std::path::PathBuf;

use clap::Parser;
use log::{LevelFilter, error, info};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Log level, defaults to INFO
    #[arg(short = 'l', long, value_name = "LEVEL")]
    pub log_level: Option<LevelFilter>,

    /// Only run the inbound proxy, config will be ignored
    #[arg(short = 'i', long, default_value = "false")]
    pub inbound_only: bool,

    /// Only run the outbound proxy, config will be ignored
    #[arg(short = 'o', long, default_value = "false")]
    pub outbound_only: bool,

    /// Sets a custom config file
    #[arg(short = 'c', long, value_name = "FILE", default_value = "config.toml")]
    pub config_file: PathBuf,

    /// Reject every default endpoint that is not explicitly allowed by an override rule.
    #[arg(long, default_value = "false")]
    pub reject_all_by_default: bool,
}

pub fn parse_cli() -> Cli {
    let cli = Cli::parse();
    if cli.inbound_only && cli.outbound_only {
        error!("Cannot use --inbound-only and --outbound-only at the same time");
        std::process::exit(1);
    }

    if cli.reject_all_by_default {
        info!(
            "Reject all by default mode enabled. The default ruleset will reject all endpoints, and only endpoints explicitly allowed by override rules will be accepted."
        );
    }
    cli
}
