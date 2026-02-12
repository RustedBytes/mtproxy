//! MTProxy Rust implementation - Main entry point
//!
//! This is the Rust-native implementation of MTProxy, migrated from C.
//! For the migration status, see `PLAN.md` Step 15.

use clap::Parser;
use mtproxy_core::runtime::mtproto::config::{
    cfg_parse_config_full_pass, MtprotoConfigDefaults, MtprotoProxyTargetPassAction,
};
use std::path::PathBuf;
use std::process;

/// Simple MT-Proto proxy - Rust implementation
#[derive(Parser, Debug)]
#[command(name = "mtproxy-rust")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "MTProxy: Simple MT-Proto proxy (Rust implementation)", long_about = None)]
struct Args {
    /// Config file path
    #[arg(value_name = "CONFIG_FILE")]
    config: Option<PathBuf>,

    /// Enable IPv6 TCP/UDP support
    #[arg(short = '6', long = "ipv6")]
    ipv6: bool,

    /// Listening port number or port range (e.g., 8080 or 8080:8090)
    #[arg(short = 'p', long = "port")]
    port: Option<String>,

    /// Comma-separated list of client (HTTP) ports to listen
    #[arg(short = 'H', long = "http-ports")]
    http_ports: Option<String>,

    /// Spawn several slave workers
    #[arg(short = 'M', long = "slaves")]
    workers: Option<u32>,

    /// User name to make setuid (drop privileges)
    #[arg(short = 'u', long = "user")]
    user: Option<String>,

    /// Backlog size
    #[arg(short = 'b', long = "backlog")]
    backlog: Option<u32>,

    /// Maximal connections number
    #[arg(short = 'c', long = "connections")]
    max_connections: Option<u32>,

    /// Maximal number of accepted client connections per worker
    #[arg(short = 'C', long = "max-special-connections")]
    max_special_connections: Option<u32>,

    /// Log file name
    #[arg(short = 'l', long = "log")]
    log_file: Option<PathBuf>,

    /// Window clamp for client TCP connections
    #[arg(short = 'W', long = "window-clamp")]
    window_clamp: Option<u32>,

    /// 16-byte secret in hex mode (can be specified multiple times)
    #[arg(short = 'S', long = "mtproto-secret")]
    mtproto_secrets: Vec<String>,

    /// 16-byte proxy tag in hex mode
    #[arg(short = 'P', long = "proxy-tag")]
    proxy_tag: Option<String>,

    /// Allowed domain for TLS-transport mode (can be specified multiple times)
    #[arg(short = 'D', long = "domain")]
    domains: Vec<String>,

    /// Custom secret.conf file
    #[arg(long = "aes-pwd")]
    aes_pwd: Option<PathBuf>,

    /// Ping interval in seconds for local TCP connections
    #[arg(short = 'T', long = "ping-interval", default_value = "5.0")]
    ping_interval: f64,

    /// Daemonize mode
    #[arg(short = 'd', long = "daemonize")]
    daemonize: bool,

    /// Verbosity level (can be specified multiple times)
    #[arg(short = 'v', long = "verbosity", action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Network address translation for RPC protocol handshake (format: local-addr:global-addr)
    #[arg(long = "nat-info")]
    nat_info: Option<String>,

    /// Try to bind socket only to specified address
    #[arg(long = "address")]
    bind_address: Option<String>,

    /// Allow HTTP server to answer on stats queries
    #[arg(long = "http-stats")]
    http_stats: bool,

    /// Number of CPU threads (1-64)
    #[arg(long = "cpu-threads", default_value = "8")]
    cpu_threads: u32,

    /// Number of I/O threads (1-64)
    #[arg(long = "io-threads", default_value = "16")]
    io_threads: u32,

    /// Allow skipping DH during RPC handshake
    #[arg(long = "allow-skip-dh")]
    allow_skip_dh: bool,

    /// Force using DH for all outbound RPC connections
    #[arg(long = "force-dh")]
    force_dh: bool,

    /// Max number of connections per second that is allowed to accept
    #[arg(long = "max-accept-rate")]
    max_accept_rate: Option<u32>,

    /// Max number of DH connections per second that is allowed to accept
    #[arg(long = "max-dh-accept-rate")]
    max_dh_accept_rate: Option<u32>,
}

fn main() {
    let args = Args::parse();
    
    // Display bootstrap information
    let signature = mtproxy_core::bootstrap_signature();
    let remaining_c_units = mtproxy_core::step15::step15_remaining_c_units();
    
    eprintln!("{signature}");
    eprintln!("Step 15 migration status: {} C units remaining", remaining_c_units);
    
    if args.verbosity > 0 {
        eprintln!("Configuration:");
        eprintln!("  IPv6: {}", args.ipv6);
        eprintln!("  Port: {:?}", args.port);
        eprintln!("  HTTP ports: {:?}", args.http_ports);
        eprintln!("  Workers: {:?}", args.workers);
        eprintln!("  User: {:?}", args.user);
        eprintln!("  Config file: {:?}", args.config);
        eprintln!("  Secrets count: {}", args.mtproto_secrets.len());
        eprintln!("  Domains count: {}", args.domains.len());
    }
    
    // Run configuration parse probe
    let parse_probe = mtproto_config_parse_probe();
    match parse_probe {
        Ok((targets, clusters)) => {
            if args.verbosity > 0 {
                eprintln!("Config parse probe successful:");
                eprintln!("  Targets: {targets}");
                eprintln!("  Clusters: {clusters}");
            }
        }
        Err(()) => {
            eprintln!("ERROR: Config parse probe failed");
            process::exit(1);
        }
    }
    
    // TODO: Implement actual proxy runtime
    // For now, this is a placeholder that demonstrates argument parsing
    // The actual runtime will be implemented as C modules are migrated
    
    eprintln!("\nNOTE: Full proxy runtime not yet implemented in Rust.");
    eprintln!("This binary demonstrates the command-line interface and configuration parsing.");
    eprintln!("Use the C binary (objs/bin/mtproto-proxy) for actual proxy operation.");
    eprintln!("\nFor migration status, see PLAN.md Step 15.");
    
    if args.config.is_none() {
        eprintln!("\nERROR: Config file is required");
        process::exit(1);
    }
}

fn mtproto_config_parse_probe() -> Result<(usize, usize), ()> {
    let mut actions = [MtprotoProxyTargetPassAction::default(); 4];
    cfg_parse_config_full_pass::<8>(
        b"proxy dc1:443;",
        MtprotoConfigDefaults {
            min_connections: 2,
            max_connections: 64,
        },
        false,
        8,
        16,
        &mut actions,
    )
    .map(|out| (out.tot_targets, out.auth_clusters))
    .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::mtproto_config_parse_probe;

    #[test]
    fn parse_probe_uses_core_full_pass_path() {
        let out = mtproto_config_parse_probe().expect("full-pass probe should parse");
        assert_eq!(out, (1, 1));
    }
}
