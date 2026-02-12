//! `MTProxy` Rust implementation - Main entry point
//!
//! This is the Rust-native implementation of `MTProxy`, migrated from C.
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
#[allow(clippy::struct_excessive_bools)]
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
    mtproxy_secrets: Vec<String>,

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

/// Validate command-line arguments
fn validate_args(args: &Args) -> Result<(), String> {
    // Check CPU threads range
    if !(1..=64).contains(&args.cpu_threads) {
        return Err(format!(
            "CPU threads must be between 1 and 64, got {}",
            args.cpu_threads
        ));
    }

    // Check I/O threads range
    if !(1..=64).contains(&args.io_threads) {
        return Err(format!(
            "I/O threads must be between 1 and 64, got {}",
            args.io_threads
        ));
    }

    // Validate secrets are 32 hex characters
    for secret in &args.mtproxy_secrets {
        if secret.len() != 32 {
            return Err(format!(
                "MTProto secret must be exactly 32 hex digits, got {} characters",
                secret.len()
            ));
        }
        if !secret.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "MTProto secret must contain only hex digits, got '{secret}'"
            ));
        }
    }

    // Validate proxy tag
    if let Some(tag) = &args.proxy_tag {
        if tag.len() != 32 {
            return Err(format!(
                "Proxy tag must be exactly 32 hex digits, got {} characters",
                tag.len()
            ));
        }
        if !tag.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "Proxy tag must contain only hex digits, got '{tag}'"
            ));
        }
    }

    Ok(())
}

/// Print configuration information
fn print_configuration(args: &Args) {
    eprintln!("Configuration:");
    eprintln!("  IPv6: {}", args.ipv6);
    eprintln!("  Port: {:?}", args.port);
    eprintln!("  HTTP ports: {:?}", args.http_ports);
    eprintln!("  Workers: {:?}", args.workers);
    eprintln!("  User: {:?}", args.user);
    eprintln!("  Config file: {:?}", args.config);
    eprintln!("  Secrets count: {}", args.mtproxy_secrets.len());
    eprintln!("  Domains count: {}", args.domains.len());
    eprintln!("  CPU threads: {}", args.cpu_threads);
    eprintln!("  I/O threads: {}", args.io_threads);
    eprintln!("  Daemonize: {}", args.daemonize);
    eprintln!("  Verbosity: {}", args.verbosity);
}

/// Initialize runtime
#[allow(clippy::unnecessary_wraps)]
fn runtime_init(_args: &Args) -> Result<(), String> {
    // Phase 2 (Entry Point) runtime initialization
    // This is a stub for now - actual engine initialization will be
    // implemented in Phase 3 (Core Runtime)

    // TODO: Initialize engine state
    // TODO: Set up signal handlers
    // TODO: Initialize logging
    // TODO: Load configuration
    // TODO: Initialize crypto subsystem
    // TODO: Set up worker processes if needed

    Ok(())
}

/// Start main runtime loop
#[allow(clippy::unnecessary_wraps)]
fn runtime_start(args: &Args) -> Result<(), String> {
    // Phase 2 (Entry Point) runtime startup
    // This is a stub for now - actual event loop will be
    // implemented in Phase 3 (Core Runtime)

    eprintln!("\n=== MTProxy Rust Runtime ===");
    eprintln!("Entry Point phase (Phase 2) complete:");
    eprintln!("  ✓ CLI argument parsing");
    eprintln!("  ✓ Argument validation");
    eprintln!("  ✓ Configuration parse probe");
    eprintln!("  ✓ Runtime initialization structure");
    eprintln!("\nNext steps (Phase 3 - Core Runtime):");
    eprintln!("  [ ] Port engine framework (engine.c, engine-net.c)");
    eprintln!("  [ ] Port job system (jobs/jobs.c)");
    eprintln!("  [ ] Implement worker process management");
    eprintln!("  [ ] Implement signal handling");
    eprintln!("  [ ] Implement main event loop");
    eprintln!("\nCurrent status:");
    eprintln!("  This binary demonstrates the Entry Point with full CLI parsing.");
    eprintln!("  Use the C binary (objs/bin/mtproto-proxy) for actual proxy operation.");
    eprintln!("  See MIGRATION_STATUS.md for detailed migration status.");

    if args.config.is_none() {
        eprintln!("\n⚠ WARNING: No config file specified.");
        eprintln!("  A config file will be required for the full runtime.");
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    // Display bootstrap information
    let signature = mtproxy_core::bootstrap_signature();
    let remaining_c_units = mtproxy_core::step15::step15_remaining_c_units();

    if args.verbosity > 0 {
        eprintln!("{signature}");
        eprintln!("Step 15 migration status: {remaining_c_units} C units remaining\n");
    }

    // Validate arguments
    if let Err(e) = validate_args(&args) {
        eprintln!("ERROR: {e}");
        process::exit(1);
    }

    if args.verbosity > 0 {
        print_configuration(&args);
        eprintln!();
    }

    // Run configuration parse probe if config file is provided
    if args.config.is_some() {
        let parse_probe = mtproto_config_parse_probe();
        if let Ok((targets, clusters)) = parse_probe {
            if args.verbosity > 0 {
                eprintln!("Config parse probe successful:");
                eprintln!("  Targets: {targets}");
                eprintln!("  Clusters: {clusters}\n");
            }
        } else {
            eprintln!("ERROR: Config parse probe failed");
            process::exit(1);
        }
    }

    // Initialize runtime
    match runtime_init(&args) {
        Ok(()) => {
            if args.verbosity > 1 {
                eprintln!("Runtime initialization successful\n");
            }
        }
        Err(e) => {
            eprintln!("ERROR: Runtime initialization failed: {e}");
            process::exit(1);
        }
    }

    // Start main runtime loop
    match runtime_start(&args) {
        Ok(()) => {
            if args.verbosity > 1 {
                eprintln!("\nRuntime completed successfully");
            }
        }
        Err(e) => {
            eprintln!("ERROR: Runtime start failed: {e}");
            process::exit(1);
        }
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
    use super::*;

    #[test]
    fn parse_probe_uses_core_full_pass_path() {
        let out = mtproto_config_parse_probe().expect("full-pass probe should parse");
        assert_eq!(out, (1, 1));
    }

    #[test]
    fn validate_args_accepts_valid_cpu_threads() {
        let args = Args {
            config: None,
            ipv6: false,
            port: None,
            http_ports: None,
            workers: None,
            user: None,
            backlog: None,
            max_connections: None,
            max_special_connections: None,
            log_file: None,
            window_clamp: None,
            mtproxy_secrets: vec![],
            proxy_tag: None,
            domains: vec![],
            aes_pwd: None,
            ping_interval: 5.0,
            daemonize: false,
            verbosity: 0,
            nat_info: None,
            bind_address: None,
            http_stats: false,
            cpu_threads: 8,
            io_threads: 16,
            allow_skip_dh: false,
            force_dh: false,
            max_accept_rate: None,
            max_dh_accept_rate: None,
        };
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn validate_args_rejects_invalid_cpu_threads() {
        let mut args = Args {
            config: None,
            ipv6: false,
            port: None,
            http_ports: None,
            workers: None,
            user: None,
            backlog: None,
            max_connections: None,
            max_special_connections: None,
            log_file: None,
            window_clamp: None,
            mtproxy_secrets: vec![],
            proxy_tag: None,
            domains: vec![],
            aes_pwd: None,
            ping_interval: 5.0,
            daemonize: false,
            verbosity: 0,
            nat_info: None,
            bind_address: None,
            http_stats: false,
            cpu_threads: 0,
            io_threads: 16,
            allow_skip_dh: false,
            force_dh: false,
            max_accept_rate: None,
            max_dh_accept_rate: None,
        };
        assert!(validate_args(&args).is_err());

        args.cpu_threads = 65;
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn validate_args_rejects_invalid_secret_length() {
        let args = Args {
            config: None,
            ipv6: false,
            port: None,
            http_ports: None,
            workers: None,
            user: None,
            backlog: None,
            max_connections: None,
            max_special_connections: None,
            log_file: None,
            window_clamp: None,
            mtproxy_secrets: vec!["abc123".to_string()],
            proxy_tag: None,
            domains: vec![],
            aes_pwd: None,
            ping_interval: 5.0,
            daemonize: false,
            verbosity: 0,
            nat_info: None,
            bind_address: None,
            http_stats: false,
            cpu_threads: 8,
            io_threads: 16,
            allow_skip_dh: false,
            force_dh: false,
            max_accept_rate: None,
            max_dh_accept_rate: None,
        };
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn validate_args_accepts_valid_secret() {
        let args = Args {
            config: None,
            ipv6: false,
            port: None,
            http_ports: None,
            workers: None,
            user: None,
            backlog: None,
            max_connections: None,
            max_special_connections: None,
            log_file: None,
            window_clamp: None,
            mtproxy_secrets: vec!["0123456789abcdef0123456789abcdef".to_string()],
            proxy_tag: None,
            domains: vec![],
            aes_pwd: None,
            ping_interval: 5.0,
            daemonize: false,
            verbosity: 0,
            nat_info: None,
            bind_address: None,
            http_stats: false,
            cpu_threads: 8,
            io_threads: 16,
            allow_skip_dh: false,
            force_dh: false,
            max_accept_rate: None,
            max_dh_accept_rate: None,
        };
        assert!(validate_args(&args).is_ok());
    }
}
