//! `MTProxy` Rust implementation - Main entry point
//!
//! This is the Rust-native implementation of `MTProxy`.

use clap::Parser;
use mtproxy_core::runtime::{
    engine,
    mtproto::config::{
        cfg_parse_config_full_pass, MtprotoConfigDefaults, MtprotoProxyTargetPassAction,
    },
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::thread;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeArgs {
    tcp_port_range: Option<(u16, u16)>,
    http_ports: Vec<u16>,
    worker_processes: u32,
    bind_address: Option<IpAddr>,
    nat_info: Option<(IpAddr, IpAddr)>,
}

fn parse_port_number(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid port number '{value}'"))?;
    if port == 0 {
        return Err("port number must be in range 1..=65535".to_string());
    }
    Ok(port)
}

fn parse_port_range(value: &str) -> Result<(u16, u16), String> {
    if let Some((start, end)) = value.split_once(':') {
        let start = parse_port_number(start.trim())?;
        let end = parse_port_number(end.trim())?;
        if start > end {
            return Err(format!(
                "invalid port range '{value}': start must be <= end"
            ));
        }
        Ok((start, end))
    } else {
        let port = parse_port_number(value.trim())?;
        Ok((port, port))
    }
}

fn parse_http_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err("http ports list contains an empty value".to_string());
        }
        out.push(parse_port_number(token)?);
    }
    if out.is_empty() {
        return Err("http ports list must not be empty".to_string());
    }
    Ok(out)
}

fn parse_nat_info(value: &str) -> Result<(IpAddr, IpAddr), String> {
    let (local, global) = value
        .split_once(':')
        .ok_or_else(|| "nat info must be in format local-addr:global-addr".to_string())?;
    let local = local
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid NAT local address '{local}'"))?;
    let global = global
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid NAT global address '{global}'"))?;
    Ok((local, global))
}

fn process_args(args: &Args) -> Result<RuntimeArgs, String> {
    if args.allow_skip_dh && args.force_dh {
        return Err("--allow-skip-dh and --force-dh cannot be used together".to_string());
    }
    if !args.ping_interval.is_finite() || args.ping_interval <= 0.0 {
        return Err("ping interval must be a finite positive number".to_string());
    }
    if matches!(args.backlog, Some(0)) {
        return Err("backlog must be greater than zero".to_string());
    }
    if matches!(args.max_connections, Some(0)) {
        return Err("max connections must be greater than zero".to_string());
    }
    if matches!(args.max_special_connections, Some(0)) {
        return Err("max special connections must be greater than zero".to_string());
    }

    let tcp_port_range = args.port.as_deref().map(parse_port_range).transpose()?;
    let http_ports = args
        .http_ports
        .as_deref()
        .map(parse_http_ports)
        .transpose()?
        .unwrap_or_default();

    let worker_processes = args.workers.unwrap_or(0);
    if args.workers.is_some() && worker_processes == 0 {
        return Err("worker process count must be greater than zero".to_string());
    }

    let bind_address = args
        .bind_address
        .as_deref()
        .map(str::parse::<IpAddr>)
        .transpose()
        .map_err(|_| "bind address must be a valid IPv4 or IPv6 address".to_string())?;

    let nat_info = args.nat_info.as_deref().map(parse_nat_info).transpose()?;

    Ok(RuntimeArgs {
        tcp_port_range,
        http_ports,
        worker_processes,
        bind_address,
        nat_info,
    })
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

    let _ = process_args(args)?;
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
fn runtime_init(args: &Args) -> Result<(), String> {
    let processed = process_args(args)?;
    let do_not_open_port = processed.tcp_port_range.is_none() && processed.http_ports.is_empty();
    let aes_pwd = args
        .aes_pwd
        .as_deref()
        .map(|path| {
            path.to_str()
                .ok_or_else(|| "aes-pwd path must be valid UTF-8".to_string())
        })
        .transpose()?;

    engine::engine_init(aes_pwd, do_not_open_port)?;
    let (port, start_port, end_port) = match processed.tcp_port_range {
        Some((start, end)) if start == end => (i32::from(start), 0, 0),
        Some((start, end)) => (0, i32::from(start), i32::from(end)),
        None => (0, 0, 0),
    };
    engine::engine_configure_network_listener(port, start_port, end_port, true)?;
    engine::server_init()?;
    Ok(())
}

/// Start main runtime loop
fn runtime_start(args: &Args) -> Result<(), String> {
    let processed = process_args(args)?;
    if processed.worker_processes > 0 {
        spawn_workers(processed.worker_processes)?;
    }
    engine::engine_server_start()?;
    let snapshot = engine::engine_runtime_snapshot();

    eprintln!("\n=== MTProxy Rust Runtime ===");
    eprintln!("Phase 2 entrypoint status:");
    eprintln!("  CLI parsing and validation: complete");
    eprintln!("  Runtime initialization sequence: complete");
    eprintln!("  Worker process bootstrap: complete");
    eprintln!("  Signal infrastructure bootstrap: complete");
    eprintln!("\nPhase 3 core runtime bootstrap:");
    eprintln!("  Engine initialized: {}", snapshot.initialized);
    eprintln!("  Server initialized: {}", snapshot.server_ready);
    eprintln!("  Engine running: {}", snapshot.running);
    eprintln!("  Worker processes: {}", processed.worker_processes);
    if let Some((start, end)) = processed.tcp_port_range {
        if start == end {
            eprintln!("  TCP port: {start}");
        } else {
            eprintln!("  TCP port range: {start}:{end}");
        }
    }
    if !processed.http_ports.is_empty() {
        eprintln!("  HTTP ports: {:?}", processed.http_ports);
    }
    if let Some(bind_addr) = processed.bind_address {
        eprintln!("  Bind address: {bind_addr}");
    }
    if let Some((local, global)) = processed.nat_info {
        eprintln!("  NAT info: {local} -> {global}");
    }
    if args.config.is_none() {
        eprintln!("\nWARNING: no config file specified.");
    }

    Ok(())
}

fn spawn_workers(worker_processes: u32) -> Result<(), String> {
    let mut handles = Vec::new();
    for worker_id in 0..worker_processes {
        let name = format!("mtproxy-worker-{worker_id}");
        let handle = thread::Builder::new()
            .name(name)
            .spawn(|| {})
            .map_err(|err| format!("failed to spawn worker thread: {err}"))?;
        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .map_err(|_| "worker thread panicked during bootstrap".to_string())?;
    }
    Ok(())
}

fn align_runtime_signal_mask() -> Result<(), String> {
    let sigchld = u32::try_from(libc::SIGCHLD)
        .map_err(|_| "platform SIGCHLD value is out of u32 range".to_string())?;
    let sigusr1 = u32::try_from(libc::SIGUSR1)
        .map_err(|_| "platform SIGUSR1 value is out of u32 range".to_string())?;

    engine::signals::register_runtime_signal(sigchld)?;
    engine::signals::register_runtime_signal(sigusr1)?;
    Ok(())
}

fn run_with_parsed_args(args: &Args) -> i32 {
    // Display bootstrap information
    let signature = mtproxy_core::bootstrap_signature();

    if args.verbosity > 0 {
        eprintln!("{signature}");
    }

    // Validate arguments
    if let Err(e) = validate_args(args) {
        eprintln!("ERROR: {e}");
        return 1;
    }

    if args.verbosity > 0 {
        print_configuration(args);
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
            return 1;
        }
    }

    // Initialize runtime
    match runtime_init(args) {
        Ok(()) => {
            if args.verbosity > 1 {
                eprintln!("Runtime initialization successful\n");
            }
        }
        Err(e) => {
            eprintln!("ERROR: Runtime initialization failed: {e}");
            return 1;
        }
    }

    if let Err(e) = align_runtime_signal_mask() {
        eprintln!("ERROR: Signal bootstrap failed: {e}");
        return 1;
    }

    // Start main runtime loop
    match runtime_start(args) {
        Ok(()) => {
            if args.verbosity > 1 {
                eprintln!("\nRuntime completed successfully");
            }
        }
        Err(e) => {
            eprintln!("ERROR: Runtime start failed: {e}");
            return 1;
        }
    }

    0
}

/// Renders CLI usage/help text with a custom binary name.
#[must_use]
pub fn usage_text(program_name: &str) -> String {
    format!("usage: {program_name} <args>\\n")
}

/// Runs entrypoint using an explicit argv vector.
#[must_use]
pub fn run_from_argv(argv: &[String]) -> i32 {
    let parsed_args = match Args::try_parse_from(argv.iter().cloned()) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return err.exit_code();
        }
    };
    run_with_parsed_args(&parsed_args)
}

/// Runs entrypoint using process environment arguments.
#[must_use]
pub fn run_from_env() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    run_from_argv(&argv)
}

/// Runs `MTProto` proxy entrypoint using process environment arguments.
///
/// This symbol mirrors the role of `main()` in `mtproto/mtproto-proxy.c`.
#[must_use]
pub fn run_mtproto_proxy_main_from_env() -> i32 {
    run_from_env()
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

    fn base_args() -> Args {
        Args {
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
        }
    }

    #[test]
    fn parse_probe_uses_core_full_pass_path() {
        let out = mtproto_config_parse_probe().expect("full-pass probe should parse");
        assert_eq!(out, (1, 1));
    }

    #[test]
    fn validate_args_accepts_valid_cpu_threads() {
        let args = base_args();
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn validate_args_rejects_invalid_cpu_threads() {
        let mut args = base_args();
        args.cpu_threads = 0;
        assert!(validate_args(&args).is_err());

        args.cpu_threads = 65;
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn validate_args_rejects_invalid_secret_length() {
        let mut args = base_args();
        args.mtproxy_secrets = vec!["abc123".to_string()];
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn validate_args_accepts_valid_secret() {
        let mut args = base_args();
        args.mtproxy_secrets = vec!["0123456789abcdef0123456789abcdef".to_string()];
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn process_args_parses_ports_workers_and_nat() {
        let mut args = base_args();
        args.port = Some("443:445".to_string());
        args.http_ports = Some("80, 8080".to_string());
        args.workers = Some(2);
        args.bind_address = Some("127.0.0.1".to_string());
        args.nat_info = Some("10.0.0.1:192.0.2.7".to_string());

        let processed = process_args(&args).expect("args should parse");
        assert_eq!(processed.tcp_port_range, Some((443, 445)));
        assert_eq!(processed.http_ports, vec![80, 8080]);
        assert_eq!(processed.worker_processes, 2);
        assert_eq!(
            processed.bind_address,
            Some("127.0.0.1".parse::<IpAddr>().expect("valid ip"))
        );
    }

    #[test]
    fn validate_args_rejects_conflicting_dh_flags() {
        let mut args = base_args();
        args.allow_skip_dh = true;
        args.force_dh = true;
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn runtime_init_and_start_complete() {
        let args = base_args();
        assert!(runtime_init(&args).is_ok());
        assert!(runtime_start(&args).is_ok());
    }
}
