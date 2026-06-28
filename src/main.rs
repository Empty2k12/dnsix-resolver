//! dnsix — an IPv6-only DNS64 forwarder.
//!
//! In short: relay every query to a configured upstream resolver,
//! synthesizing AAAA records (RFC 6147) for IPv4-only names so IPv6-only clients
//! reach IPv4-only hosts via a companion NAT64 translator.

mod blocklist;
mod config;
mod handler;
mod metrics;
mod querylog;
mod synth;
mod upstream;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::handler::Dns64Handler;
use crate::metrics::Metrics;
use crate::querylog::QueryLog;
use crate::synth::Chain;
use crate::upstream::Pool;

/// Timeout for an idle inbound TCP connection.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// TCP listen backlog.
const TCP_BACKLOG: i32 = 1024;

#[derive(Parser)]
#[command(name = "dnsix", about = "IPv6-only DNS64 forwarder")]
struct Args {
    /// Path to the TOML configuration file. Defaults to `config.toml` in the
    /// working directory (the project root under `cargo run`).
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading config file {}", args.config.display()))?;
    let cfg = Config::from_toml(&text).context("parsing configuration")?;

    // Logging is opt-in. `RUST_LOG` wins if set; otherwise the config's `log`
    // directive applies (default `"off"`, i.e. silent). Fatal startup errors are
    // returned from `main` and printed to stderr regardless of this filter.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new(&cfg.log))
                .unwrap_or_else(|_| EnvFilter::new("off")),
        )
        .init();

    // Boot time, for the dashboard: the Prometheus counters are cumulative since
    // this instant, so the UI shows it (and the running uptime) to make them
    // interpretable. `Instant` drives uptime; `SystemTime` gives a wall clock.
    let started = Instant::now();
    let started_wall = SystemTime::now();

    let chain = Arc::new(Chain::build(
        &cfg.synthesizers,
        cfg.nat64_prefix,
        cfg.ttl_cap,
        cfg.nat64_fallback,
    )?);
    let metrics = Arc::new(Metrics::new(&cfg.synthesizers));

    // Start the Prometheus metrics endpoint if configured (best-effort; bind
    // failures are logged inside `serve` and don't abort the server).
    match cfg.metrics_listen {
        Some(addr) => {
            tokio::spawn(metrics::serve(metrics.clone(), addr));
        }
        None => info!("metrics endpoint disabled (set `metrics_listen` to enable)"),
    }

    // The Query log — and thus all per-query capture — exists only when the
    // dashboard is enabled. With `ui_listen` unset, no client IPs or queried
    // names are ever stored.
    let query_log = cfg
        .ui_listen
        .map(|_| Arc::new(QueryLog::new(cfg.query_log_size)));

    info!(upstreams = ?cfg.upstreams, prefix = %cfg.nat64_prefix, cache_size = cfg.cache_size, serve_stale = cfg.serve_stale, synthesizers = ?cfg.synthesizers, "connecting to upstream resolvers");
    let pool = Arc::new(
        Pool::connect(
            &cfg.upstreams,
            cfg.cache_size,
            cfg.serve_stale,
            metrics.clone(),
        )
        .await?,
    );

    // Load the Blocklist (if configured) once, now that the pool exists — the
    // fetch resolves list hosts through it and reaches them over NAT64. Fail-open
    // per source: a list that won't load is skipped, never aborting startup.
    let blocklist = if cfg.blocklists.is_empty() {
        info!("blocklist disabled (set `blocklists` to enable)");
        None
    } else {
        info!(sources = cfg.blocklists.len(), "loading blocklists");
        let bl = blocklist::load(&cfg.blocklists, &pool, cfg.nat64_prefix).await;
        info!(
            blocked = bl.block_count(),
            allowed = bl.allow_count(),
            "blocklist loaded"
        );
        Some(Arc::new(bl))
    };

    // Start the dashboard once the data it shows (query log + blocklist) exists.
    match (cfg.ui_listen, query_log.clone()) {
        (Some(addr), Some(log)) => {
            tokio::spawn(web::serve(
                addr,
                metrics.clone(),
                log,
                blocklist.clone(),
                started,
                started_wall,
            ));
        }
        _ => info!("dashboard disabled (set `ui_listen` to enable)"),
    }

    let handler = Dns64Handler::new(pool, chain, metrics, query_log, blocklist);

    let mut server = hickory_server::ServerFuture::new(handler);
    server
        .register_socket_std(bind_udp_v6only(cfg.listen)?)
        .context("registering UDP socket")?;
    server
        .register_listener_std(bind_tcp_v6only(cfg.listen)?, TCP_IDLE_TIMEOUT)
        .context("registering TCP listener")?;

    info!(listen = %cfg.listen, "dnsix DNS64 forwarder started (IPv6-only)");
    server.block_until_done().await.context("server error")?;
    Ok(())
}

/// Bind an IPv6-only UDP socket. `IPV6_V6ONLY` makes the IPv6-only guarantee hard:
/// the socket will not accept IPv4 clients via IPv4-mapped addresses.
fn bind_udp_v6only(addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding UDP {addr}"))?;
    Ok(socket.into())
}

/// Bind an IPv6-only TCP listener, with the same hard `IPV6_V6ONLY` guarantee.
fn bind_tcp_v6only(addr: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding TCP {addr}"))?;
    socket.listen(TCP_BACKLOG)?;
    Ok(socket.into())
}
