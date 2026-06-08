//! dnsix — an IPv6-only DNS64 forwarder.
//!
//! In short: relay every query to a configured upstream resolver,
//! synthesizing AAAA records (RFC 6147) for IPv4-only names so IPv6-only clients
//! reach IPv4-only hosts via a companion NAT64 translator.

mod config;
mod handler;
mod metrics;
mod synth;
mod upstream;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::handler::Dns64Handler;
use crate::metrics::Metrics;
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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading config file {}", args.config.display()))?;
    let cfg = Config::from_toml(&text).context("parsing configuration")?;

    let chain = Arc::new(Chain::build(&cfg.synthesizers, cfg.nat64_prefix, cfg.ttl_cap)?);
    let metrics = Arc::new(Metrics::new(&cfg.synthesizers));

    // Start the Prometheus metrics endpoint if configured (best-effort; bind
    // failures are logged inside `serve` and don't abort the server).
    match cfg.metrics_listen {
        Some(addr) => {
            tokio::spawn(metrics::serve(metrics.clone(), addr));
        }
        None => info!("metrics endpoint disabled (set `metrics_listen` to enable)"),
    }

    info!(upstreams = ?cfg.upstreams, prefix = %cfg.nat64_prefix, cache_size = cfg.cache_size, synthesizers = ?cfg.synthesizers, "connecting to upstream resolvers");
    let pool = Arc::new(Pool::connect(&cfg.upstreams, cfg.cache_size, metrics.clone()).await?);
    let handler = Dns64Handler::new(pool, chain, metrics);

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
