//! Upstream resolver pool.
//!
//! Each upstream keeps a long-lived UDP and TCP `Client` (both cheaply cloneable
//! and shared across requests). We send over UDP and fall back to TCP on a
//! truncated (TC=1) response, since the client layer does not do this for us.
//! Across upstreams we fail over on connection error or SERVFAIL.
//!
//! In front of the upstreams sits an optional response cache ([`StaleCache`]),
//! which stores positive answers whole (the full answer section, keyed by the
//! single query) rather than per-record, and also caches negative answers
//! (RFC 2308). On top of plain caching it implements two resilience features:
//!
//! * **Serve-stale (RFC 8767):** an expired entry is kept for up to ~1 day past
//!   its TTL. When one is hit we kick off an async refresh and start a short
//!   client-response timer (just under the typical client timeout); if the
//!   refresh wins we serve the fresh answer, otherwise we serve the stale one
//!   with a brief TTL so it self-corrects, and let the refresh finish in the
//!   background. A failing upstream therefore degrades to "slightly stale"
//!   rather than SERVFAIL.
//! * **Prefetch:** a fresh hit in the last tenth of its TTL triggers a background
//!   re-resolve, so a popular name is refreshed before it expires and never
//!   causes a client-facing miss.
//!
//! Both background refreshes share an in-flight guard keyed by the query, so a
//! burst of requests for the same name spawns at most one upstream refresh.
//!
//! Negative caching (RFC 2308) stores NXDOMAIN and NODATA responses keyed the
//! same way, with a TTL of `min(SOA TTL, SOA MINIMUM)` taken from the authority
//! section; a negative response that carries no SOA is not cached. This blunts
//! the flood of doomed lookups (Chrome's random-label probes, ad/tracker noise)
//! that would otherwise hit upstream on every repeat.
//!
//! The cache is deliberately narrow: only queries with the DNSSEC-OK (DO) bit
//! clear are cached, so DNSSEC-aware clients always get an untouched,
//! full-fidelity upstream response.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_util::stream::StreamExt;
use hickory_client::client::Client;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{RData, Record};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::rustls::{client_config, tls_client_connect};
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsHandle, DnsResponse};
use moka::{sync::Cache, Expiry};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::config::Upstream as UpstreamConfig;
use crate::metrics::Metrics;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// How a resolved answer was sourced, for the Query log. Describes a single
/// query's cache disposition; says nothing about any internal sub-lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    /// The query never consulted the cache (caching disabled, or not cacheable —
    /// e.g. a DNSSEC-aware query).
    Uncached,
    /// Cacheable, but not present: answered by an upstream round-trip.
    Miss,
    /// Served from a fresh cache entry.
    Hit,
    /// Served from an expired entry under serve-stale (RFC 8767).
    Stale,
}

impl CacheStatus {
    /// Short lowercase label for display.
    pub fn label(self) -> &'static str {
        match self {
            CacheStatus::Uncached => "uncached",
            CacheStatus::Miss => "miss",
            CacheStatus::Hit => "hit",
            CacheStatus::Stale => "stale",
        }
    }
}

/// Upper bound a cached TTL is clamped to (one day), matching common forwarder
/// behaviour and RFC 2181 §8 guidance that implementations may cap received TTLs.
const MAX_TTL: u32 = 86_400;

/// Upper bound on a negative-cache TTL. RFC 2308 §5 caps negative answers well
/// below positive ones; one hour keeps a name that starts existing from being
/// denied for too long while still absorbing repeated doomed lookups.
const NEG_MAX_TTL: u32 = 3_600;

/// RFC 8767 client-response timer: once a refresh of an expired entry has not
/// returned within this window we answer with the stale data. Kept just under the
/// typical ~2s client timeout so a healthy upstream still produces a fresh answer.
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1800);

/// TTL stamped on a stale answer (RFC 8767 §4): short, so the client re-queries
/// soon and the answer self-corrects once upstream is healthy again.
const STALE_SERVE_TTL: u32 = 30;

/// How long a record may be served past its TTL (RFC 8767 recommends ~1 day).
const STALE_MAX_WINDOW: Duration = Duration::from_secs(86_400);

/// Prefetch trigger point: a fresh hit whose remaining TTL has fallen to this
/// fraction of its original TTL kicks off a background refresh (Unbound uses the
/// same last-10% heuristic).
const PREFETCH_FRACTION: f64 = 0.10;

/// A live set of clients for one upstream. `Plain` keeps a UDP and a TCP client
/// and uses UDP with a TCP fallback on truncation; `Tls` (DNS-over-TLS, RFC 7858)
/// keeps a single TLS-over-TCP client — TLS rides TCP, so it never truncates.
///
/// Every variant is connection-oriented underneath (even UDP is a long-lived
/// `Client` driven by a background task), so a dead connection means the whole
/// `Conn` is discarded and re-dialed by its owning [`Upstream`].
enum Conn {
    Plain { udp: Client, tcp: Client },
    Tls { client: Client },
}

/// Establishes a fresh [`Connection`] for one upstream on demand. Abstracted so
/// the reconnect logic in [`Upstream`] can be driven by a fake in tests without
/// touching the network.
#[async_trait::async_trait]
trait Dialer: Send + Sync {
    async fn dial(&self) -> anyhow::Result<Arc<dyn Connection>>;
}

/// A live connection that can resolve queries. Real connections are hickory
/// `Client`s ([`Conn`]); tests substitute a controllable fake.
#[async_trait::async_trait]
trait Connection: Send + Sync {
    async fn resolve(&self, query: Message) -> anyhow::Result<DnsResponse>;
}

/// The production dialer: (re)connects a [`Conn`] from its config.
struct NetworkDialer {
    cfg: UpstreamConfig,
}

#[async_trait::async_trait]
impl Dialer for NetworkDialer {
    async fn dial(&self) -> anyhow::Result<Arc<dyn Connection>> {
        Ok(Arc::new(Conn::connect(&self.cfg).await?))
    }
}

#[async_trait::async_trait]
impl Connection for Conn {
    async fn resolve(&self, query: Message) -> anyhow::Result<DnsResponse> {
        Conn::resolve(self, query).await
    }
}

impl Conn {
    async fn connect(cfg: &UpstreamConfig) -> anyhow::Result<Self> {
        match cfg {
            UpstreamConfig::Plain(addr) => Self::connect_plain(*addr).await,
            UpstreamConfig::Tls { addr, dns_name } => Self::connect_tls(*addr, dns_name).await,
        }
    }

    async fn connect_plain(addr: SocketAddr) -> anyhow::Result<Self> {
        let provider = TokioRuntimeProvider::new();

        // UDP: the stream is itself a DnsRequestSender, so Client::connect drives it.
        let udp_connect = UdpClientStream::builder(addr, provider.clone())
            .with_timeout(Some(UPSTREAM_TIMEOUT))
            .build();
        let (udp, udp_bg) = Client::connect(udp_connect)
            .await
            .with_context(|| format!("connecting UDP client to upstream {addr}"))?;
        tokio::spawn(udp_bg);

        // TCP: a connect future + a stream handle, wrapped in a multiplexer by Client::new.
        let (tcp_future, tcp_handle) =
            TcpClientStream::new(addr, None, Some(UPSTREAM_TIMEOUT), provider);
        let (tcp, tcp_bg) = Client::new(tcp_future, tcp_handle, None)
            .await
            .with_context(|| format!("connecting TCP client to upstream {addr}"))?;
        tokio::spawn(tcp_bg);

        Ok(Self::Plain { udp, tcp })
    }

    /// Connect a DNS-over-TLS (RFC 7858) upstream. `dns_name` is validated against
    /// the server certificate and sent as SNI; roots come from the bundled
    /// webpki-roots store, so trust is independent of the host's system store. The
    /// TLS stream plugs into `Client::new` exactly like the plain TCP path.
    async fn connect_tls(addr: SocketAddr, dns_name: &str) -> anyhow::Result<Self> {
        let provider = TokioRuntimeProvider::new();
        let (tls_future, tls_handle) = tls_client_connect(
            addr,
            dns_name.to_string(),
            Arc::new(client_config()),
            provider,
        );
        let (client, bg) = Client::new(tls_future, tls_handle, None)
            .await
            .with_context(|| format!("connecting DoT client to upstream {addr} ({dns_name})"))?;
        tokio::spawn(bg);

        Ok(Self::Tls { client })
    }

    /// Resolve `query`: over UDP with a TCP retry on truncation for a plain
    /// upstream, or over the single TLS client for a DoT upstream.
    async fn resolve(&self, query: Message) -> anyhow::Result<DnsResponse> {
        match self {
            Conn::Plain { udp, tcp } => {
                let resp = send_once(udp, query.clone()).await.context("UDP query")?;
                if resp.truncated() {
                    send_once(tcp, query).await.context("TCP retry")
                } else {
                    Ok(resp)
                }
            }
            Conn::Tls { client } => send_once(client, query).await.context("DoT query"),
        }
    }
}

/// A single upstream resolver that transparently reconnects. The underlying
/// clients are all connection-oriented and long-lived; DoT and TCP connections
/// in particular get closed by an idle upstream (Cloudflare and Quad9 both do
/// this aggressively). hickory's `Client` does not redial — once the connection
/// dies, the background multiplexer task ends and every later send fails with
/// `Busy` ("resource too busy") or a disconnected-stream error. Without
/// reconnection that turns a routine idle-close into a permanent SERVFAIL for
/// every query until the process restarts.
///
/// So the live [`Conn`] sits behind a lazily-(re)established cell: on any send
/// error we drop the dead connection and redial once, healing a server-side
/// close on the very next query.
struct Upstream {
    dialer: Arc<dyn Dialer>,
    addr: SocketAddr,
    /// `(generation, conn)`; `None` before first use and after a failure. The
    /// async mutex serializes (re)connects, so a burst of concurrent failures
    /// triggers a single redial rather than a thundering herd.
    cell: AsyncMutex<Option<(u64, Arc<dyn Connection>)>>,
    gen: AtomicU64,
}

impl Upstream {
    fn new(cfg: &UpstreamConfig) -> Self {
        let addr = match cfg {
            UpstreamConfig::Plain(addr) => *addr,
            UpstreamConfig::Tls { addr, .. } => *addr,
        };
        Self::with_dialer(addr, Arc::new(NetworkDialer { cfg: cfg.clone() }))
    }

    fn with_dialer(addr: SocketAddr, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            dialer,
            addr,
            cell: AsyncMutex::new(None),
            gen: AtomicU64::new(0),
        }
    }

    /// Build an upstream and dial it once, so a wholly unreachable or
    /// misconfigured upstream still fails fast at startup.
    async fn connect(cfg: &UpstreamConfig) -> anyhow::Result<Self> {
        let upstream = Self::new(cfg);
        upstream.acquire().await?;
        Ok(upstream)
    }

    /// The socket address of this upstream, for logging.
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Return the live connection, dialing one if the cell is empty.
    async fn acquire(&self) -> anyhow::Result<(u64, Arc<dyn Connection>)> {
        let mut cell = self.cell.lock().await;
        if let Some((g, conn)) = cell.as_ref() {
            return Ok((*g, Arc::clone(conn)));
        }
        let conn = self.dialer.dial().await?;
        let g = self.gen.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        *cell = Some((g, Arc::clone(&conn)));
        Ok((g, conn))
    }

    /// Drop the cached connection if it is still generation `g`, so the next
    /// `acquire` redials. A connection already replaced by a concurrent
    /// reconnect (newer `g`) is left intact.
    async fn invalidate(&self, g: u64) {
        let mut cell = self.cell.lock().await;
        if matches!(cell.as_ref(), Some((cg, _)) if *cg == g) {
            *cell = None;
        }
    }

    /// Resolve `query`, reconnecting once if the live connection has died.
    async fn resolve(&self, query: Message) -> anyhow::Result<DnsResponse> {
        let mut last_err = None;
        for _ in 0..2 {
            let (g, conn) = self.acquire().await?;
            match conn.resolve(query.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    self.invalidate(g).await;
                    last_err = Some(err);
                }
            }
        }
        Err(last_err
            .expect("loop runs at least once")
            .context(format!("upstream {} failed after reconnect", self.addr)))
    }
}

async fn send_once(client: &Client, query: Message) -> anyhow::Result<DnsResponse> {
    let mut responses = client.send(query);
    match responses.next().await {
        Some(result) => result.map_err(Into::into),
        None => anyhow::bail!("upstream closed the stream without a response"),
    }
}

/// The upstream-resolution step, behind a trait so tests can substitute a
/// controllable in-process resolver for the real network clients. A `None` return
/// means every upstream failed.
#[async_trait::async_trait]
trait Resolver: Send + Sync {
    async fn resolve(&self, query: Message) -> Option<DnsResponse>;
}

/// The production resolver: an ordered set of network upstreams with failover.
struct UpstreamSet {
    upstreams: Vec<Upstream>,
}

#[async_trait::async_trait]
impl Resolver for UpstreamSet {
    /// Try each upstream in turn. An upstream is considered failed (move to the
    /// next) on transport error or SERVFAIL; any other response — including
    /// NXDOMAIN and NODATA — is authoritative and returned. `None` if all failed.
    async fn resolve(&self, query: Message) -> Option<DnsResponse> {
        for upstream in &self.upstreams {
            match upstream.resolve(query.clone()).await {
                Ok(resp) if resp.response_code() == ResponseCode::ServFail => {
                    tracing::warn!(upstream = %upstream.addr(), "upstream returned SERVFAIL, failing over");
                }
                Ok(resp) => return Some(resp),
                Err(err) => {
                    tracing::warn!(upstream = %upstream.addr(), error = %format!("{err:#}"), "upstream query failed, failing over");
                }
            }
        }
        None
    }
}

/// Shared, `'static` state behind the pool. Held in an `Arc` so a background
/// refresh task can clone what it needs (the resolver and the `Arc`-backed moka
/// `Cache` are both cheap to share) without borrowing the request's `&self`.
struct Inner {
    resolver: Arc<dyn Resolver>,
    /// `None` when caching is disabled (`cache_size = 0`).
    cache: Option<StaleCache>,
    metrics: Arc<Metrics>,
    /// Queries with a refresh (serve-stale or prefetch) currently in flight, so we
    /// never run more than one upstream refresh for the same name at a time.
    in_flight: Mutex<HashSet<Query>>,
}

impl Inner {
    /// Claim the refresh slot for `question`. Returns a guard (which frees the slot
    /// on drop, even on panic) if no refresh was already running, else `None`.
    fn try_claim_refresh(self: &Arc<Self>, question: Query) -> Option<RefreshGuard> {
        if self.in_flight.lock().unwrap().insert(question.clone()) {
            Some(RefreshGuard {
                inner: Arc::clone(self),
                question,
            })
        } else {
            None
        }
    }
}

/// Frees a query's in-flight refresh slot when dropped.
struct RefreshGuard {
    inner: Arc<Inner>,
    question: Query,
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.inner.in_flight.lock().unwrap().remove(&self.question);
    }
}

/// An ordered pool of upstreams with failover, fronted by an optional cache.
/// Cheaply cloneable: it is a thin handle over the shared [`Inner`].
pub struct Pool {
    inner: Arc<Inner>,
}

impl Pool {
    pub async fn connect(
        configs: &[UpstreamConfig],
        cache_size: usize,
        serve_stale: bool,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let mut upstreams = Vec::with_capacity(configs.len());
        for cfg in configs {
            upstreams.push(Upstream::connect(cfg).await?);
        }
        Ok(Self::from_parts(
            Arc::new(UpstreamSet { upstreams }),
            cache_size,
            serve_stale,
            metrics,
        ))
    }

    /// Assemble a pool from an already-built resolver. Shared by `connect` and the
    /// test harness, which injects a mock resolver.
    fn from_parts(
        resolver: Arc<dyn Resolver>,
        cache_size: usize,
        serve_stale: bool,
        metrics: Arc<Metrics>,
    ) -> Self {
        // With serve-stale off the stale window is zero, so an expired entry is
        // never served and moka evicts it at its TTL — i.e. plain caching.
        let stale_window = if serve_stale {
            STALE_MAX_WINDOW
        } else {
            Duration::ZERO
        };
        let cache = (cache_size > 0).then(|| StaleCache::new(cache_size, stale_window));
        Self {
            inner: Arc::new(Inner {
                resolver,
                cache,
                metrics,
                in_flight: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// Resolve a query, serving from cache when possible and otherwise querying
    /// upstream. Returns `None` only if every upstream failed and no stale answer
    /// was available.
    pub async fn resolve(&self, query: Message) -> Option<DnsResponse> {
        self.resolve_observed(query).await.0
    }

    /// Like [`resolve`](Self::resolve), but also reports how the answer was
    /// sourced (cache hit / stale / miss / uncached) for the Query log. The
    /// status describes *this* query's cache disposition only.
    pub async fn resolve_observed(&self, query: Message) -> (Option<DnsResponse>, CacheStatus) {
        let inner = &self.inner;
        // Only cacheable queries get a key; everything else bypasses the cache.
        let key = inner
            .cache
            .as_ref()
            .and_then(|_| cacheable_question(&query));

        if let (Some(cache), Some(question)) = (&inner.cache, &key) {
            match cache.get(question, Instant::now()) {
                Some(CacheLookup::Fresh { response, prefetch }) => {
                    let negative = response.negative;
                    if let Some(resp) = build_cached_response(question, response) {
                        tracing::debug!(name = %question.name(), qtype = %question.query_type(), negative, "cache hit");
                        inner.metrics.inc_cache_hit();
                        if negative {
                            inner.metrics.inc_negative_cache_hit();
                        }
                        // Popular name nearing expiry: refresh it before it lapses.
                        if prefetch && self.spawn_refresh(query, question.clone()).is_some() {
                            inner.metrics.inc_prefetch();
                        }
                        return (Some(resp), CacheStatus::Hit);
                    }
                }
                Some(CacheLookup::Stale(response)) => {
                    let negative = response.negative;
                    if let Some(stale) = build_cached_response(question, response) {
                        if negative {
                            inner.metrics.inc_negative_cache_hit();
                        }
                        let resp = self.serve_stale(query, question.clone(), stale).await;
                        return (Some(resp), CacheStatus::Stale);
                    }
                }
                None => inner.metrics.inc_cache_miss(),
            }
        }

        // A miss when the query was cacheable (and a cache exists); otherwise the
        // query never touched the cache at all.
        let status = if key.is_some() {
            CacheStatus::Miss
        } else {
            CacheStatus::Uncached
        };
        (self.resolve_and_cache(query).await, status)
    }

    /// Query upstream and, on a positive answer, store it in the cache. Returns the
    /// response, or `None` (incrementing the failure counter) if every upstream failed.
    async fn resolve_and_cache(&self, query: Message) -> Option<DnsResponse> {
        let inner = &self.inner;
        let key = inner
            .cache
            .as_ref()
            .and_then(|_| cacheable_question(&query));

        let resp = match inner.resolver.resolve(query).await {
            Some(resp) => resp,
            None => {
                inner.metrics.inc_upstream_failed();
                return None;
            }
        };

        // Cache positive answers whole, and negative answers (RFC 2308) keyed on
        // the SOA in the authority section. A negative response with no SOA — or
        // any other RCODE (SERVFAIL etc.) — is passed through uncached.
        if let (Some(cache), Some(question)) = (&inner.cache, &key) {
            let rcode = resp.response_code();
            let now = Instant::now();
            if rcode == ResponseCode::NoError && !resp.answers().is_empty() {
                cache.insert(question.clone(), resp.answers().to_vec(), now);
            } else if rcode == ResponseCode::NXDomain
                || (rcode == ResponseCode::NoError && resp.answers().is_empty())
            {
                let soa = negative_soa(&resp);
                if !soa.is_empty() {
                    cache.insert_negative(question.clone(), rcode, soa, now);
                }
            }
        }
        Some(resp)
    }

    /// Serve-stale (RFC 8767): we hold a `stale` answer ready. Kick off a refresh
    /// and wait up to the client-response timeout; if the refresh produces a fresh
    /// answer in time, return it, otherwise return the stale answer and let the
    /// refresh finish in the background. If a refresh is already in flight for this
    /// name we don't pile on — we just serve stale immediately.
    async fn serve_stale(
        &self,
        query: Message,
        question: Query,
        stale: DnsResponse,
    ) -> DnsResponse {
        let Some(mut refresh) = self.spawn_refresh(query, question.clone()) else {
            // A refresh is already in flight; don't pile on, just serve stale.
            self.serving_stale(&question);
            return stale;
        };
        match tokio::time::timeout(CLIENT_RESPONSE_TIMEOUT, &mut refresh).await {
            // Refresh won the race with a fresh answer.
            Ok(Ok(Some(fresh))) => fresh,
            // Refresh failed or panicked: the stale answer is our resilience backstop.
            Ok(Ok(None)) | Ok(Err(_)) => {
                self.serving_stale(&question);
                stale
            }
            // Timer fired first: serve stale now. Dropping the handle detaches the
            // task, which keeps running and repopulates the cache when it completes.
            Err(_) => {
                self.serving_stale(&question);
                stale
            }
        }
    }

    /// Note (log + count) that we are answering `question` from expired cache.
    fn serving_stale(&self, question: &Query) {
        tracing::debug!(name = %question.name(), qtype = %question.query_type(), "serving stale");
        self.inner.metrics.inc_served_stale();
    }

    /// Spawn a background refresh of `question` unless one is already in flight.
    /// The returned handle resolves to the refreshed response (or `None` on upstream
    /// failure); dropping it detaches the task without cancelling it.
    fn spawn_refresh(
        &self,
        query: Message,
        question: Query,
    ) -> Option<JoinHandle<Option<DnsResponse>>> {
        let guard = self.inner.try_claim_refresh(question)?;
        let inner = Arc::clone(&self.inner);
        Some(tokio::spawn(async move {
            // Held for the task's lifetime; frees the in-flight slot on completion
            // or panic.
            let _guard = guard;
            let pool = Pool { inner };
            pool.resolve_and_cache(query).await
        }))
    }
}

/// The cache key for a query, or `None` if it must not be cached: we cache only
/// single-question queries with the DNSSEC-OK (DO) bit clear, so DNSSEC-aware
/// clients always receive a full-fidelity upstream answer rather than one
/// reassembled from cache (which drops RRSIGs and the AD bit).
fn cacheable_question(query: &Message) -> Option<Query> {
    let dnssec_ok = query
        .extensions()
        .as_ref()
        .map(|e| e.flags().dnssec_ok)
        .unwrap_or(false);
    if dnssec_ok {
        return None;
    }
    match query.queries() {
        [question] => Some(question.clone()),
        _ => None,
    }
}

/// Rebuild a response message from a cached entry: the answer section for a
/// positive hit, or the RCODE plus authority SOA for a negative one (RFC 2308).
/// Returns `None` for an entry that carries neither (which is never stored).
fn build_cached_response(question: &Query, response: CachedResponse) -> Option<DnsResponse> {
    if response.answers.is_empty() && response.authority.is_empty() {
        return None;
    }
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(response.response_code)
        .set_recursion_available(true)
        .add_query(question.clone())
        .add_answers(response.answers)
        .add_name_servers(response.authority);
    DnsResponse::from_message(message).ok()
}

/// A response cache that retains expired answers for a stale window (RFC 8767).
///
/// Positive answers are stored whole — the entire answer section (including any
/// CNAME chain, in upstream order) under the single query key — so a hit is
/// served verbatim with no per-record reassembly. The min TTL across the answer
/// set (clamped to [`MAX_TTL`]) is the entry's freshness deadline.
///
/// Negative answers (RFC 2308) store the response's RCODE and the authority-
/// section SOA instead, with a freshness deadline of `min(SOA TTL, SOA MINIMUM)`
/// clamped to [`NEG_MAX_TTL`]. Serve-stale and prefetch apply to both kinds.
struct StaleCache {
    cache: Cache<Query, Arc<CacheEntry>>,
    /// How long past its deadline an entry may still be served stale.
    stale_window: Duration,
}

struct CacheEntry {
    /// Positive answer section; empty for a negative entry.
    answers: Vec<Record>,
    /// Authority SOA proving a negative answer (RFC 2308); empty for a positive.
    authority: Vec<Record>,
    /// RCODE to rebuild: `NoError` for a positive answer or a NODATA negative,
    /// `NXDomain` for a name-error negative.
    response_code: ResponseCode,
    /// When the entry was stored (used to recover the original TTL for prefetch).
    fetched_at: Instant,
    /// Freshness deadline: `fetched_at + min(TTLs, cap)`.
    valid_until: Instant,
}

impl CacheEntry {
    /// Snapshot the entry as a rebuildable response, stamping every record (answer
    /// and authority) with `ttl`.
    fn to_response(&self, ttl: u32) -> CachedResponse {
        CachedResponse {
            response_code: self.response_code,
            negative: self.answers.is_empty(),
            answers: stamp_ttl(&self.answers, ttl),
            authority: stamp_ttl(&self.authority, ttl),
        }
    }
}

/// A cache entry rendered back into the pieces needed to rebuild a response.
struct CachedResponse {
    response_code: ResponseCode,
    /// True for a negative (NXDOMAIN/NODATA) entry, for hit accounting.
    negative: bool,
    answers: Vec<Record>,
    authority: Vec<Record>,
}

/// The outcome of a cache lookup for a present entry.
enum CacheLookup {
    /// Still within TTL. `prefetch` is set when it has entered the last
    /// [`PREFETCH_FRACTION`] of its life and should be refreshed proactively.
    Fresh {
        response: CachedResponse,
        prefetch: bool,
    },
    /// Expired but within the stale window.
    Stale(CachedResponse),
}

impl StaleCache {
    fn new(capacity: usize, stale_window: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity as u64)
            .expire_after(StaleExpiry { stale_window })
            .build();
        Self {
            cache,
            stale_window,
        }
    }

    /// Cache a positive answer, with a deadline of `min(answer TTLs, MAX_TTL)`.
    fn insert(&self, question: Query, answers: Vec<Record>, now: Instant) {
        let ttl = answers
            .iter()
            .map(Record::ttl)
            .min()
            .unwrap_or(0)
            .min(MAX_TTL);
        self.store(
            question,
            CacheEntry {
                answers,
                authority: Vec::new(),
                response_code: ResponseCode::NoError,
                fetched_at: now,
                valid_until: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// Cache a negative answer (RFC 2308). `soa` is the authority-section SOA;
    /// the deadline is `min(SOA TTL, SOA MINIMUM)` over those records, clamped to
    /// [`NEG_MAX_TTL`]. Callers must not pass an empty `soa`.
    fn insert_negative(
        &self,
        question: Query,
        response_code: ResponseCode,
        soa: Vec<Record>,
        now: Instant,
    ) {
        let ttl = soa
            .iter()
            .filter_map(|r| match r.data() {
                RData::SOA(s) => Some(r.ttl().min(s.minimum())),
                _ => None,
            })
            .min()
            .unwrap_or(0)
            .min(NEG_MAX_TTL);
        self.store(
            question,
            CacheEntry {
                answers: Vec::new(),
                authority: soa,
                response_code,
                fetched_at: now,
                valid_until: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    fn store(&self, question: Query, entry: CacheEntry) {
        self.cache.insert(question, Arc::new(entry));
    }

    fn get(&self, question: &Query, now: Instant) -> Option<CacheLookup> {
        let entry = self.cache.get(question)?;
        if now <= entry.valid_until {
            let remaining = entry.valid_until.saturating_duration_since(now);
            let total = entry
                .valid_until
                .saturating_duration_since(entry.fetched_at);
            // Prefetch once we are within the last fraction of the (non-zero) TTL.
            let prefetch = !total.is_zero()
                && remaining.as_secs_f64() <= total.as_secs_f64() * PREFETCH_FRACTION;
            Some(CacheLookup::Fresh {
                response: entry.to_response(remaining.as_secs() as u32),
                prefetch,
            })
        } else if now <= entry.valid_until + self.stale_window {
            Some(CacheLookup::Stale(entry.to_response(STALE_SERVE_TTL)))
        } else {
            None
        }
    }
}

/// Extract the authority-section SOA record(s) from a negative response, used as
/// the RFC 2308 proof and TTL source. Empty when the response carries no SOA, in
/// which case the negative answer is not cached.
fn negative_soa(resp: &DnsResponse) -> Vec<Record> {
    resp.name_servers()
        .iter()
        .filter(|r| matches!(r.data(), RData::SOA(_)))
        .cloned()
        .collect()
}

/// Clone `answers`, stamping every record with `ttl` (a single collapsed TTL, as
/// the record cache does for an answer set).
fn stamp_ttl(answers: &[Record], ttl: u32) -> Vec<Record> {
    answers
        .iter()
        .map(|r| {
            let mut r = r.clone();
            r.set_ttl(ttl);
            r
        })
        .collect()
}

/// moka expiry policy: keep an entry until `stale_window` past its TTL deadline so
/// expired answers remain available to serve stale. With a zero window this
/// collapses to evicting exactly at the TTL (plain caching).
struct StaleExpiry {
    stale_window: Duration,
}

impl Expiry<Query, Arc<CacheEntry>> for StaleExpiry {
    fn expire_after_create(
        &self,
        _key: &Query,
        value: &Arc<CacheEntry>,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.valid_until.saturating_duration_since(created_at) + self.stale_window)
    }

    fn expire_after_update(
        &self,
        _key: &Query,
        value: &Arc<CacheEntry>,
        updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.valid_until.saturating_duration_since(updated_at) + self.stale_window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_util::future::join_all;
    use hickory_proto::op::{Edns, MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

    use crate::metrics::Metrics;

    fn a_query(name: &str) -> Query {
        let mut q = Query::query(Name::from_str(name).unwrap(), RecordType::A);
        q.set_query_class(DNSClass::IN);
        q
    }

    fn a_record(name: &str, ip: [u8; 4], ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::from(ip))),
        )
    }

    /// An SOA record at `zone` with the given record TTL and MINIMUM field, as a
    /// negative answer's authority section would carry.
    fn soa_record(zone: &str, ttl: u32, minimum: u32) -> Record {
        let name = Name::from_str(zone).unwrap();
        let soa = SOA::new(name.clone(), name.clone(), 1, 3600, 600, 86400, minimum);
        Record::from_rdata(name, ttl, RData::SOA(soa))
    }

    fn first_ip(records: &[Record]) -> Ipv4Addr {
        match records[0].data() {
            RData::A(A(ip)) => *ip,
            other => panic!("expected A record, got {other:?}"),
        }
    }

    #[test]
    fn fresh_hit_round_trips() {
        let cache = StaleCache::new(64, STALE_MAX_WINDOW);
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert(
            q.clone(),
            vec![a_record("example.com.", [93, 1, 2, 3], 300)],
            now,
        );

        match cache.get(&q, now) {
            Some(CacheLookup::Fresh { response, prefetch }) => {
                assert_eq!(first_ip(&response.answers), Ipv4Addr::new(93, 1, 2, 3));
                assert!(!prefetch, "a just-stored entry is not yet due for prefetch");
            }
            other => panic!("expected a fresh hit, got {:?}", other.is_some()),
        }
    }

    /// A fresh hit carries the record's *remaining* TTL, not its original.
    #[test]
    fn fresh_hit_decrements_ttl() {
        let cache = StaleCache::new(64, STALE_MAX_WINDOW);
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert(
            q.clone(),
            vec![a_record("example.com.", [93, 1, 2, 3], 300)],
            now,
        );

        match cache.get(&q, now + Duration::from_secs(100)) {
            Some(CacheLookup::Fresh { response, .. }) => {
                assert!(
                    response.answers[0].ttl() <= 200,
                    "ttl should have decayed, got {}",
                    response.answers[0].ttl()
                );
            }
            _ => panic!("expected a fresh hit"),
        }
    }

    /// Entering the last 10% of the TTL flags the entry for prefetch.
    #[test]
    fn fresh_hit_flags_prefetch_near_expiry() {
        let cache = StaleCache::new(64, STALE_MAX_WINDOW);
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert(
            q.clone(),
            vec![a_record("example.com.", [93, 1, 2, 3], 100)],
            now,
        );

        // 80% through: not yet due.
        match cache.get(&q, now + Duration::from_secs(80)) {
            Some(CacheLookup::Fresh { prefetch, .. }) => assert!(!prefetch),
            _ => panic!("expected a fresh hit"),
        }
        // 95% through: into the last 10%, so due.
        match cache.get(&q, now + Duration::from_secs(95)) {
            Some(CacheLookup::Fresh { prefetch, .. }) => assert!(prefetch),
            _ => panic!("expected a fresh hit"),
        }
    }

    #[test]
    fn expired_within_window_is_stale() {
        let cache = StaleCache::new(64, STALE_MAX_WINDOW);
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert(
            q.clone(),
            vec![a_record("example.com.", [93, 1, 2, 3], 5)],
            now,
        );

        match cache.get(&q, now + Duration::from_secs(10)) {
            Some(CacheLookup::Stale(response)) => {
                assert_eq!(first_ip(&response.answers), Ipv4Addr::new(93, 1, 2, 3));
                // Stale answers are stamped with the short self-correcting TTL.
                assert_eq!(response.answers[0].ttl(), STALE_SERVE_TTL);
            }
            _ => panic!("expected a stale hit"),
        }
    }

    #[test]
    fn stale_beyond_window_is_a_miss() {
        let cache = StaleCache::new(64, Duration::from_secs(60));
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert(
            q.clone(),
            vec![a_record("example.com.", [93, 1, 2, 3], 5)],
            now,
        );

        // 5s TTL + 60s window = served until 65s; 100s is past that.
        assert!(cache.get(&q, now + Duration::from_secs(100)).is_none());
    }

    /// With serve-stale disabled (zero window), an expired entry is a plain miss.
    #[test]
    fn disabled_serve_stale_expires_at_ttl() {
        let cache = StaleCache::new(64, Duration::ZERO);
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert(
            q.clone(),
            vec![a_record("example.com.", [93, 1, 2, 3], 5)],
            now,
        );

        assert!(matches!(
            cache.get(&q, now),
            Some(CacheLookup::Fresh { .. })
        ));
        assert!(cache.get(&q, now + Duration::from_secs(10)).is_none());
    }

    /// A negative entry round-trips with its RCODE and the authority SOA.
    #[test]
    fn negative_entry_round_trips_rcode_and_soa() {
        let cache = StaleCache::new(64, STALE_MAX_WINDOW);
        let q = a_query("nope.example.com.");
        let now = Instant::now();
        cache.insert_negative(
            q.clone(),
            ResponseCode::NXDomain,
            vec![soa_record("example.com.", 300, 60)],
            now,
        );

        match cache.get(&q, now) {
            Some(CacheLookup::Fresh { response, .. }) => {
                assert!(response.negative);
                assert!(response.answers.is_empty());
                assert_eq!(response.response_code, ResponseCode::NXDomain);
                assert!(matches!(response.authority[0].data(), RData::SOA(_)));
            }
            _ => panic!("expected a fresh negative hit"),
        }
    }

    /// The negative TTL is `min(SOA TTL, SOA MINIMUM)` (RFC 2308 §5).
    #[test]
    fn negative_ttl_is_min_of_soa_ttl_and_minimum() {
        let cache = StaleCache::new(64, Duration::ZERO);
        let q = a_query("nope.example.com.");
        let now = Instant::now();
        // SOA TTL 300, MINIMUM 60 -> the entry expires after 60s.
        cache.insert_negative(
            q.clone(),
            ResponseCode::NXDomain,
            vec![soa_record("example.com.", 300, 60)],
            now,
        );

        assert!(matches!(
            cache.get(&q, now + Duration::from_secs(59)),
            Some(CacheLookup::Fresh { .. })
        ));
        assert!(cache.get(&q, now + Duration::from_secs(61)).is_none());
    }

    /// A negative TTL is clamped to [`NEG_MAX_TTL`] even when the SOA asks for more.
    #[test]
    fn negative_ttl_is_clamped() {
        let cache = StaleCache::new(64, Duration::ZERO);
        let q = a_query("nope.example.com.");
        let now = Instant::now();
        cache.insert_negative(
            q.clone(),
            ResponseCode::NXDomain,
            vec![soa_record("example.com.", 100_000, 100_000)],
            now,
        );

        assert!(cache
            .get(&q, now + Duration::from_secs(u64::from(NEG_MAX_TTL) + 1))
            .is_none());
    }

    /// `negative_soa` returns only the SOA records, and nothing when there is none.
    #[test]
    fn negative_soa_extracts_only_soa() {
        let mut with_soa = Message::new();
        with_soa.add_name_server(soa_record("example.com.", 300, 60));
        with_soa.add_name_server(a_record("ns.example.com.", [1, 2, 3, 4], 300));
        let with_soa = DnsResponse::from_message(with_soa).unwrap();
        let soa = negative_soa(&with_soa);
        assert_eq!(soa.len(), 1);
        assert!(matches!(soa[0].data(), RData::SOA(_)));

        let without = DnsResponse::from_message(Message::new()).unwrap();
        assert!(negative_soa(&without).is_empty());
    }

    fn message_with(queries: &[Query], dnssec_ok: bool) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query);
        for q in queries {
            msg.add_query(q.clone());
        }
        let mut edns = Edns::new();
        edns.set_dnssec_ok(dnssec_ok);
        msg.set_edns(edns);
        msg
    }

    #[test]
    fn dnssec_aware_queries_are_not_cached() {
        let msg = message_with(&[a_query("example.com.")], true);
        assert!(cacheable_question(&msg).is_none());
    }

    #[test]
    fn plain_single_question_is_cacheable() {
        let msg = message_with(&[a_query("example.com.")], false);
        assert!(cacheable_question(&msg).is_some());
    }

    #[test]
    fn multi_question_is_not_cached() {
        let msg = message_with(&[a_query("a.example."), a_query("b.example.")], false);
        assert!(cacheable_question(&msg).is_none());
    }

    // --- End-to-end orchestration of `Pool::resolve` over a mock upstream. ---

    /// A controllable in-process resolver: counts how many upstream queries it
    /// receives, optionally sleeps `delay` (in tokio time, so virtual-clock tests
    /// drive the serve-stale race deterministically), and returns either a single
    /// A record or `None` (every upstream down).
    struct MockResolver {
        calls: AtomicUsize,
        delay: Duration,
        response: Option<(Ipv4Addr, u32)>,
    }

    impl MockResolver {
        fn new(response: Option<(Ipv4Addr, u32)>, delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                delay,
                response,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl Resolver for MockResolver {
        async fn resolve(&self, query: Message) -> Option<DnsResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            let (ip, ttl) = self.response?;
            let question = query.queries().first()?.clone();
            let record = Record::from_rdata(question.name().clone(), ttl, RData::A(A(ip)));
            let mut msg = Message::new();
            msg.set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_response_code(ResponseCode::NoError)
                .add_query(question)
                .add_answer(record);
            DnsResponse::from_message(msg).ok()
        }
    }

    fn query_msg(name: &str) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .add_query(a_query(name));
        msg
    }

    fn pool_with(resolver: Arc<dyn Resolver>, serve_stale: bool, metrics: Arc<Metrics>) -> Pool {
        Pool::from_parts(resolver, 64, serve_stale, metrics)
    }

    // --- Upstream reconnection (regression for the DoT-default outage: an idle
    //     connection closed by the upstream made every later send fail with
    //     `Busy`, so the upstream SERVFAILed forever instead of redialing). ---

    /// A connection that answers `remaining` queries and then fails every later
    /// one — exactly how a hickory `Client` behaves once its connection is closed
    /// (`Busy` / disconnected-stream on every send).
    struct FlakyConn {
        remaining: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Connection for FlakyConn {
        async fn resolve(&self, query: Message) -> anyhow::Result<DnsResponse> {
            if self.remaining.load(Ordering::SeqCst) == 0 {
                anyhow::bail!("resource too busy");
            }
            self.remaining.fetch_sub(1, Ordering::SeqCst);
            let question = query.queries().first().unwrap().clone();
            let mut msg = Message::new();
            msg.set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_response_code(ResponseCode::NoError)
                .add_query(question);
            Ok(DnsResponse::from_message(msg).unwrap())
        }
    }

    /// Dials a fresh [`FlakyConn`] each time, counting dials so a test can assert
    /// that a dead connection actually triggered a redial.
    struct FlakyDialer {
        dials: AtomicUsize,
        uses_per_conn: usize,
    }

    #[async_trait::async_trait]
    impl Dialer for FlakyDialer {
        async fn dial(&self) -> anyhow::Result<Arc<dyn Connection>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(FlakyConn {
                remaining: AtomicUsize::new(self.uses_per_conn),
            }))
        }
    }

    fn flaky_upstream(uses_per_conn: usize) -> (Upstream, Arc<FlakyDialer>) {
        let dialer = Arc::new(FlakyDialer {
            dials: AtomicUsize::new(0),
            uses_per_conn,
        });
        let addr = "[::1]:853".parse().unwrap();
        (Upstream::with_dialer(addr, dialer.clone()), dialer)
    }

    #[tokio::test]
    async fn upstream_redials_after_connection_dies() {
        // Each connection serves exactly one query before "dying", so every query
        // after the first must transparently redial and still succeed.
        let (upstream, dialer) = flaky_upstream(1);

        for i in 0..4 {
            let resp = upstream.resolve(query_msg("example.com.")).await;
            assert!(
                resp.is_ok(),
                "query {i} should heal via reconnect, got {resp:?}"
            );
        }
        // One initial dial plus three reconnects — not a single permanent failure.
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn upstream_gives_up_after_one_reconnect_when_dead() {
        // A connection that fails immediately and stays dead: resolve must try
        // once, redial once, then return an error (not loop forever).
        let (upstream, dialer) = flaky_upstream(0);

        let resp = upstream.resolve(query_msg("example.com.")).await;
        assert!(
            resp.is_err(),
            "a permanently dead upstream must surface an error"
        );
        assert_eq!(
            dialer.dials.load(Ordering::SeqCst),
            2,
            "exactly one redial attempt before giving up"
        );
    }

    /// Seed a cache entry whose `fetched_at` is `age_secs` in the past, so it is
    /// fresh (when `age_secs < ttl`) or expired (when `age_secs > ttl`) at `now`.
    fn seed(pool: &Pool, name: &str, ip: [u8; 4], ttl: u32, age_secs: u64) {
        let fetched_at = Instant::now() - Duration::from_secs(age_secs);
        pool.inner.cache.as_ref().unwrap().insert(
            a_query(name),
            vec![a_record(name, ip, ttl)],
            fetched_at,
        );
    }

    fn first_answer_ip(resp: &DnsResponse) -> Ipv4Addr {
        first_ip(resp.answers())
    }

    /// Read a scalar Prometheus counter out of the exposition.
    fn counter(metrics: &Metrics, name: &str) -> u64 {
        for line in metrics.render_prometheus().lines() {
            if let Some(value) = line.strip_prefix(name).and_then(|r| r.strip_prefix(' ')) {
                return value.trim().parse().unwrap();
            }
        }
        panic!("metric {name} not found");
    }

    #[tokio::test]
    async fn cold_miss_caches_then_serves_fresh_without_re_querying() {
        let metrics = Arc::new(Metrics::new(&[]));
        let mock = MockResolver::new(Some((Ipv4Addr::new(1, 2, 3, 4), 300)), Duration::ZERO);
        let pool = pool_with(mock.clone(), true, metrics.clone());

        let r1 = pool
            .resolve(query_msg("example.com."))
            .await
            .expect("answer");
        assert_eq!(first_answer_ip(&r1), Ipv4Addr::new(1, 2, 3, 4));

        let r2 = pool
            .resolve(query_msg("example.com."))
            .await
            .expect("answer");
        assert_eq!(first_answer_ip(&r2), Ipv4Addr::new(1, 2, 3, 4));

        assert_eq!(mock.calls(), 1, "the second query is served from cache");
        assert_eq!(counter(&metrics, "dns_cache_hits_total"), 1);
    }

    #[tokio::test]
    async fn serves_stale_when_upstream_is_down() {
        let metrics = Arc::new(Metrics::new(&[]));
        let mock = MockResolver::new(None, Duration::ZERO); // every upstream down
        let pool = pool_with(mock.clone(), true, metrics.clone());
        seed(&pool, "example.com.", [9, 9, 9, 9], 5, 100); // expired ~95s ago

        let r = pool
            .resolve(query_msg("example.com."))
            .await
            .expect("stale answer, not SERVFAIL");
        assert_eq!(first_answer_ip(&r), Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(
            r.answers()[0].ttl(),
            STALE_SERVE_TTL,
            "stale answers carry the short self-correcting TTL"
        );
        assert_eq!(mock.calls(), 1, "a refresh was attempted");
        assert_eq!(counter(&metrics, "dns_served_stale_total"), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn fast_refresh_beats_timer_and_serves_fresh() {
        let metrics = Arc::new(Metrics::new(&[]));
        // Refresh returns in 1s, inside the 1.8s client-response window.
        let mock = MockResolver::new(
            Some((Ipv4Addr::new(2, 2, 2, 2), 300)),
            Duration::from_secs(1),
        );
        let pool = pool_with(mock.clone(), true, metrics.clone());
        seed(&pool, "example.com.", [9, 9, 9, 9], 5, 100);

        let r = pool
            .resolve(query_msg("example.com."))
            .await
            .expect("answer");
        assert_eq!(
            first_answer_ip(&r),
            Ipv4Addr::new(2, 2, 2, 2),
            "the refresh won the race, so the client gets fresh data"
        );
        assert_eq!(counter(&metrics, "dns_served_stale_total"), 0);
        assert_eq!(mock.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_refresh_serves_stale_then_repopulates_cache() {
        let metrics = Arc::new(Metrics::new(&[]));
        // Refresh takes 3s, past the 1.8s timer.
        let mock = MockResolver::new(
            Some((Ipv4Addr::new(2, 2, 2, 2), 300)),
            Duration::from_secs(3),
        );
        let pool = pool_with(mock.clone(), true, metrics.clone());
        seed(&pool, "example.com.", [9, 9, 9, 9], 5, 100);

        let r = pool
            .resolve(query_msg("example.com."))
            .await
            .expect("stale answer");
        assert_eq!(
            first_answer_ip(&r),
            Ipv4Addr::new(9, 9, 9, 9),
            "timer fired first, so the client gets stale data"
        );
        assert_eq!(counter(&metrics, "dns_served_stale_total"), 1);

        // Let the detached refresh finish, then the next query is served fresh from
        // the repopulated cache with no further upstream traffic.
        tokio::time::sleep(Duration::from_secs(2)).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        let r2 = pool
            .resolve(query_msg("example.com."))
            .await
            .expect("answer");
        assert_eq!(
            first_answer_ip(&r2),
            Ipv4Addr::new(2, 2, 2, 2),
            "the background refresh updated the cache"
        );
        assert_eq!(
            mock.calls(),
            1,
            "only the single background refresh hit upstream"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_stale_queries_trigger_one_refresh() {
        let metrics = Arc::new(Metrics::new(&[]));
        let mock = MockResolver::new(
            Some((Ipv4Addr::new(2, 2, 2, 2), 300)),
            Duration::from_secs(1),
        );
        let pool = pool_with(mock.clone(), true, metrics.clone());
        seed(&pool, "example.com.", [9, 9, 9, 9], 5, 100);

        let answers = join_all((0..5).map(|_| pool.resolve(query_msg("example.com.")))).await;
        assert!(
            answers.iter().all(Option::is_some),
            "every concurrent query gets an answer"
        );
        assert_eq!(
            mock.calls(),
            1,
            "the in-flight guard collapses the burst to one refresh"
        );
    }

    #[tokio::test]
    async fn prefetch_refreshes_entry_near_expiry() {
        let metrics = Arc::new(Metrics::new(&[]));
        let mock = MockResolver::new(Some((Ipv4Addr::new(2, 2, 2, 2), 300)), Duration::ZERO);
        let pool = pool_with(mock.clone(), true, metrics.clone());
        // Fresh, but 95s into a 100s TTL — inside the last 10%, so prefetch-due.
        seed(&pool, "example.com.", [9, 9, 9, 9], 100, 95);

        let r = pool
            .resolve(query_msg("example.com."))
            .await
            .expect("fresh answer");
        assert_eq!(
            first_answer_ip(&r),
            Ipv4Addr::new(9, 9, 9, 9),
            "the still-fresh cached answer is served immediately"
        );

        // The hit kicked off exactly one background prefetch.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(mock.calls(), 1);
        assert_eq!(counter(&metrics, "dns_prefetch_total"), 1);
        assert_eq!(counter(&metrics, "dns_cache_hits_total"), 1);
    }

    /// A resolver that always returns a negative response (counting calls),
    /// optionally carrying an authority SOA.
    struct NegResolver {
        calls: AtomicUsize,
        code: ResponseCode,
        with_soa: bool,
    }

    impl NegResolver {
        fn new(code: ResponseCode, with_soa: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                code,
                with_soa,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl Resolver for NegResolver {
        async fn resolve(&self, query: Message) -> Option<DnsResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let question = query.queries().first()?.clone();
            let mut msg = Message::new();
            msg.set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_response_code(self.code)
                .add_query(question);
            if self.with_soa {
                msg.add_name_server(soa_record("example.com.", 300, 60));
            }
            DnsResponse::from_message(msg).ok()
        }
    }

    #[tokio::test]
    async fn caches_nxdomain_with_soa() {
        let metrics = Arc::new(Metrics::new(&[]));
        let mock = NegResolver::new(ResponseCode::NXDomain, true);
        let pool = pool_with(mock.clone(), true, metrics.clone());

        let r1 = pool
            .resolve(query_msg("nope.example.com."))
            .await
            .expect("answer");
        assert_eq!(r1.response_code(), ResponseCode::NXDomain);

        let r2 = pool
            .resolve(query_msg("nope.example.com."))
            .await
            .expect("answer");
        assert_eq!(r2.response_code(), ResponseCode::NXDomain);
        // The cached negative carries its proof of non-existence.
        assert!(r2
            .name_servers()
            .iter()
            .any(|r| matches!(r.data(), RData::SOA(_))));

        assert_eq!(mock.calls(), 1, "the second query is served from cache");
        assert_eq!(counter(&metrics, "dns_negative_cache_hits_total"), 1);
        assert_eq!(counter(&metrics, "dns_cache_hits_total"), 1);
    }

    #[tokio::test]
    async fn caches_nodata_with_soa() {
        let metrics = Arc::new(Metrics::new(&[]));
        // NODATA: NoError with no answers, but an authority SOA.
        let mock = NegResolver::new(ResponseCode::NoError, true);
        let pool = pool_with(mock.clone(), true, metrics.clone());

        for _ in 0..2 {
            let r = pool
                .resolve(query_msg("nodata.example.com."))
                .await
                .expect("answer");
            assert_eq!(r.response_code(), ResponseCode::NoError);
            assert!(r.answers().is_empty());
        }
        assert_eq!(mock.calls(), 1, "NODATA is cached and re-served");
        assert_eq!(counter(&metrics, "dns_negative_cache_hits_total"), 1);
    }

    #[tokio::test]
    async fn negative_without_soa_is_not_cached() {
        let metrics = Arc::new(Metrics::new(&[]));
        let mock = NegResolver::new(ResponseCode::NXDomain, false);
        let pool = pool_with(mock.clone(), true, metrics.clone());

        for _ in 0..2 {
            pool.resolve(query_msg("nope.example.com."))
                .await
                .expect("answer");
        }
        assert_eq!(
            mock.calls(),
            2,
            "with no SOA there is nothing to cache, so both queries hit upstream"
        );
        assert_eq!(counter(&metrics, "dns_negative_cache_hits_total"), 0);
    }
}
