//! Upstream resolver pool.
//!
//! Each upstream keeps a long-lived UDP and TCP `Client` (both cheaply cloneable
//! and shared across requests). We send over UDP and fall back to TCP on a
//! truncated (TC=1) response, since the client layer does not do this for us.
//! Across upstreams we fail over on connection error or SERVFAIL.
//!
//! In front of the upstreams sits an optional response cache ([`StaleCache`]),
//! which stores positive answers whole (the full answer section, keyed by the
//! single query) rather than per-record. On top of plain caching it implements
//! two resilience features:
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
//! The cache is deliberately narrow: positive answers only, and only for queries
//! with the DNSSEC-OK (DO) bit clear, so DNSSEC-aware clients always get an
//! untouched, full-fidelity upstream response.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_util::stream::StreamExt;
use hickory_client::client::Client;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsHandle, DnsResponse};
use moka::{sync::Cache, Expiry};
use tokio::task::JoinHandle;

use crate::metrics::Metrics;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound a cached TTL is clamped to (one day), matching common forwarder
/// behaviour and RFC 2181 §8 guidance that implementations may cap received TTLs.
const MAX_TTL: u32 = 86_400;

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

/// A single upstream resolver reachable over both UDP and TCP.
struct Upstream {
    addr: SocketAddr,
    udp: Client,
    tcp: Client,
}

impl Upstream {
    async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
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

        Ok(Self { addr, udp, tcp })
    }

    /// Send `query` over UDP, retrying over TCP if the answer is truncated.
    async fn resolve(&self, query: Message) -> anyhow::Result<DnsResponse> {
        let resp = send_once(&self.udp, query.clone())
            .await
            .with_context(|| format!("UDP query to upstream {}", self.addr))?;
        if resp.truncated() {
            send_once(&self.tcp, query)
                .await
                .with_context(|| format!("TCP retry to upstream {}", self.addr))
        } else {
            Ok(resp)
        }
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
                    tracing::warn!(upstream = %upstream.addr, "upstream returned SERVFAIL, failing over");
                }
                Ok(resp) => return Some(resp),
                Err(err) => {
                    tracing::warn!(upstream = %upstream.addr, error = %format!("{err:#}"), "upstream query failed, failing over");
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
        addrs: &[SocketAddr],
        cache_size: usize,
        serve_stale: bool,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let mut upstreams = Vec::with_capacity(addrs.len());
        for &addr in addrs {
            upstreams.push(Upstream::connect(addr).await?);
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
        let inner = &self.inner;
        // Only cacheable queries get a key; everything else bypasses the cache.
        let key = inner
            .cache
            .as_ref()
            .and_then(|_| cacheable_question(&query));

        if let (Some(cache), Some(question)) = (&inner.cache, &key) {
            match cache.get(question, Instant::now()) {
                Some(CacheLookup::Fresh { records, prefetch }) => {
                    if let Some(resp) = build_cached_response(question, records) {
                        tracing::debug!(name = %question.name(), qtype = %question.query_type(), "cache hit");
                        inner.metrics.inc_cache_hit();
                        // Popular name nearing expiry: refresh it before it lapses.
                        if prefetch && self.spawn_refresh(query, question.clone()).is_some() {
                            inner.metrics.inc_prefetch();
                        }
                        return Some(resp);
                    }
                }
                Some(CacheLookup::Stale(records)) => {
                    if let Some(stale) = build_cached_response(question, records) {
                        return Some(self.serve_stale(query, question.clone(), stale).await);
                    }
                }
                None => inner.metrics.inc_cache_miss(),
            }
        }

        self.resolve_and_cache(query).await
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

        // Cache positive answers only. Negative responses (NXDOMAIN/NODATA) flow
        // upstream every time — we never cache or serve them stale.
        if let (Some(cache), Some(question)) = (&inner.cache, &key) {
            if resp.response_code() == ResponseCode::NoError && !resp.answers().is_empty() {
                cache.insert(question.clone(), resp.answers().to_vec(), Instant::now());
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

/// Build a response message carrying `records` as the answer to `question`.
fn build_cached_response(question: &Query, records: Vec<Record>) -> Option<DnsResponse> {
    if records.is_empty() {
        return None;
    }
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(ResponseCode::NoError)
        .set_recursion_available(true)
        .add_query(question.clone())
        .add_answers(records);
    DnsResponse::from_message(message).ok()
}

/// A response cache that retains expired answers for a stale window (RFC 8767).
///
/// Answers are stored whole — the entire answer section (including any CNAME
/// chain, in upstream order) under the single query key — so a hit is served
/// verbatim with no per-record reassembly. The min TTL across the answer set
/// (clamped to [`MAX_TTL`]) is the entry's freshness deadline.
struct StaleCache {
    cache: Cache<Query, Arc<CacheEntry>>,
    /// How long past its deadline an entry may still be served stale.
    stale_window: Duration,
}

struct CacheEntry {
    answers: Vec<Record>,
    /// When the entry was stored (used to recover the original TTL for prefetch).
    fetched_at: Instant,
    /// Freshness deadline: `fetched_at + min(answer TTLs, MAX_TTL)`.
    valid_until: Instant,
}

/// The outcome of a cache lookup for a present entry.
enum CacheLookup {
    /// Still within TTL. `prefetch` is set when it has entered the last
    /// [`PREFETCH_FRACTION`] of its life and should be refreshed proactively.
    Fresh {
        records: Vec<Record>,
        prefetch: bool,
    },
    /// Expired but within the stale window.
    Stale(Vec<Record>),
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

    fn insert(&self, question: Query, answers: Vec<Record>, now: Instant) {
        let ttl = answers
            .iter()
            .map(Record::ttl)
            .min()
            .unwrap_or(0)
            .min(MAX_TTL);
        let valid_until = now + Duration::from_secs(u64::from(ttl));
        self.cache.insert(
            question,
            Arc::new(CacheEntry {
                answers,
                fetched_at: now,
                valid_until,
            }),
        );
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
                records: stamp_ttl(&entry.answers, remaining.as_secs() as u32),
                prefetch,
            })
        } else if now <= entry.valid_until + self.stale_window {
            Some(CacheLookup::Stale(stamp_ttl(
                &entry.answers,
                STALE_SERVE_TTL,
            )))
        } else {
            None
        }
    }
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
    use hickory_proto::rr::rdata::A;
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
            Some(CacheLookup::Fresh { records, prefetch }) => {
                assert_eq!(first_ip(&records), Ipv4Addr::new(93, 1, 2, 3));
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
            Some(CacheLookup::Fresh { records, .. }) => {
                assert!(
                    records[0].ttl() <= 200,
                    "ttl should have decayed, got {}",
                    records[0].ttl()
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
            Some(CacheLookup::Stale(records)) => {
                assert_eq!(first_ip(&records), Ipv4Addr::new(93, 1, 2, 3));
                // Stale answers are stamped with the short self-correcting TTL.
                assert_eq!(records[0].ttl(), STALE_SERVE_TTL);
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
}
