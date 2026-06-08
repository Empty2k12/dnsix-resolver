//! Upstream resolver pool.
//!
//! Each upstream keeps a long-lived UDP and TCP `Client` (both cheaply cloneable
//! and shared across requests). We send over UDP and fall back to TCP on a
//! truncated (TC=1) response, since the client layer does not do this for us.
//! Across upstreams we fail over on connection error or SERVFAIL.
//!
//! In front of the upstreams sits an optional response cache.
//! We reuse hickory-resolver's `DnsLru` — its per-(name, type) record cache — as
//! the store. Because that cache holds answer records only (not authority/additional
//! sections or the AD bit) we deliberately keep it narrow: positive answers only,
//! and only for queries with the DNSSEC-OK (DO) bit clear, so DNSSEC-aware clients
//! always get an untouched, full-fidelity upstream response.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_util::stream::StreamExt;
use hickory_client::client::Client;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsHandle, DnsResponse};
use hickory_resolver::dns_lru::{DnsLru, TtlConfig};

use crate::metrics::Metrics;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on how many CNAME hops we will follow when reassembling a cached answer,
/// guarding against a pathological or looping chain in the cache.
const MAX_CNAME_HOPS: usize = 16;

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

/// An ordered pool of upstreams with failover, fronted by an optional cache.
pub struct Pool {
    upstreams: Vec<Upstream>,
    /// `None` when caching is disabled (`cache_size = 0`).
    cache: Option<DnsLru>,
    metrics: Arc<Metrics>,
}

impl Pool {
    pub async fn connect(
        addrs: &[SocketAddr],
        cache_size: usize,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let mut upstreams = Vec::with_capacity(addrs.len());
        for &addr in addrs {
            upstreams.push(Upstream::connect(addr).await?);
        }
        // DnsLru clamps record TTLs to TtlConfig's bounds; the defaults (min 0,
        // max 1 day) are the right behaviour for a forwarder cache.
        let cache = (cache_size > 0).then(|| DnsLru::new(cache_size, TtlConfig::default()));
        Ok(Self { upstreams, cache, metrics })
    }

    /// Resolve a query, serving from cache when possible and otherwise querying
    /// upstream. Returns `None` only if every upstream failed.
    pub async fn resolve(&self, query: Message) -> Option<DnsResponse> {
        // Only cacheable queries get a key; everything else bypasses the cache.
        let key = self
            .cache
            .as_ref()
            .and_then(|_| cacheable_question(&query));

        if let (Some(cache), Some(question)) = (&self.cache, &key) {
            if let Some(resp) = cache_get(cache, question) {
                tracing::debug!(name = %question.name(), qtype = %question.query_type(), "cache hit");
                self.metrics.inc_cache_hit();
                return Some(resp);
            }
            self.metrics.inc_cache_miss();
        }

        let resp = match self.resolve_upstream(query).await {
            Some(resp) => resp,
            None => {
                self.metrics.inc_upstream_failed();
                return None;
            }
        };

        // Populate the cache from positive answers only. Negative responses
        // (NXDOMAIN/NODATA) would need DnsLru's crate-private negative-caching
        // path, so we leave them to flow upstream every time.
        if let (Some(cache), Some(question)) = (&self.cache, &key) {
            if resp.response_code() == ResponseCode::NoError && !resp.answers().is_empty() {
                cache.insert_records(
                    question.clone(),
                    resp.answers().iter().cloned(),
                    Instant::now(),
                );
            }
        }
        Some(resp)
    }

    /// Try each upstream in turn. An upstream is considered failed (move to the
    /// next) on transport error or SERVFAIL; any other response — including
    /// NXDOMAIN and NODATA — is authoritative and returned. `None` if all failed.
    async fn resolve_upstream(&self, query: Message) -> Option<DnsResponse> {
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

/// The cache key for a query, or `None` if it must not be cached: we cache only
/// single-question queries with the DNSSEC-OK (DO) bit clear, so DNSSEC-aware
/// clients always receive a full-fidelity upstream answer rather than one
/// reassembled from the record cache (which drops RRSIGs and the AD bit).
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

/// Reassemble a cached response for `question`, or `None` on a cache miss.
fn cache_get(cache: &DnsLru, question: &Query) -> Option<DnsResponse> {
    let records = cached_records(cache, question, Instant::now())?;
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

/// Collect the answer records for `question` from the cache, following CNAMEs.
///
/// `DnsLru` stores each name+type as its own entry and keys a CNAME under the
/// *original* query type, so a single `get` for a CNAME'd name returns just the
/// CNAME record. We chase the chain ourselves — as hickory's own `CachingClient`
/// does — assembling the full answer. A missing or expired link anywhere in the
/// chain yields `None` (a miss), so we never serve a dangling CNAME.
fn cached_records(cache: &DnsLru, question: &Query, now: Instant) -> Option<Vec<Record>> {
    let mut current = question.clone();
    let mut answers: Vec<Record> = Vec::new();

    for _ in 0..MAX_CNAME_HOPS {
        let lookup = cache.get(&current, now)?.ok()?;
        let mut cname_target = None;
        for record in lookup.records() {
            if let RData::CNAME(target) = record.data() {
                cname_target = Some(target.0.clone());
            }
            answers.push(record.clone());
        }
        match cname_target {
            // A CNAME aliases to another name; follow it for the original type.
            // (A direct CNAME query stops here — the CNAME itself is the answer.)
            Some(target) if question.query_type() != RecordType::CNAME => {
                let mut next = Query::query(target, question.query_type());
                next.set_query_class(question.query_class());
                current = next;
            }
            _ => return Some(answers),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use hickory_proto::op::{Edns, MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{DNSClass, Name, RData, Record};

    fn lru() -> DnsLru {
        DnsLru::new(64, TtlConfig::default())
    }

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

    fn cname_record(name: &str, target: &str, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::CNAME(CNAME(Name::from_str(target).unwrap())),
        )
    }

    #[test]
    fn direct_answer_round_trips() {
        let cache = lru();
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert_records(q.clone(), [a_record("example.com.", [93, 1, 2, 3], 300)].into_iter(), now);

        let records = cached_records(&cache, &q, now).expect("cache hit");
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0].data(), RData::A(A(ip)) if *ip == Ipv4Addr::new(93, 1, 2, 3)));
    }

    #[test]
    fn cname_chain_is_followed() {
        let cache = lru();
        let q = a_query("www.example.com.");
        let now = Instant::now();
        // www -> alias -> a record, the shape a CDN typically returns.
        cache.insert_records(
            q.clone(),
            [
                cname_record("www.example.com.", "alias.cdn.net.", 300),
                cname_record("alias.cdn.net.", "host.cdn.net.", 300),
                a_record("host.cdn.net.", [203, 0, 113, 5], 300),
            ]
            .into_iter(),
            now,
        );

        let records = cached_records(&cache, &q, now).expect("cache hit");
        // Two CNAMEs plus the terminal A, reassembled in chain order.
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].record_type(), RecordType::CNAME);
        assert_eq!(records[1].record_type(), RecordType::CNAME);
        assert!(matches!(records[2].data(), RData::A(_)));
    }

    #[test]
    fn broken_chain_is_a_miss() {
        let cache = lru();
        let q = a_query("www.example.com.");
        let now = Instant::now();
        // Cache only the CNAME; its target was never cached.
        cache.insert_records(
            q.clone(),
            [cname_record("www.example.com.", "absent.cdn.net.", 300)].into_iter(),
            now,
        );
        assert!(cached_records(&cache, &q, now).is_none());
    }

    #[test]
    fn expired_entry_is_a_miss() {
        let cache = lru();
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert_records(q.clone(), [a_record("example.com.", [93, 1, 2, 3], 5)].into_iter(), now);

        let later = now + Duration::from_secs(10);
        assert!(cached_records(&cache, &q, later).is_none());
    }

    /// A reassembled hit carries the record's *remaining* TTL, not its original.
    #[test]
    fn cache_hit_decrements_ttl() {
        let cache = lru();
        let q = a_query("example.com.");
        let now = Instant::now();
        cache.insert_records(q.clone(), [a_record("example.com.", [93, 1, 2, 3], 300)].into_iter(), now);

        let records = cached_records(&cache, &q, now + Duration::from_secs(100)).expect("hit");
        assert!(records[0].ttl() <= 200, "ttl should have decayed, got {}", records[0].ttl());
    }

    fn message_with(queries: &[Query], dnssec_ok: bool) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query).set_op_code(OpCode::Query);
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
}
