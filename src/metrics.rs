//! Prometheus metrics: counters and a tiny `GET /metrics` HTTP endpoint.
//!
//! All state is `AtomicU64` counters in a single [`Metrics`] shared (via `Arc`)
//! across the handler, the upstream `Pool`, and the synthesizer `Chain`. The
//! exposition is plain Prometheus text (version 0.0.4), scrapeable by a Zabbix
//! HTTP-agent item with *Prometheus pattern* / *Prometheus to JSON* preprocessing
//!
//! Per-synthesizer hits are tracked only for the *enabled* synthesizers (config
//! order), so the `synth_hits_total` family is a stable set Zabbix LLD can
//! discover. Counters use `Relaxed` ordering: each is independent, with no
//! cross-counter invariant to preserve.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::synth::KNOWN_IDS;

/// Query-type buckets we expose, in render order. Everything not listed maps to
/// the trailing `other` bucket, so a client cannot inflate label cardinality with
/// arbitrary qtype numbers. Keep this aligned with [`qtype_index`].
const QTYPE_LABELS: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA", "SRV", "CAA", "HTTPS", "SVCB", "DS",
    "DNSKEY", "NAPTR", "ANY", "other",
];

/// Index of `rt`'s bucket in [`QTYPE_LABELS`]; the last index is the `other` catch-all.
fn qtype_index(rt: RecordType) -> usize {
    match rt {
        RecordType::A => 0,
        RecordType::AAAA => 1,
        RecordType::CNAME => 2,
        RecordType::MX => 3,
        RecordType::TXT => 4,
        RecordType::NS => 5,
        RecordType::PTR => 6,
        RecordType::SOA => 7,
        RecordType::SRV => 8,
        RecordType::CAA => 9,
        RecordType::HTTPS => 10,
        RecordType::SVCB => 11,
        RecordType::DS => 12,
        RecordType::DNSKEY => 13,
        RecordType::NAPTR => 14,
        RecordType::ANY => 15,
        _ => QTYPE_LABELS.len() - 1,
    }
}

/// Per-RCODE response counters.
#[derive(Default)]
struct RcodeCounters {
    noerror: AtomicU64,
    nxdomain: AtomicU64,
    servfail: AtomicU64,
    notimp: AtomicU64,
    formerr: AtomicU64,
    refused: AtomicU64,
    other: AtomicU64,
}

/// All scalar counters, grouped so they can be zero-initialized with `Default`.
#[derive(Default)]
struct Counters {
    queries_dns64: AtomicU64,
    queries_passthrough: AtomicU64,
    rcode: RcodeCounters,
    upstream_failed: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    negative_cache_hits: AtomicU64,
    served_stale: AtomicU64,
    prefetches: AtomicU64,
    native_aaaa: AtomicU64,
    nxdomain64: AtomicU64,
    nodata: AtomicU64,
    synthesized: AtomicU64,
    empty: AtomicU64,
}

/// Process-wide metrics. Cheap to share behind an `Arc`.
pub struct Metrics {
    c: Counters,
    /// Enabled synthesizer ids, in config order; parallel to `synth_hits`.
    synth_ids: Vec<&'static str>,
    /// Hit count per enabled synthesizer; parallel to `synth_ids`.
    synth_hits: Vec<AtomicU64>,
    /// Query count per type, parallel to [`QTYPE_LABELS`].
    qtype_counts: Vec<AtomicU64>,
}

impl Metrics {
    /// Build metrics for the given enabled synthesizer ids (unknown ids — which
    /// `Chain::build` would already have rejected — are skipped defensively).
    pub fn new(enabled: &[String]) -> Self {
        let synth_ids: Vec<&'static str> = enabled
            .iter()
            .filter_map(|id| KNOWN_IDS.iter().copied().find(|k| *k == id))
            .collect();
        let synth_hits = synth_ids.iter().map(|_| AtomicU64::new(0)).collect();
        let qtype_counts = QTYPE_LABELS.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            c: Counters::default(),
            synth_ids,
            synth_hits,
            qtype_counts,
        }
    }

    pub fn inc_queries_dns64(&self) {
        self.c.queries_dns64.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_queries_passthrough(&self) {
        self.c.queries_passthrough.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_upstream_failed(&self) {
        self.c.upstream_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cache_hit(&self) {
        self.c.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cache_miss(&self) {
        self.c.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_negative_cache_hit(&self) {
        self.c.negative_cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_served_stale(&self) {
        self.c.served_stale.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_prefetch(&self) {
        self.c.prefetches.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_native_aaaa(&self) {
        self.c.native_aaaa.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_nxdomain64(&self) {
        self.c.nxdomain64.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_nodata(&self) {
        self.c.nodata.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_synthesized(&self) {
        self.c.synthesized.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_empty(&self) {
        self.c.empty.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a query under its type bucket (unlisted types fall to `other`).
    pub fn record_qtype(&self, rt: RecordType) {
        self.qtype_counts[qtype_index(rt)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a response RCODE under the matching label.
    pub fn record_rcode(&self, code: ResponseCode) {
        let r = &self.c.rcode;
        let counter = match code {
            ResponseCode::NoError => &r.noerror,
            ResponseCode::NXDomain => &r.nxdomain,
            ResponseCode::ServFail => &r.servfail,
            ResponseCode::NotImp => &r.notimp,
            ResponseCode::FormErr => &r.formerr,
            ResponseCode::Refused => &r.refused,
            _ => &r.other,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that synthesizer `id` produced records. No-op for an id that is not
    /// enabled (so it never appears in the exposition).
    pub fn synth_hit(&self, id: &str) {
        if let Some(i) = self.synth_ids.iter().position(|s| *s == id) {
            self.synth_hits[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Render the Prometheus text exposition (version 0.0.4).
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut s = String::with_capacity(2048);

        let _ = writeln!(
            s,
            "# HELP dns_queries_total DNS queries handled, by processing kind."
        );
        let _ = writeln!(s, "# TYPE dns_queries_total counter");
        let _ = writeln!(
            s,
            "dns_queries_total{{kind=\"dns64\"}} {}",
            g(&self.c.queries_dns64)
        );
        let _ = writeln!(
            s,
            "dns_queries_total{{kind=\"passthrough\"}} {}",
            g(&self.c.queries_passthrough)
        );

        let _ = writeln!(
            s,
            "# HELP dns_queries_by_qtype_total DNS queries handled, by query type."
        );
        let _ = writeln!(s, "# TYPE dns_queries_by_qtype_total counter");
        for (label, a) in QTYPE_LABELS.iter().zip(&self.qtype_counts) {
            let _ = writeln!(
                s,
                "dns_queries_by_qtype_total{{qtype=\"{label}\"}} {}",
                g(a)
            );
        }

        let _ = writeln!(
            s,
            "# HELP dns_responses_total Responses sent to clients, by RCODE."
        );
        let _ = writeln!(s, "# TYPE dns_responses_total counter");
        for (label, a) in [
            ("noerror", &self.c.rcode.noerror),
            ("nxdomain", &self.c.rcode.nxdomain),
            ("servfail", &self.c.rcode.servfail),
            ("notimp", &self.c.rcode.notimp),
            ("formerr", &self.c.rcode.formerr),
            ("refused", &self.c.rcode.refused),
            ("other", &self.c.rcode.other),
        ] {
            let _ = writeln!(s, "dns_responses_total{{rcode=\"{label}\"}} {}", g(a));
        }

        for (name, help, a) in [
            (
                "dns_upstream_failed_total",
                "Queries where every upstream failed (client got SERVFAIL).",
                &self.c.upstream_failed,
            ),
            (
                "dns_cache_hits_total",
                "Response-cache hits (all pool lookups, incl. internal reference resolutions).",
                &self.c.cache_hits,
            ),
            (
                "dns_cache_misses_total",
                "Response-cache misses for cacheable queries.",
                &self.c.cache_misses,
            ),
            (
                "dns_negative_cache_hits_total",
                "Cache hits served from a negative (NXDOMAIN/NODATA) entry (RFC 2308).",
                &self.c.negative_cache_hits,
            ),
            (
                "dns_served_stale_total",
                "Answers served from expired cache (RFC 8767 serve-stale).",
                &self.c.served_stale,
            ),
            (
                "dns_prefetch_total",
                "Background refreshes triggered by a cache hit near TTL expiry.",
                &self.c.prefetches,
            ),
            (
                "dns64_native_aaaa_total",
                "AAAA queries relayed because a native AAAA existed.",
                &self.c.native_aaaa,
            ),
            (
                "dns64_nxdomain_total",
                "AAAA queries that resolved to NXDOMAIN.",
                &self.c.nxdomain64,
            ),
            (
                "dns64_nodata_total",
                "AAAA-NODATA queries that entered the synthesizer chain.",
                &self.c.nodata,
            ),
            (
                "dns64_synthesized_total",
                "AAAA-NODATA queries where the chain produced records.",
                &self.c.synthesized,
            ),
            (
                "dns64_empty_total",
                "AAAA-NODATA queries where the chain produced nothing (honest empty answer).",
                &self.c.empty,
            ),
        ] {
            let _ = writeln!(s, "# HELP {name} {help}");
            let _ = writeln!(s, "# TYPE {name} counter");
            let _ = writeln!(s, "{name} {}", g(a));
        }

        let _ = writeln!(
            s,
            "# HELP synth_hits_total Records synthesized, by the synthesizer that produced them."
        );
        let _ = writeln!(s, "# TYPE synth_hits_total counter");
        for (id, a) in self.synth_ids.iter().zip(&self.synth_hits) {
            let _ = writeln!(s, "synth_hits_total{{synthesizer=\"{id}\"}} {}", g(a));
        }

        s
    }
}

/// How long a single metrics connection may take before we drop it. Bounds the
/// per-connection task so an idle or slow client can't park a task forever (the
/// endpoint is unauthenticated, so this guards against trivial slow-loris).
const CONN_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve the metrics endpoint forever. Logs and returns if the bind fails (the
/// rest of the server keeps running — metrics are best-effort).
pub async fn serve(metrics: Arc<Metrics>, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(err) => {
            error!(error = %err, %addr, "metrics: failed to bind; endpoint disabled");
            return;
        }
    };
    info!(%addr, "metrics endpoint listening on GET /metrics");

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(CONN_TIMEOUT, handle_conn(stream, metrics)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            tracing::debug!(error = %err, "metrics: connection error")
                        }
                        Err(_) => tracing::debug!("metrics: connection timed out"),
                    }
                });
            }
            Err(err) => error!(error = %err, "metrics: accept failed"),
        }
    }
}

/// Handle one HTTP/1.1 connection: parse the request line, answer `GET /metrics`
/// with the exposition and everything else with 404. Headers and body are ignored.
async fn handle_conn(mut stream: TcpStream, metrics: Arc<Metrics>) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;

    let head = String::from_utf8_lossy(&buf[..n]);
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");

    let (status, ctype, body) = if method == "GET" && path == "/metrics" {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            metrics.render_prometheus(),
        )
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        )
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> Metrics {
        Metrics::new(&["fastly".to_string(), "nat64".to_string()])
    }

    #[test]
    fn synth_hit_counts_enabled_and_ignores_unknown() {
        let m = metrics();
        m.synth_hit("fastly");
        m.synth_hit("fastly");
        m.synth_hit("nat64");
        m.synth_hit("akamai"); // not enabled -> no-op, never rendered

        let out = m.render_prometheus();
        assert!(out.contains("synth_hits_total{synthesizer=\"fastly\"} 2"));
        assert!(out.contains("synth_hits_total{synthesizer=\"nat64\"} 1"));
        assert!(!out.contains("akamai"));
    }

    #[test]
    fn qtype_buckets_and_other_catch_all() {
        let m = metrics();
        m.record_qtype(RecordType::AAAA);
        m.record_qtype(RecordType::AAAA);
        m.record_qtype(RecordType::A);
        m.record_qtype(RecordType::PTR);
        m.record_qtype(RecordType::HINFO); // unlisted -> "other"

        let out = m.render_prometheus();
        assert!(out.contains("dns_queries_by_qtype_total{qtype=\"AAAA\"} 2"));
        assert!(out.contains("dns_queries_by_qtype_total{qtype=\"A\"} 1"));
        assert!(out.contains("dns_queries_by_qtype_total{qtype=\"PTR\"} 1"));
        assert!(out.contains("dns_queries_by_qtype_total{qtype=\"other\"} 1"));
    }

    #[test]
    fn rcode_and_scalar_counters_render() {
        let m = metrics();
        m.inc_queries_dns64();
        m.inc_cache_hit();
        m.inc_cache_hit();
        m.record_rcode(ResponseCode::NoError);
        m.record_rcode(ResponseCode::NXDomain);
        m.record_rcode(ResponseCode::Refused);
        m.record_rcode(ResponseCode::YXDomain); // maps to "other"

        let out = m.render_prometheus();
        assert!(out.contains("dns_queries_total{kind=\"dns64\"} 1"));
        assert!(out.contains("dns_queries_total{kind=\"passthrough\"} 0"));
        assert!(out.contains("dns_cache_hits_total 2"));
        assert!(out.contains("dns_responses_total{rcode=\"noerror\"} 1"));
        assert!(out.contains("dns_responses_total{rcode=\"nxdomain\"} 1"));
        assert!(out.contains("dns_responses_total{rcode=\"refused\"} 1"));
        assert!(out.contains("dns_responses_total{rcode=\"other\"} 1"));
        // Every counter family carries HELP/TYPE metadata.
        assert!(out.contains("# TYPE dns64_synthesized_total counter"));
    }
}
