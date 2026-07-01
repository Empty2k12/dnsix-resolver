//! The Query log: a bounded, in-memory record of recent queries for the
//! dashboard.
//!
//! This is the Forwarder's only store of potentially sensitive data (client
//! addresses and queried names), so it exists *only while the dashboard is
//! enabled* — `main` constructs a `QueryLog` solely when `ui_listen` is set, and
//! the handler captures nothing when it is absent. It is purely in-memory and
//! lost on restart.
//!
//! New entries are pushed into a ring buffer (oldest displaced) and also fanned
//! out on a broadcast channel so the dashboard's Server-Sent-Events stream can
//! tail the log live. Each entry records *how* the answer was produced — the
//! piece the aggregate Prometheus counters can never attribute to an individual
//! query.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use tokio::sync::broadcast;

use crate::upstream::CacheStatus;

/// Capacity of the broadcast channel feeding live SSE subscribers. A subscriber
/// that falls this far behind gets a `Lagged` error and simply resumes from the
/// newest entries — fine for a best-effort live tail.
const BROADCAST_CAPACITY: usize = 256;

/// How a query was ultimately answered — the dashboard's signature column. The
/// Forwarder filters nothing, so this describes the *synthesis* disposition, not
/// a block/allow decision.
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    /// Relayed an upstream Native AAAA (synthesis suppressed).
    NativeAaaa,
    /// AAAA query that resolved to NXDOMAIN (relayed).
    Nxdomain,
    /// AAAA-NODATA where the chain produced records; carries the winning
    /// Synthesizer id (a CDN Provider, or `nat64`).
    Synthesized(&'static str),
    /// AAAA-NODATA where the chain produced nothing (honest empty answer).
    EmptyNodata,
    /// A non-AAAA (or CD-bit) query relayed transparently.
    Passthrough,
    /// The name was on the **Blocklist**: answered NXDOMAIN locally, no upstream.
    Blocked,
    /// The client was outside the configured allowlist: answered REFUSED locally.
    Refused,
    /// Every upstream failed; the client got SERVFAIL.
    ServFail,
}

impl Outcome {
    /// Stable category for styling (the dashboard colors the outcome badge by
    /// this, as a reachability-quality gradient: `native` best, then `synth`
    /// (CDN-native IPv6), then `nat64` (only via the translator)). CDN-provider
    /// synthesis is `synth`; only a name that fell through to NAT64 embedding is
    /// `nat64`.
    pub fn kind(&self) -> &'static str {
        match self {
            Outcome::NativeAaaa => "native",
            Outcome::Nxdomain => "nxdomain",
            Outcome::Synthesized("nat64") => "nat64",
            Outcome::Synthesized(_) => "synth",
            Outcome::EmptyNodata => "empty",
            Outcome::Passthrough => "passthrough",
            Outcome::Blocked => "blocked",
            Outcome::Refused => "refused",
            Outcome::ServFail => "servfail",
        }
    }

    /// Short label for display (`synth:<id>` for a synthesized answer).
    pub fn label(&self) -> String {
        match self {
            Outcome::NativeAaaa => "native-aaaa".to_string(),
            Outcome::Nxdomain => "nxdomain".to_string(),
            Outcome::Synthesized(id) => format!("synth:{id}"),
            Outcome::EmptyNodata => "empty".to_string(),
            Outcome::Passthrough => "passthrough".to_string(),
            Outcome::Blocked => "blocked".to_string(),
            Outcome::Refused => "refused".to_string(),
            Outcome::ServFail => "servfail".to_string(),
        }
    }
}

/// One handled query and how it was answered.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Wall-clock time the entry was recorded.
    pub time: SystemTime,
    /// The client that asked.
    pub client: IpAddr,
    /// The queried name (already a presentation string).
    pub name: String,
    /// The queried record type.
    pub qtype: RecordType,
    /// The response code returned to the client.
    pub rcode: ResponseCode,
    /// Cache disposition of the client-facing query.
    pub cache: CacheStatus,
    /// How the answer was produced.
    pub outcome: Outcome,
    /// End-to-end handling latency.
    pub latency: Duration,
}

/// What the handler knows about a query before timing/identity are attached.
/// The handler builds one of these per request; [`QueryLog::record`] stamps the
/// rest.
pub struct Record {
    pub client: IpAddr,
    pub name: String,
    pub qtype: RecordType,
    pub rcode: ResponseCode,
    pub cache: CacheStatus,
    pub outcome: Outcome,
    pub latency: Duration,
}

/// A bounded ring buffer of recent [`Entry`]s plus a live broadcast feed.
pub struct QueryLog {
    buf: Mutex<VecDeque<Entry>>,
    cap: usize,
    tx: broadcast::Sender<Entry>,
}

impl QueryLog {
    /// Create a log holding at most `cap` recent entries (clamped to ≥1).
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            buf: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
            tx,
        }
    }

    /// Record a handled query: push into the ring (displacing the oldest if
    /// full) and fan out to any live subscribers.
    pub fn record(&self, r: Record) {
        let entry = Entry {
            time: SystemTime::now(),
            client: r.client,
            name: r.name,
            qtype: r.qtype,
            rcode: r.rcode,
            cache: r.cache,
            outcome: r.outcome,
            latency: r.latency,
        };
        {
            let mut buf = self.buf.lock().unwrap();
            if buf.len() == self.cap {
                buf.pop_front();
            }
            buf.push_back(entry.clone());
        }
        // Ignore the error when there are no subscribers — the ring buffer is the
        // durable copy; the broadcast is only for live tailing.
        let _ = self.tx.send(entry);
    }

    /// A newest-first snapshot of the ring buffer.
    pub fn snapshot_newest_first(&self) -> Vec<Entry> {
        self.buf.lock().unwrap().iter().rev().cloned().collect()
    }

    /// Subscribe to live entries as they are recorded.
    pub fn subscribe(&self) -> broadcast::Receiver<Entry> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn rec(name: &str) -> Record {
        Record {
            client: IpAddr::V6(Ipv6Addr::LOCALHOST),
            name: name.to_string(),
            qtype: RecordType::AAAA,
            rcode: ResponseCode::NoError,
            cache: CacheStatus::Miss,
            outcome: Outcome::Passthrough,
            latency: Duration::from_millis(1),
        }
    }

    #[test]
    fn ring_evicts_oldest_and_is_newest_first() {
        let log = QueryLog::new(2);
        log.record(rec("a"));
        log.record(rec("b"));
        log.record(rec("c"));

        let snap = log.snapshot_newest_first();
        let names: Vec<&str> = snap.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["c", "b"]); // "a" displaced; newest first
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let log = QueryLog::new(0);
        log.record(rec("only"));
        assert_eq!(log.snapshot_newest_first().len(), 1);
    }

    #[tokio::test]
    async fn subscribers_receive_live_entries() {
        let log = QueryLog::new(8);
        let mut rx = log.subscribe();
        log.record(rec("live"));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.name, "live");
    }
}
