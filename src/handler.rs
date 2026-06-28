//! The DNS64 request handler — the RFC 6147 brain.
//!
//! For an AAAA query (class IN, CD bit clear) we fire the AAAA and A lookups in
//! parallel. If the name has Native AAAA, or is NXDOMAIN, we relay the upstream
//! answer untouched. If AAAA is NODATA, we build a `SynthContext` and run it
//! through the Synthesizer chain (CDN Providers first, NAT64 last); if the chain
//! produces records we send them (AD cleared, since synthesized data is
//! unsigned), otherwise we relay the honest empty answer. Everything else — all
//! non-AAAA queries, and AAAA queries with the CD bit set — is a faithful
//! Passthrough of the upstream response.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Edns, Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::xfer::DnsResponse;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use crate::metrics::Metrics;
use crate::querylog::{Outcome, QueryLog};
use crate::synth::{Authority, Chain, SynthContext};
use crate::upstream::{CacheStatus, Pool};

/// EDNS payload size we advertise upstream and to clients.
const EDNS_PAYLOAD: u16 = 1232;

/// What a finished request observed, for the Query log. Carried back out of the
/// per-path handlers so [`handle_request`](Dns64Handler::handle_request) can
/// record one entry in a single place.
struct Observation {
    rcode: ResponseCode,
    cache: CacheStatus,
    outcome: Outcome,
}

pub struct Dns64Handler {
    pool: Arc<Pool>,
    chain: Arc<Chain>,
    metrics: Arc<Metrics>,
    /// Present only when the dashboard is enabled; `None` means no per-query
    /// capture happens at all.
    query_log: Option<Arc<QueryLog>>,
}

impl Dns64Handler {
    pub fn new(
        pool: Arc<Pool>,
        chain: Arc<Chain>,
        metrics: Arc<Metrics>,
        query_log: Option<Arc<QueryLog>>,
    ) -> Self {
        Self {
            pool,
            chain,
            metrics,
            query_log,
        }
    }

    /// The DNS64 synthesis path: parallel AAAA + A, decide, relay or synthesize.
    /// Returns the response info plus an [`Observation`] for the Query log; the
    /// cache disposition reported is that of the client-facing AAAA query.
    async fn handle_dns64<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        query: &Query,
    ) -> (ResponseInfo, Observation) {
        let aaaa_q = upstream_query(request, query.clone());
        let mut a_query = Query::query(query.name().clone(), RecordType::A);
        a_query.set_query_class(DNSClass::IN);
        let a_q = upstream_query(request, a_query);

        let ((aaaa_res, cache), a_res) =
            tokio::join!(self.pool.resolve_observed(aaaa_q), self.pool.resolve(a_q));

        let Some(aaaa) = aaaa_res else {
            self.metrics.record_rcode(ResponseCode::ServFail);
            let info = serve_fail(request, response_handle).await;
            return (
                info,
                Observation {
                    rcode: ResponseCode::ServFail,
                    cache,
                    outcome: Outcome::ServFail,
                },
            );
        };

        // Native AAAA present: relay untouched.
        let has_native_aaaa = aaaa
            .answers()
            .iter()
            .any(|r| r.record_type() == RecordType::AAAA);
        if has_native_aaaa {
            self.metrics.inc_native_aaaa();
            let rcode = aaaa.response_code();
            self.metrics.record_rcode(rcode);
            let info = relay(request, response_handle, &aaaa).await;
            return (
                info,
                Observation {
                    rcode,
                    cache,
                    outcome: Outcome::NativeAaaa,
                },
            );
        }
        // The name doesn't exist: relay the NXDOMAIN untouched.
        if aaaa.response_code() == ResponseCode::NXDomain {
            self.metrics.inc_nxdomain64();
            self.metrics.record_rcode(ResponseCode::NXDomain);
            let info = relay(request, response_handle, &aaaa).await;
            return (
                info,
                Observation {
                    rcode: ResponseCode::NXDomain,
                    cache,
                    outcome: Outcome::Nxdomain,
                },
            );
        }

        // AAAA is NODATA — assemble the synthesis context and run the chain.
        self.metrics.inc_nodata();
        let a_records: Vec<(Ipv4Addr, u32)> = a_res
            .as_ref()
            .filter(|a| a.response_code() == ResponseCode::NoError)
            .map(|a| {
                a.answers()
                    .iter()
                    .filter_map(|r| match r.data() {
                        RData::A(addr) => Some((addr.0, r.ttl())),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let cname_targets = aaaa
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                RData::CNAME(c) => Some(c.0.clone()),
                _ => None,
            })
            .collect();

        let ctx = SynthContext::new(
            query.name().clone(),
            cname_targets,
            a_records,
            extract_authority(&aaaa),
        );

        match self.chain.synthesize(&ctx, &self.pool, &self.metrics).await {
            Some((records, synth_id)) => {
                self.metrics.inc_synthesized();
                self.metrics.record_rcode(ResponseCode::NoError);
                let info = self
                    .send_synthesized(request, response_handle, records)
                    .await;
                (
                    info,
                    Observation {
                        rcode: ResponseCode::NoError,
                        cache,
                        outcome: Outcome::Synthesized(synth_id),
                    },
                )
            }
            // Nothing synthesized — relay the honest empty answer.
            None => {
                self.metrics.inc_empty();
                let rcode = aaaa.response_code();
                self.metrics.record_rcode(rcode);
                let info = relay(request, response_handle, &aaaa).await;
                (
                    info,
                    Observation {
                        rcode,
                        cache,
                        outcome: Outcome::EmptyNodata,
                    },
                )
            }
        }
    }

    /// Send a synthesized answer. The AAAA records are emitted directly at the
    /// queried owner name; any CNAME chain from the upstream AAAA answer is
    /// deliberately omitted, so the client gets a self-consistent AAAA for the
    /// name it asked for (the canonical-name indirection is not reproduced).
    async fn send_synthesized<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        answers: Vec<Record>,
    ) -> ResponseInfo {
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NoError);
        header.set_recursion_available(true);
        // Synthesized data is unsigned: never claim it is authenticated.
        header.set_authentic_data(false);

        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = response_edns(request) {
            builder.edns(edns);
        }
        let message = builder.build(
            header,
            answers.iter(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
        );
        let result = response_handle.send_response(message).await;
        finish(request, result)
    }
}

#[async_trait::async_trait]
impl RequestHandler for Dns64Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        // We only handle standard queries with exactly one question.
        if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            self.metrics.record_rcode(ResponseCode::NotImp);
            return serve_error(request, response_handle, ResponseCode::NotImp).await;
        }
        let queries = request.queries();
        let [query] = queries else {
            self.metrics.record_rcode(ResponseCode::FormErr);
            return serve_error(request, response_handle, ResponseCode::FormErr).await;
        };
        let query = query.original().clone();
        self.metrics.record_qtype(query.query_type());

        // Identity/timing captured up front, only if we'll record (dashboard on).
        let started = self.query_log.as_ref().map(|_| Instant::now());

        let is_dns64 = query.query_type() == RecordType::AAAA
            && query.query_class() == DNSClass::IN
            && !request.checking_disabled();

        let (info, obs) = if is_dns64 {
            self.metrics.inc_queries_dns64();
            self.handle_dns64(request, response_handle, &query).await
        } else {
            // Passthrough: forward the exact query and relay the response.
            self.metrics.inc_queries_passthrough();
            let msg = upstream_query(request, query.clone());
            let (resp, cache) = self.pool.resolve_observed(msg).await;
            match resp {
                Some(resp) => {
                    let rcode = resp.response_code();
                    self.metrics.record_rcode(rcode);
                    let info = relay(request, response_handle, &resp).await;
                    (
                        info,
                        Observation {
                            rcode,
                            cache,
                            outcome: Outcome::Passthrough,
                        },
                    )
                }
                None => {
                    self.metrics.record_rcode(ResponseCode::ServFail);
                    let info = serve_fail(request, response_handle).await;
                    (
                        info,
                        Observation {
                            rcode: ResponseCode::ServFail,
                            cache,
                            outcome: Outcome::Passthrough,
                        },
                    )
                }
            }
        };

        // Capture one Query-log entry. Only when the dashboard is enabled.
        if let (Some(log), Some(started)) = (&self.query_log, started) {
            log.record(crate::querylog::Record {
                client: request.src().ip(),
                name: query.name().to_string(),
                qtype: query.query_type(),
                rcode: obs.rcode,
                cache: obs.cache,
                outcome: obs.outcome,
                latency: started.elapsed(),
            });
        }

        info
    }
}

/// Extract the authority-section signals a Provider may match on: the SOA admin
/// (RNAME) and the SOA owner name (zone apex).
fn extract_authority(resp: &DnsResponse) -> Authority {
    for r in resp.name_servers() {
        if let RData::SOA(soa) = r.data() {
            return Authority {
                soa_admin: Some(soa.rname().clone()),
                soa_zone: Some(r.name().clone()),
            };
        }
    }
    Authority::default()
}

/// Build an upstream query message carrying `query`, propagating the client's
/// CD bit and DO bit so DNSSEC behaviour is preserved end to end.
fn upstream_query(request: &Request, query: Query) -> Message {
    let mut msg = Message::new();
    msg.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(query);
    msg.set_checking_disabled(request.checking_disabled());

    let dnssec_ok = request.edns().map(|e| e.flags().dnssec_ok).unwrap_or(false);
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(dnssec_ok);
    msg.set_edns(edns);
    msg
}

/// An EDNS OPT to attach to a response when the client used EDNS, mirroring DO.
fn response_edns(request: &Request) -> Option<Edns> {
    let req_edns = request.edns()?;
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
    Some(edns)
}

/// Faithfully relay an upstream response: all sections, RCODE, and the AD bit.
async fn relay<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    resp: &DnsResponse,
) -> ResponseInfo {
    let mut header = Header::response_from_request(request.header());
    header.set_response_code(resp.response_code());
    header.set_recursion_available(true);
    header.set_authentic_data(resp.header().authentic_data());

    let answers = resp.answers().to_vec();
    let authority = resp.name_servers().to_vec();
    let additionals = resp.additionals().to_vec();

    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = response_edns(request) {
        builder.edns(edns);
    }
    let message = builder.build(
        header,
        answers.iter(),
        authority.iter(),
        std::iter::empty::<&Record>(),
        additionals.iter(),
    );
    let result = response_handle.send_response(message).await;
    finish(request, result)
}

async fn serve_fail<R: ResponseHandler>(request: &Request, response_handle: R) -> ResponseInfo {
    serve_error(request, response_handle, ResponseCode::ServFail).await
}

async fn serve_error<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    code: ResponseCode,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let message = builder.error_msg(request.header(), code);
    let result = response_handle.send_response(message).await;
    finish(request, result)
}

/// Map the result of a `send_response` write to a `ResponseInfo`, turning a
/// write failure into a SERVFAIL-shaped result.
fn finish(request: &Request, result: std::io::Result<ResponseInfo>) -> ResponseInfo {
    match result {
        Ok(info) => info,
        Err(err) => {
            tracing::error!(error = %err, "failed to send response to client");
            let mut header = Header::response_from_request(request.header());
            header.set_response_code(ResponseCode::ServFail);
            header.into()
        }
    }
}
