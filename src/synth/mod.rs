//! AAAA synthesis: the pluggable Synthesizer chain.
//!
//! A `Synthesizer` is the seam: a *pure* rule that, given a name and its
//! upstream context, may produce AAAA records for an AAAA-NODATA name.
//! It performs no DNS lookups itself — it returns a [`Plan`] describing
//! what to resolve and how to combine the result, and the [`Chain`] orchestrator
//! executes any resolution (through the upstream `Pool`, so the response cache
//! applies).
//!
//! Two kinds of Synthesizer exist: the [`nat64`] embedding rule (the fallback,
//! intended last in the chain) and the CDN [`cdn`] Providers.

mod cdn;
mod nat64;

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::xfer::DnsResponse;

use crate::metrics::Metrics;
use crate::upstream::Pool;

/// TTL applied to a synthesized record when no source TTL is available (e.g. a
/// constant-fallback address derived after a live reference lookup failed).
const DEFAULT_SYNTH_TTL: u32 = 300;

/// EDNS payload size for the orchestrator's own reference lookups.
const EDNS_PAYLOAD: u16 = 1232;

/// Authority-section signals lifted from the AAAA-NODATA response. Providers
/// match on these for CDNs that run their own DNS (e.g. the SOA admin mailbox
/// `hostmaster.fastly.com`, or an SOA zone under `*.msedge.net`).
#[derive(Debug, Clone, Default)]
pub struct Authority {
    /// The SOA RNAME (admin mailbox), e.g. `hostmaster.fastly.com`.
    pub soa_admin: Option<Name>,
    /// The owner name of the SOA record (the zone apex), e.g. `*.a-msedge.net`.
    pub soa_zone: Option<Name>,
}

/// Everything a Synthesizer may inspect. Built once per AAAA-NODATA query from
/// the parallel AAAA and A lookups the handler already performs — fully inline,
/// no cross-query state.
pub struct SynthContext {
    /// The queried name.
    pub name: Name,
    /// CNAME targets seen in the AAAA answer chain, in order.
    pub cname_targets: Vec<Name>,
    /// The name's A records (address + TTL) from the parallel A lookup.
    pub a_records: Vec<(Ipv4Addr, u32)>,
    /// Authority-section signals from the AAAA response.
    pub authority: Authority,
}

impl SynthContext {
    /// Hostnames a Provider may match against, CNAME targets first (the CDN
    /// hostname is usually the chain's end) then the queried name.
    fn hostnames(&self) -> Vec<&Name> {
        let mut v: Vec<&Name> = self.cname_targets.iter().collect();
        v.push(&self.name);
        v
    }

    /// Just the A addresses, dropping TTLs.
    fn a_addrs(&self) -> Vec<Ipv4Addr> {
        self.a_records.iter().map(|(ip, _)| *ip).collect()
    }
}

/// A pure combinator: given the addresses the orchestrator resolved for the
/// plan and the name's original A addresses, produce the synthesized IPv6 set.
/// A constant fallback lives here (`if resolved.is_empty() { vec![CONST] }`).
pub type Combine = Box<dyn Fn(&[Ipv6Addr], &[Ipv4Addr]) -> Vec<Ipv6Addr> + Send + Sync>;

/// What a Synthesizer returns when it matches: names to resolve and how to turn
/// the result into AAAA records. The orchestrator performs the resolution.
pub struct Plan {
    /// Names the orchestrator must resolve (AAAA, cached) before combining.
    pub resolve: Vec<Name>,
    /// Pure transform from (resolved, original A) to synthesized addresses.
    pub combine: Combine,
}

impl Plan {
    /// A plan that resolves nothing and emits a fixed combine.
    fn pure(combine: Combine) -> Self {
        Plan {
            resolve: Vec::new(),
            combine,
        }
    }
}

/// A pure rule that may synthesize AAAA for an AAAA-NODATA name.
pub trait Synthesizer: Send + Sync {
    /// Stable identifier used in config and precedence rules.
    fn id(&self) -> &'static str;
    /// Inspect the context; return a [`Plan`] if this Synthesizer applies.
    fn detect(&self, ctx: &SynthContext) -> Option<Plan>;
}

/// The ordered Synthesizer chain.
pub struct Chain {
    synths: Vec<Box<dyn Synthesizer>>,
    ttl_cap: Option<u32>,
}

impl Chain {
    /// Build a chain from the configured synthesizer ids (order = precedence).
    /// Validates that every id is known and that hard precedence constraints hold.
    pub fn build(
        ids: &[String],
        nat64_prefix: Ipv6Addr,
        ttl_cap: Option<u32>,
    ) -> anyhow::Result<Self> {
        validate_order(ids)?;

        let mut synths: Vec<Box<dyn Synthesizer>> = Vec::with_capacity(ids.len());
        for id in ids {
            match make_synthesizer(id, nat64_prefix) {
                Some(s) => synths.push(s),
                None => anyhow::bail!(
                    "unknown synthesizer {id:?}; known ids: {}",
                    KNOWN_IDS.join(", ")
                ),
            }
        }

        Ok(Chain { synths, ttl_cap })
    }

    /// Synthesize AAAA records for an AAAA-NODATA name, or `None` if no
    /// Synthesizer produced any.
    pub async fn synthesize(
        &self,
        ctx: &SynthContext,
        pool: &Pool,
        metrics: &Metrics,
    ) -> Option<Vec<Record>> {
        let a_addrs = ctx.a_addrs();
        for synth in &self.synths {
            let Some(plan) = synth.detect(ctx) else {
                continue;
            };
            if let Some(records) = self.run_plan(&plan, &a_addrs, ctx, pool).await {
                metrics.synth_hit(synth.id());
                tracing::debug!(name = %ctx.name, synthesizer = synth.id(), "synthesized AAAA");
                return Some(records);
            }
        }
        None
    }

    /// Execute one plan: resolve its names, run `combine`, validate the result,
    /// and build TTL'd AAAA records. `None` if it produces nothing usable.
    async fn run_plan(
        &self,
        plan: &Plan,
        a_addrs: &[Ipv4Addr],
        ctx: &SynthContext,
        pool: &Pool,
    ) -> Option<Vec<Record>> {
        // Base TTL: the resolved reference record's TTL for lookup-based rules,
        // otherwise the A record TTL for embedding rules (DEFAULT as a floor).
        let mut base_ttl = ctx
            .a_records
            .iter()
            .map(|(_, t)| *t)
            .min()
            .unwrap_or(DEFAULT_SYNTH_TTL);

        let mut resolved: Vec<Ipv6Addr> = Vec::new();
        let mut resolved_ttls: Vec<u32> = Vec::new();
        for name in &plan.resolve {
            for (v6, ttl) in resolve_aaaa(pool, name).await {
                resolved.push(v6);
                resolved_ttls.push(ttl);
            }
        }
        if let Some(min) = resolved_ttls.iter().copied().min() {
            base_ttl = min;
        }

        let out: Vec<Ipv6Addr> = (plan.combine)(&resolved, a_addrs)
            .into_iter()
            .filter(|ip| is_global_unicast_v6(*ip))
            .collect();
        if out.is_empty() {
            return None;
        }

        let ttl = capped_ttl(base_ttl, self.ttl_cap);
        Some(
            out.into_iter()
                .map(|v6| Record::from_rdata(ctx.name.clone(), ttl, RData::AAAA(AAAA(v6))))
                .collect(),
        )
    }
}

/// Resolve a name's AAAA records (address, TTL) through the pool. DO bit clear,
/// so the response cache applies to these internal reference lookups.
async fn resolve_aaaa(pool: &Pool, name: &Name) -> Vec<(Ipv6Addr, u32)> {
    let mut query = Query::query(name.clone(), RecordType::AAAA);
    query.set_query_class(DNSClass::IN);

    let mut msg = Message::new();
    msg.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(query);
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(false);
    msg.set_edns(edns);

    match pool.resolve(msg).await {
        Some(resp) if resp.response_code() == ResponseCode::NoError => extract_aaaa(&resp),
        _ => Vec::new(),
    }
}

fn extract_aaaa(resp: &DnsResponse) -> Vec<(Ipv6Addr, u32)> {
    resp.answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::AAAA(a) => Some((a.0, r.ttl())),
            _ => None,
        })
        .collect()
}

/// Cap a TTL if a cap is configured.
pub fn capped_ttl(ttl: u32, cap: Option<u32>) -> u32 {
    match cap {
        Some(c) => ttl.min(c),
        None => ttl,
    }
}

/// Whether a synthesized address is a sane global unicast IPv6 to serve. Filters
/// the unspecified/loopback/multicast/link-local/ULA junk a transform might emit.
fn is_global_unicast_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let first = ip.segments()[0];
    let link_local = (first & 0xffc0) == 0xfe80; // fe80::/10
    let unique_local = (first & 0xfe00) == 0xfc00; // fc00::/7
    !(link_local || unique_local)
}

// ---------------------------------------------------------------------------
// Registry + precedence validation
// ---------------------------------------------------------------------------

/// Every synthesizer id that may appear in config, for error messages and for
/// the metrics layer to resolve enabled ids to `&'static str` labels.
pub(crate) const KNOWN_IDS: &[&str] = &[
    "nat64",
    "fastly",
    "akamai",
    "cloudfront",
    "cloudflare",
    "shopify",
    "webflow",
    "s3",
    "oss",
    "alicdn",
    "oracleobjectstorage",
    "msedge",
    "edgecast",
    "limelight",
    "bunnycdn",
    "blazingcdn",
    "gcorecdn",
    "cachefly",
    "cdn77",
    "awsglb",
    "weebly",
    "sucuri",
    "netlify",
    "bearblog",
    "azurewebsites",
    "wpvip",
];

/// Construct a synthesizer by id. `None` for an unknown id.
fn make_synthesizer(id: &str, nat64_prefix: Ipv6Addr) -> Option<Box<dyn Synthesizer>> {
    match id {
        "nat64" => Some(Box::new(nat64::Nat64::new(nat64_prefix))),
        other => cdn::make(other),
    }
}

/// Hard precedence constraints: `(a, b)` means a more-specific Provider `a` must
/// run before the generic `b` it would otherwise be shadowed by (both share the
/// generic's IP space / hostname space).
const PRECEDES: &[(&str, &str)] = &[("shopify", "cloudflare"), ("webflow", "cloudflare")];

/// Validate the configured order: unknown ids are caught later in `build`; here
/// we enforce specific-before-generic and warn if `nat64` is not last.
fn validate_order(ids: &[String]) -> anyhow::Result<()> {
    let pos = |id: &str| ids.iter().position(|x| x == id);
    for (a, b) in PRECEDES {
        if let (Some(ia), Some(ib)) = (pos(a), pos(b)) {
            if ia > ib {
                anyhow::bail!(
                    "synthesizer order: {a:?} must precede {b:?} (a specific provider cannot \
                     follow the generic one that shadows it)"
                );
            }
        }
    }
    if let Some(p) = pos("nat64") {
        if p != ids.len() - 1 {
            tracing::warn!(
                "synthesizer order: \"nat64\" is not last; it is the intended fallback and \
                 anything after it can only run when NAT64 produced nothing"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers for Synthesizers (label + CIDR matching)
// ---------------------------------------------------------------------------

/// A name's labels, lowercased, root dropped: `www.Example.COM.` -> [www, example, com].
pub(crate) fn labels(name: &Name) -> Vec<String> {
    name.to_ascii()
        .trim_end_matches('.')
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_ascii_lowercase())
        .collect()
}

/// Whether `name`'s trailing labels equal `suffix` (already lowercase).
pub(crate) fn ends_with(name: &Name, suffix: &[&str]) -> bool {
    let l = labels(name);
    l.len() >= suffix.len()
        && l[l.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(a, b)| a == b)
}

/// Parse a (possibly non-FQDN) string into an absolute `Name`.
pub(crate) fn parse_name(s: &str) -> anyhow::Result<Name> {
    let s = s.trim_end_matches('.');
    Ok(Name::from_ascii(format!("{s}."))?)
}

/// Re-join labels (normal order) into an absolute `Name`.
pub(crate) fn name_from_labels(labels: &[String]) -> Option<Name> {
    Name::from_ascii(format!("{}.", labels.join("."))).ok()
}

/// Whether `ip` falls in `cidr` (e.g. "151.101.0.0/16"). Panics on a malformed
/// constant — callers pass only compile-time literals.
pub(crate) fn in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let (net, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let net: Ipv4Addr = net.parse().expect("valid CIDR network");
    let prefix: u32 = prefix.parse().expect("valid CIDR prefix");
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// Whether `ip` is in any of the given CIDRs.
pub(crate) fn in_any(ip: Ipv4Addr, cidrs: &[&str]) -> bool {
    cidrs.iter().any(|c| in_cidr(ip, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn labels_lowercases_and_drops_root() {
        assert_eq!(labels(&n("www.Example.COM.")), ["www", "example", "com"]);
    }

    #[test]
    fn ends_with_matches_suffix() {
        assert!(ends_with(&n("x.y.fastly.net."), &["fastly", "net"]));
        assert!(!ends_with(&n("x.fastlylb.net."), &["fastly", "net"]));
        assert!(!ends_with(&n("net."), &["fastly", "net"]));
    }

    #[test]
    fn cidr_matching() {
        assert!(in_cidr("151.101.1.140".parse().unwrap(), "151.101.0.0/16"));
        assert!(!in_cidr("151.102.1.140".parse().unwrap(), "151.101.0.0/16"));
        assert!(in_cidr(
            "185.199.108.1".parse().unwrap(),
            "185.199.108.0/22"
        ));
        assert!(in_any(
            "104.16.5.5".parse().unwrap(),
            &["162.159.128.0/17", "104.16.0.0/12"]
        ));
    }

    #[test]
    fn validate_order_rejects_shopify_after_cloudflare() {
        let ids = vec!["cloudflare".to_string(), "shopify".to_string()];
        assert!(validate_order(&ids).is_err());
    }

    #[test]
    fn validate_order_accepts_specific_first() {
        let ids = vec![
            "shopify".to_string(),
            "webflow".to_string(),
            "cloudflare".to_string(),
            "nat64".to_string(),
        ];
        assert!(validate_order(&ids).is_ok());
    }

    #[test]
    fn global_unicast_filter() {
        assert!(is_global_unicast_v6("2606:4700::1".parse().unwrap()));
        assert!(is_global_unicast_v6("64:ff9b::c000:221".parse().unwrap()));
        assert!(!is_global_unicast_v6("::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("fe80::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("fc00::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("ff02::1".parse().unwrap()));
    }
}
