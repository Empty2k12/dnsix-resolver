//! CDN Providers: Synthesizers that recognise a name as hosted on a specific CDN
//! that already serves over native IPv6, and yield that CDN's real IPv6 — no
//! NAT64 translator in the path. Ported from miyurusankalpa/IPv6-dns-server.
//!
//! Detection uses three signals (hostname/CNAME-target suffix, A-record IP range,
//! DNS authority) and four derivation methods (constant, borrow a reference
//! domain's live IPv6, rewrite into a dual-stack hostname and resolve it, or an
//! algorithmic transform of the A address). Per the freshness guard, borrow/resolve
//! lookups are live (cached) and a hardcoded constant — where a CDN has one — is
//! only a last-resort fallback, expressed in the `combine` closure.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::Name;

use super::{ends_with, in_any, in_cidr, labels, name_from_labels, parse_name};
use super::{Combine, Plan, SynthContext, Synthesizer};

/// Construct a CDN provider by id, or `None` if unknown.
pub(super) fn make(id: &str) -> Option<Box<dyn Synthesizer>> {
    Some(match id {
        // --- constant (with optional live reference for the freshness guard) ---
        "cloudflare" => Box::new(MatchConst {
            id: "cloudflare",
            suffixes: &[&["cdn", "cloudflare", "net"]],
            ranges: &[
                "104.16.0.0/12",
                "162.159.128.0/17",
                "216.198.53.0/24",  // zendesk
                "216.198.54.0/24",  // zendesk
                "141.193.213.0/24", // wpengine
                "94.247.142.0/24",  // servd
                "103.133.1.0/24",   // laravel cloud
            ],
            addr: "2606:4700::6810:bad",
            reference: Some("www.cloudflare.com"),
        }),
        "shopify" => Box::new(MatchConst {
            id: "shopify",
            suffixes: &[&["shopify", "com"], &["myshopify", "com"]],
            ranges: &[
                "23.227.37.0/24",
                "23.227.38.0/23",
                "23.227.60.0/24",
                "185.146.172.0/23",
            ],
            addr: "2620:127:f00f::",
            reference: None,
        }),
        "webflow" => Box::new(MatchConst {
            id: "webflow",
            suffixes: &[&["webflow", "com"]],
            ranges: &["198.202.211.0/24", "75.2.70.75/32", "99.83.190.102/32"],
            addr: "2620:cb:2000::1",
            reference: None,
        }),
        "weebly" => Box::new(MatchConst {
            id: "weebly",
            suffixes: &[&["weebly", "com"]],
            ranges: &["199.34.228.0/22"],
            addr: "2620:11c:1:e4::36",
            reference: None,
        }),

        // --- borrow a reference domain's live IPv6 ---
        "cloudfront" => Box::new(MatchBorrow {
            id: "cloudfront",
            suffixes: &[&["cloudfront", "net"]],
            ranges: CLOUDFRONT_RANGES,
            soa_admin: None,
            reference: "static.twitchcdn.net",
            fallback: None,
        }),
        "bunnycdn" => Box::new(MatchBorrow {
            id: "bunnycdn",
            suffixes: &[&["b-cdn", "net"]],
            ranges: &[],
            soa_admin: None,
            reference: "bunnyfonts.b-cdn.net",
            fallback: Some("2400:52e0:1e01::883:1"),
        }),
        "blazingcdn" => Box::new(MatchBorrow {
            id: "blazingcdn",
            suffixes: &[&["blazingcdn", "net"]],
            ranges: &[],
            soa_admin: None,
            reference: "cdn59455242.blazingcdn.net",
            fallback: Some("2a02:b48:9000::1"),
        }),
        "gcorecdn" => Box::new(MatchBorrow {
            id: "gcorecdn",
            suffixes: &[&["gcdn", "co"]],
            ranges: &[],
            soa_admin: None,
            reference: "d.gcdn.co",
            fallback: None,
        }),
        "cdn77" => Box::new(MatchBorrow {
            id: "cdn77",
            suffixes: &[&["cdn77", "org"]],
            ranges: &[],
            soa_admin: Some("admin.cdn77.com"),
            reference: "www.cdn77.com",
            fallback: None,
        }),
        "sucuri" => Box::new(MatchBorrow {
            id: "sucuri",
            suffixes: &[],
            ranges: &["192.124.249.0/24"],
            soa_admin: None,
            reference: "sucuri.net",
            fallback: None,
        }),
        "netlify" => Box::new(MatchBorrow {
            id: "netlify",
            suffixes: &[&["netlify", "com"]],
            ranges: &["75.2.60.5/32", "99.83.231.61/32"],
            soa_admin: None,
            reference: "www.netlify.com",
            fallback: None,
        }),
        "bearblog" => Box::new(MatchBorrow {
            id: "bearblog",
            suffixes: &[],
            ranges: &["159.223.204.176/32"],
            soa_admin: None,
            reference: "domain-proxy.bearblog.dev",
            fallback: None,
        }),
        "alicdn" => Box::new(MatchBorrow {
            id: "alicdn",
            suffixes: &[&["alicdn", "com"]],
            ranges: &[],
            soa_admin: None,
            reference: "t.alicdn.com",
            fallback: None,
        }),

        // --- rewrite hostname into a dual-stack variant, then resolve ---
        "akamai" => Box::new(MatchRewrite {
            id: "akamai",
            rewrite: akamai_rewrite,
        }),
        "s3" => Box::new(MatchRewrite {
            id: "s3",
            rewrite: s3_rewrite,
        }),
        "oss" => Box::new(MatchRewrite {
            id: "oss",
            rewrite: oss_rewrite,
        }),
        "oracleobjectstorage" => Box::new(MatchRewrite {
            id: "oracleobjectstorage",
            rewrite: oracle_rewrite,
        }),
        "awsglb" => Box::new(MatchRewrite {
            id: "awsglb",
            rewrite: awsglb_rewrite,
        }),
        "edgecast" => Box::new(MatchRewrite {
            id: "edgecast",
            rewrite: edgecast_rewrite,
        }),
        "limelight" => Box::new(MatchRewrite {
            id: "limelight",
            rewrite: limelight_rewrite,
        }),
        "azurewebsites" => Box::new(MatchRewrite {
            id: "azurewebsites",
            rewrite: azure_rewrite,
        }),

        // --- custom ---
        "fastly" => Box::new(Fastly),
        "msedge" => Box::new(Msedge),
        "wpvip" => Box::new(Wpvip),
        "cachefly" => Box::new(Cachefly),

        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Shared detection + combine helpers
// ---------------------------------------------------------------------------

fn host_matches(ctx: &SynthContext, suffixes: &[&[&str]]) -> bool {
    ctx.hostnames()
        .iter()
        .any(|h| suffixes.iter().any(|s| ends_with(h, s)))
}

fn ip_matches(ctx: &SynthContext, ranges: &[&str]) -> bool {
    !ranges.is_empty() && ctx.a_records.iter().any(|(ip, _)| in_any(*ip, ranges))
}

fn soa_admin_is(ctx: &SynthContext, admin: &str) -> bool {
    let want = format!("{}.", admin.trim_end_matches('.'));
    ctx.authority
        .soa_admin
        .as_ref()
        .is_some_and(|n| n.to_ascii().eq_ignore_ascii_case(&want))
}

fn fqdn(s: &str) -> Name {
    parse_name(s).expect("valid constant domain")
}

fn verbatim() -> Combine {
    Box::new(|resolved, _| resolved.to_vec())
}

fn borrow_or(fallback: Option<Ipv6Addr>) -> Combine {
    Box::new(move |resolved, _| {
        if resolved.is_empty() {
            fallback.into_iter().collect()
        } else {
            resolved.to_vec()
        }
    })
}

// ---------------------------------------------------------------------------
// Generic provider shapes
// ---------------------------------------------------------------------------

/// A Provider that yields a constant IPv6, optionally backed by a live reference
/// domain (resolved first; the constant is the fallback when the lookup fails).
struct MatchConst {
    id: &'static str,
    suffixes: &'static [&'static [&'static str]],
    ranges: &'static [&'static str],
    addr: &'static str,
    reference: Option<&'static str>,
}

impl Synthesizer for MatchConst {
    fn id(&self) -> &'static str {
        self.id
    }
    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        if !(host_matches(ctx, self.suffixes) || ip_matches(ctx, self.ranges)) {
            return None;
        }
        let addr: Ipv6Addr = self.addr.parse().expect("valid constant address");
        Some(match self.reference {
            Some(r) => Plan {
                resolve: vec![fqdn(r)],
                combine: borrow_or(Some(addr)),
            },
            None => Plan::pure(Box::new(move |_, _| vec![addr])),
        })
    }
}

/// A Provider that borrows a reference domain's live IPv6, with an optional
/// constant fallback.
struct MatchBorrow {
    id: &'static str,
    suffixes: &'static [&'static [&'static str]],
    ranges: &'static [&'static str],
    soa_admin: Option<&'static str>,
    reference: &'static str,
    fallback: Option<&'static str>,
}

impl Synthesizer for MatchBorrow {
    fn id(&self) -> &'static str {
        self.id
    }
    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        let soa = self.soa_admin.is_some_and(|a| soa_admin_is(ctx, a));
        if !(soa || host_matches(ctx, self.suffixes) || ip_matches(ctx, self.ranges)) {
            return None;
        }
        let fallback = self
            .fallback
            .map(|f| f.parse().expect("valid fallback address"));
        Some(Plan {
            resolve: vec![fqdn(self.reference)],
            combine: borrow_or(fallback),
        })
    }
}

/// A Provider that rewrites a matched hostname into a dual-stack hostname and
/// borrows that name's live IPv6.
struct MatchRewrite {
    id: &'static str,
    rewrite: fn(&Name) -> Option<Name>,
}

impl Synthesizer for MatchRewrite {
    fn id(&self) -> &'static str {
        self.id
    }
    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        for h in ctx.hostnames() {
            if let Some(target) = (self.rewrite)(h) {
                return Some(Plan {
                    resolve: vec![target],
                    combine: verbatim(),
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Hostname rewrites
// ---------------------------------------------------------------------------

/// Akamai: `eXXX.akamaiedge.net` -> `dscXXX.akamaiedge.net` (or `dsXXX` when the
/// third-from-last label is `cj`).
fn akamai_rewrite(name: &Name) -> Option<Name> {
    let mut l = labels(name);
    let n = l.len();
    if n < 3 || l[n - 1] != "net" || !(l[n - 2] == "akamaiedge" || l[n - 2] == "akamai") {
        return None;
    }
    let lab = &l[n - 3];
    l[n - 3] = if lab == "cj" {
        format!("ds{lab}")
    } else {
        format!("dsc{lab}")
    };
    name_from_labels(&l)
}

/// AWS Global Accelerator: insert `dualstack` before the `awsglobalaccelerator` label.
fn awsglb_rewrite(name: &Name) -> Option<Name> {
    let mut l = labels(name);
    let n = l.len();
    if n < 2 || l[n - 1] != "com" || l[n - 2] != "awsglobalaccelerator" {
        return None;
    }
    if n >= 3 && l[n - 3] == "dualstack" {
        return name_from_labels(&l);
    }
    l.insert(n - 2, "dualstack".to_string());
    name_from_labels(&l)
}

/// Edgecast/Windows (`*.v0cdn.net`): set the leftmost-of-four label to `cs21`.
fn edgecast_rewrite(name: &Name) -> Option<Name> {
    let mut l = labels(name);
    let n = l.len();
    if n < 4 || l[n - 1] != "net" || l[n - 2] != "v0cdn" {
        return None;
    }
    l[n - 4] = "cs21".to_string();
    name_from_labels(&l)
}

/// Limelight (`*.llnwi.net`): set the leftmost-of-four label to `msftstore`.
fn limelight_rewrite(name: &Name) -> Option<Name> {
    let mut l = labels(name);
    let n = l.len();
    if n < 4 || l[n - 1] != "net" || l[n - 2] != "llnwi" {
        return None;
    }
    l[n - 4] = "msftstore".to_string();
    name_from_labels(&l)
}

/// Azure Websites: a CNAME target `*.azurewebsites.windows.net` -> set the
/// leftmost-of-four label to `sip-v4andv6`.
fn azure_rewrite(name: &Name) -> Option<Name> {
    let mut l = labels(name);
    let n = l.len();
    if n < 4 || l[n - 1] != "net" || l[n - 2] != "windows" || l[n - 3] != "azurewebsites" {
        return None;
    }
    l[n - 4] = "sip-v4andv6".to_string();
    name_from_labels(&l)
}

/// CacheFly hostname: `vipN.<mid>.cachefly.net` -> `rvipN-dstack.<mid>.cachefly.net`.
fn cachefly_rewrite(name: &Name) -> Option<Name> {
    let l = labels(name);
    let n = l.len();
    if n < 4 || l[n - 2] != "cachefly" || l[n - 1] != "net" {
        return None;
    }
    let first = &l[0];
    if !is_vip_label(first) {
        return None;
    }
    let first = if first.starts_with("vip") {
        format!("r{first}")
    } else {
        first.clone()
    };
    let mut middle = l[1..n - 2].join(".");
    if middle.is_empty() {
        return None;
    }
    if middle == "g-anycast1" {
        middle = "g".to_string();
    }
    parse_name(&format!("{first}-dstack.{middle}.cachefly.net")).ok()
}

/// `^r?vip\d+$`
fn is_vip_label(s: &str) -> bool {
    let s = s.strip_prefix('r').unwrap_or(s);
    s.strip_prefix("vip")
        .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
}

/// AWS S3: rewrite various S3 endpoint forms into their `dualstack` equivalent.
/// A faithful port of the upstream reversed-label algorithm (see tests/s3.js).
fn s3_rewrite(name: &Name) -> Option<Name> {
    let mut s = labels(name);
    s.reverse();
    let idx = |v: &[String], t: &str| {
        v.iter()
            .position(|x| x == t)
            .map(|p| p as isize)
            .unwrap_or(-1)
    };

    let mut dp1 = idx(&s, "cn");
    if dp1 == 0 {
        s.remove(0);
    }
    let dp2 = idx(&s, "amazonaws");
    let dpff = idx(&s, "dualstack");
    if dpff == 3 && dp2 == 1 {
        return None;
    }
    let dp3 = idx(&s, "s3");
    let dp4 = idx(&s, "s3-control");
    let dp6 = idx(&s, "s3-accelerate");
    let dp7 = idx(&s, "s3-accesspoint");
    let dp8 = idx(&s, "s3-website");
    let dp9 = idx(&s, "console-l");

    if !(dp2 == 1 && s.len() > 2) {
        return None;
    }

    let ssdomains: Vec<String> = s[2].split('-').map(String::from).collect();
    if s.len() == 5 {
        let v = s[4].clone();
        s.push(v);
    }

    if dp6 == 2 {
        splice_insert(&mut s, 2, "dualstack");
        dp1 = -1;
    } else if dp7 == 3 {
        splice_remove(&mut s, 4);
    } else if dp8 == 3 {
        splice_remove(&mut s, 4);
        dp1 = -1;
    } else if dp9 == 2 {
        return None;
    } else if ssdomains[0] == "s3" && (ssdomains.len() == 3 || ssdomains.len() == 2) && dp1 != 0 {
        splice_insert(&mut s, 2, "us-east-1");
        if ssdomains.get(1).map(String::as_str) == Some("1") {
            s[3] = "s3-r-w".to_string();
        }
    } else if dp3 == 3 || dp4 == 3 {
        splice_remove(&mut s, 4);
    } else if ssdomains[0] == "s3" && ssdomains.get(1).map(String::as_str) == Some("website") {
        splice_replace(&mut s, 2, "us-east-1");
        splice_replace(&mut s, 3, "s3-website");
    } else if ssdomains.len() > 1 {
        if ssdomains[0] != "s3" {
            return None;
        }
        splice_remove(&mut s, 2);
        let mut region: Vec<String> = ssdomains.clone();
        if region.len() == 4 && dp1 != 0 {
            region.remove(0);
        }
        splice_insert(&mut s, 2, &region.join("-"));
        if dp3 == -1 {
            splice_insert(&mut s, 3, "s3");
        }
    } else if dp2 == 1 && dp3 == 2 && dp1 != 0 {
        splice_insert(&mut s, 2, "us-east-1");
    } else {
        return None;
    }

    if s.get(2).map(String::as_str) != Some("dualstack") {
        splice_insert(&mut s, 3, "dualstack");
    }
    if dp1 == 0 {
        splice_insert(&mut s, 0, "cn");
    }
    s.reverse();
    name_from_labels(&s)
}

/// Alibaba OSS: rewrite `*.aliyuncs.com` / `*.aliyun-inc.com` endpoints into the
/// region-prefixed `*.oss.aliyuncs.com` form. Faithful port (see tests/oss.js).
fn oss_rewrite(name: &Name) -> Option<Name> {
    let mut s = labels(name);
    s.reverse();
    let idx = |v: &[String], t: &str| {
        v.iter()
            .position(|x| x == t)
            .map(|p| p as isize)
            .unwrap_or(-1)
    };

    let dp0 = idx(&s, "com");
    let dp1 = idx(&s, "aliyuncs");
    let dp2 = idx(&s, "aliyun-inc");
    if dp2 == 1 {
        s[1] = "aliyuncs".to_string();
    }
    if !(dp0 == 0 && (dp1 == 1 || dp2 == 1)) {
        return None;
    }

    let dpff1 = idx(&s, "oss");
    let mut ssdomains: Vec<String> = s[2].split('-').map(String::from).collect();
    let mut ssdoaminloc = 2usize;
    if dpff1 == 2 && ssdomains.iter().position(|x| x == "oss") == Some(0) && s.get(3).is_some() {
        ssdomains = s[3].split('-').map(String::from).collect();
        ssdoaminloc = 3;
    }
    let dpff3 = ssdomains
        .iter()
        .position(|x| x == "oss")
        .map(|p| p as isize)
        .unwrap_or(-1);

    if s.len() == 4 && dpff1 < 0 {
        splice_remove(&mut s, 3);
    }
    if dpff3 == 0 {
        ssdomains.remove(0);
    }
    let isbucket = OSS_REGIONS.contains(&ssdomains.join("-").as_str());
    if dpff1 == 2 && !isbucket {
        set_ext(&mut ssdomains, 0, "cn");
        set_ext(&mut ssdomains, 1, "hangzhou");
    }
    if !ssdomains.is_empty() {
        // ssdoaminloc may be 3, which can be past the end after a removal above;
        // the upstream relies on it still being in range, so guard.
        if ssdoaminloc < s.len() {
            s[ssdoaminloc] = ssdomains.join("-");
        } else {
            s.push(ssdomains.join("-"));
        }
    } else {
        splice_remove(&mut s, 2);
    }
    if dpff3 == 0 {
        splice_insert(&mut s, 2, "oss");
    }
    s.reverse();
    name_from_labels(&s)
}

/// Oracle Object Storage: rewrite native / S3-compatible / Swift / legacy
/// endpoints into their `ds` dual-stack form. Faithful port (see tests/oracleobjectstorage.js).
fn oracle_rewrite(name: &Name) -> Option<Name> {
    let l = labels(name);
    let n = l.len();
    let (suffix, suffix_oraclecloud): (&[&str], bool) =
        if n >= 2 && l[n - 2] == "oraclecloud" && l[n - 1] == "com" {
            (&["oraclecloud", "com"], true)
        } else if n >= 3 && l[n - 3] == "oci" && l[n - 2] == "customer-oci" && l[n - 1] == "com" {
            (&["oci", "customer-oci", "com"], false)
        } else {
            return None;
        };

    let mut body: Vec<&str> = l[..n - suffix.len()].iter().map(String::as_str).collect();
    if body.len() < 2 {
        return None;
    }
    let ds_enabled = *body.last().unwrap() == "ds";
    if ds_enabled {
        body.pop();
    }

    let mut namespace: Option<&str> = None;
    let mut is_compat = false;
    let service;
    let region;
    if body.len() == 2 && (body[0] == "objectstorage" || body[0] == "swiftobjectstorage") {
        service = body[0];
        region = body[1];
    } else if body.len() == 3 && body[0] == "compat" && body[1] == "objectstorage" {
        return parse_name(&format!(
            "objectstorage.{}.ds.oci.customer-oci.com",
            body[2]
        ))
        .ok();
    } else if body.len() == 3 && (body[1] == "objectstorage" || body[1] == "swiftobjectstorage") {
        namespace = Some(body[0]);
        service = body[1];
        region = body[2];
    } else if body.len() == 4 && body[1] == "compat" && body[2] == "objectstorage" {
        namespace = Some(body[0]);
        is_compat = true;
        service = body[2];
        region = body[3];
    } else {
        return None;
    }

    let output_suffix: &[&str] = if suffix_oraclecloud && !ds_enabled {
        &["oci", "customer-oci", "com"]
    } else {
        suffix
    };

    let mut out: Vec<&str> = Vec::new();
    if let Some(ns) = namespace {
        out.push(ns);
    }
    if is_compat {
        out.push("compat");
    }
    out.push(service);
    out.push(region);
    out.push("ds");
    out.extend_from_slice(output_suffix);
    parse_name(&out.join(".")).ok()
}

// JS Array.splice helpers (insert / remove with JS out-of-range tolerance).
fn splice_insert(v: &mut Vec<String>, i: usize, val: &str) {
    let i = i.min(v.len());
    v.insert(i, val.to_string());
}
fn splice_remove(v: &mut Vec<String>, i: usize) {
    if i < v.len() {
        v.remove(i);
    }
}
/// JS `splice(i, 1, val)`: replace element `i`, or append when `i == len`.
fn splice_replace(v: &mut Vec<String>, i: usize, val: &str) {
    if i < v.len() {
        v[i] = val.to_string();
    } else {
        v.insert(i.min(v.len()), val.to_string());
    }
}
fn set_ext(v: &mut Vec<String>, i: usize, val: &str) {
    while v.len() <= i {
        v.push(String::new());
    }
    v[i] = val.to_string();
}

// ---------------------------------------------------------------------------
// Custom providers
// ---------------------------------------------------------------------------

/// Fastly: hostname path rewrites to `dualstack.<host>` and resolves it; the
/// IP/authority path borrows a Fastly dual-stack reference domain's prefixes and
/// fuses each with a host id derived from the original A address.
struct Fastly;

const FASTLY_RANGES: &[&str] = &["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/17"];
const FASTLY_REF: &str = "dualstack.g.shared.global.fastly.net";
const GITHUB_PAGES_RANGE: &str = "185.199.108.0/22";
const GITHUB_PAGES_REF: &str = "dualstack.github.io";

/// Fastly host-id from the A address. github uses the last octet; otherwise
/// `(octet3 % 4) * 256 + octet4`. (Upstream's `octet0 === 151` branch is dead —
/// it compares a string to a number — so the else branch is the real one.)
fn fastly_v6hex(ip: Ipv4Addr, github: bool) -> u32 {
    let o = ip.octets();
    if github {
        o[3] as u32
    } else {
        (o[2] as u32 % 4) * 256 + o[3] as u32
    }
}

/// Reproduce the upstream behaviour of appending the host-id's *decimal digits*
/// into the IPv6 text (so they are read as hex), placing them in the low 16 bits
/// of the borrowed prefix. `None` if they don't fit 16 bits.
fn fastly_fuse(prefix: Ipv6Addr, hostid: u32) -> Option<Ipv6Addr> {
    let seg = u16::from_str_radix(&hostid.to_string(), 16).ok()?;
    let mut segs = prefix.segments();
    segs[7] = seg;
    Some(Ipv6Addr::from(segs))
}

impl Synthesizer for Fastly {
    fn id(&self) -> &'static str {
        "fastly"
    }
    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        let v4 = ctx.a_addrs();
        let fastly_ip = v4.iter().any(|ip| in_any(*ip, FASTLY_RANGES));
        let github_ip = v4
            .iter()
            .find(|ip| in_cidr(**ip, GITHUB_PAGES_RANGE))
            .copied();

        // IP / authority path: borrow a reference prefix and fuse the host id.
        if soa_admin_is(ctx, "hostmaster.fastly.com") || fastly_ip {
            let chosen = v4
                .iter()
                .find(|ip| in_any(**ip, FASTLY_RANGES))
                .copied()
                .or_else(|| v4.first().copied());
            if let Some(ip) = chosen {
                let hostid = fastly_v6hex(ip, false);
                return Some(Plan {
                    resolve: vec![fqdn(FASTLY_REF)],
                    combine: Box::new(move |resolved, _| {
                        resolved
                            .iter()
                            .filter_map(|p| fastly_fuse(*p, hostid))
                            .collect()
                    }),
                });
            }
        }
        if let Some(ip) = github_ip {
            let hostid = fastly_v6hex(ip, true);
            return Some(Plan {
                resolve: vec![fqdn(GITHUB_PAGES_REF)],
                combine: Box::new(move |resolved, _| {
                    resolved
                        .iter()
                        .filter_map(|p| fastly_fuse(*p, hostid))
                        .collect()
                }),
            });
        }

        // Hostname path: dualstack.<host>.
        for h in ctx.hostnames() {
            if ends_with(h, &["fastly", "net"]) || ends_with(h, &["fastlylb", "net"]) {
                let mut l = labels(h);
                l.insert(0, "dualstack".to_string());
                if let Some(target) = name_from_labels(&l) {
                    return Some(Plan {
                        resolve: vec![target],
                        combine: verbatim(),
                    });
                }
            }
        }
        None
    }
}

/// Microsoft Edge: matched by an SOA zone under `*.msedge.net`; the IPv6 prefix
/// is chosen by the leading letter of the edge hostname, with the A address's
/// last octet appended.
struct Msedge;

fn msedge_prefix(letter: &str) -> Option<(&'static str, bool)> {
    Some(match letter {
        "a" => ("2620:1ec:c11::", false),
        "b" => ("2620:1ec:a92::", false),
        "c" => ("2a01:111:2003::", false),
        "l" => ("2620:1ec:21::", false),
        "s" => ("2620:1ec:6::", false),
        "k" => ("2620:1ec:c::", false),
        "t" => ("2620:1ec:bdf::", false),
        "spo" => ("2620:1ec:8f8::", true),
        _ => return None,
    })
}

impl Synthesizer for Msedge {
    fn id(&self) -> &'static str {
        "msedge"
    }
    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        let zone = ctx.authority.soa_zone.as_ref()?;
        if !zone.to_ascii().to_ascii_lowercase().contains("msedge.net") {
            return None;
        }
        // The msedge edge hostname is the deepest CNAME target, else the name.
        let host = ctx.cname_targets.last().unwrap_or(&ctx.name);
        let l = labels(host);
        let letter = l.first()?.split('-').next()?.to_string();
        let (prefix, spo) = msedge_prefix(&letter)?;
        Some(Plan::pure(Box::new(move |_, v4| {
            v4.iter()
                .filter_map(|ip| {
                    let mut o3 = ip.octets()[3];
                    if spo && o3 == 9 {
                        o3 = 8;
                    }
                    format!("{prefix}{o3}").parse().ok()
                })
                .collect()
        })))
    }
}

/// WordPress VIP: algorithmic embed of the A address into `2a04:fa87:fffd::/48`.
struct Wpvip;

const WPVIP_RANGE: &str = "192.0.66.0/24";

impl Synthesizer for Wpvip {
    fn id(&self) -> &'static str {
        "wpvip"
    }
    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        if !ctx
            .a_records
            .iter()
            .any(|(ip, _)| in_cidr(*ip, WPVIP_RANGE))
        {
            return None;
        }
        Some(Plan::pure(Box::new(|_, v4| {
            v4.iter()
                .filter(|ip| in_cidr(**ip, WPVIP_RANGE))
                .filter_map(|ip| {
                    let o = ip.octets();
                    format!(
                        "2a04:fa87:fffd::{:02x}{:02x}:{:02x}{:02x}",
                        o[0], o[1], o[2], o[3]
                    )
                    .parse()
                    .ok()
                })
                .collect()
        })))
    }
}

/// CacheFly: hostname path rewrites to a `-dstack` variant and resolves it; the
/// IP path embeds the A address into `2605:4c40::/32`.
struct Cachefly;

const CACHEFLY_RANGE: &str = "205.234.175.0/24";

fn cachefly_v4to6(ip: Ipv4Addr) -> Option<Ipv6Addr> {
    let o = ip.octets();
    format!("2605:4c40::{}:{}", o[2], o[3]).parse().ok()
}

impl Synthesizer for Cachefly {
    fn id(&self) -> &'static str {
        "cachefly"
    }
    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        for h in ctx.hostnames() {
            if let Some(target) = cachefly_rewrite(h) {
                return Some(Plan {
                    resolve: vec![target],
                    combine: verbatim(),
                });
            }
        }
        if ctx
            .a_records
            .iter()
            .any(|(ip, _)| in_cidr(*ip, CACHEFLY_RANGE))
        {
            return Some(Plan::pure(Box::new(|_, v4| {
                v4.iter()
                    .filter(|ip| in_cidr(**ip, CACHEFLY_RANGE))
                    .filter_map(|ip| cachefly_v4to6(*ip))
                    .collect()
            })));
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Static data
// ---------------------------------------------------------------------------

const OSS_REGIONS: &[&str] = &[
    "cn-hangzhou",
    "cn-shanghai",
    "cn-nanjing",
    "cn-qingdao",
    "cn-beijing",
    "cn-zhangjiakou",
    "cn-huhehaote",
    "cn-wulanchabu",
    "cn-shenzhen",
    "cn-heyuan",
    "cn-guangzhou",
    "cn-chengdu",
    "cn-hongkong",
    "us-west-1",
    "us-east-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ap-southeast-6",
    "ap-southeast-7",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "eu-central-1",
    "eu-west-1",
    "me-east-1",
    "me-central-1",
    "cn-hangzhou-finance",
    "cn-shanghai-finance",
    "cn-shenzhen-finance",
    "cn-beijing-finance-1",
    "cn-beijing-finance-2",
];

/// CloudFront global + regional edge IPv4 ranges (from list-cloudfront-ips).
const CLOUDFRONT_RANGES: &[&str] = &[
    "120.52.22.96/27",
    "205.251.249.0/24",
    "180.163.57.128/26",
    "204.246.168.0/22",
    "111.13.171.128/26",
    "18.160.0.0/15",
    "205.251.252.0/23",
    "54.192.0.0/16",
    "204.246.173.0/24",
    "54.230.200.0/21",
    "120.253.240.192/26",
    "116.129.226.128/26",
    "130.176.0.0/17",
    "108.156.0.0/14",
    "99.86.0.0/16",
    "13.32.0.0/15",
    "120.253.245.128/26",
    "13.224.0.0/14",
    "70.132.0.0/18",
    "15.158.0.0/16",
    "111.13.171.192/26",
    "13.249.0.0/16",
    "18.238.0.0/15",
    "18.244.0.0/15",
    "205.251.208.0/20",
    "65.9.128.0/18",
    "130.176.128.0/18",
    "58.254.138.0/25",
    "205.251.201.0/24",
    "205.251.206.0/23",
    "54.230.208.0/20",
    "3.160.0.0/14",
    "116.129.226.0/25",
    "52.222.128.0/17",
    "18.164.0.0/15",
    "111.13.185.32/27",
    "64.252.128.0/18",
    "205.251.254.0/24",
    "54.230.224.0/19",
    "71.152.0.0/17",
    "216.137.32.0/19",
    "204.246.172.0/24",
    "205.251.202.0/23",
    "18.172.0.0/15",
    "120.52.39.128/27",
    "118.193.97.64/26",
    "3.164.64.0/18",
    "18.154.0.0/15",
    "54.240.128.0/18",
    "205.251.250.0/23",
    "180.163.57.0/25",
    "52.46.0.0/18",
    "52.82.128.0/19",
    "54.230.0.0/17",
    "54.230.128.0/18",
    "54.239.128.0/18",
    "130.176.224.0/20",
    "36.103.232.128/26",
    "52.84.0.0/15",
    "143.204.0.0/16",
    "144.220.0.0/16",
    "120.52.153.192/26",
    "119.147.182.0/25",
    "120.232.236.0/25",
    "111.13.185.64/27",
    "3.164.0.0/18",
    "54.182.0.0/16",
    "58.254.138.128/26",
    "120.253.245.192/27",
    "54.239.192.0/19",
    "18.68.0.0/16",
    "18.64.0.0/14",
    "120.52.12.64/26",
    "99.84.0.0/16",
    "205.251.204.0/23",
    "130.176.192.0/19",
    "52.124.128.0/17",
    "205.251.200.0/24",
    "204.246.164.0/22",
    "13.35.0.0/16",
    "204.246.174.0/23",
    "3.164.128.0/17",
    "3.172.0.0/18",
    "36.103.232.0/25",
    "119.147.182.128/26",
    "118.193.97.128/25",
    "120.232.236.128/26",
    "204.246.176.0/20",
    "65.8.0.0/16",
    "65.9.0.0/17",
    "108.138.0.0/15",
    "120.253.241.160/27",
    "64.252.64.0/18",
    // regional edge
    "13.113.196.64/26",
    "13.113.203.0/24",
    "52.199.127.192/26",
    "13.124.199.0/24",
    "3.35.130.128/25",
    "52.78.247.128/26",
    "13.233.177.192/26",
    "15.207.13.128/25",
    "15.207.213.128/25",
    "52.66.194.128/26",
    "13.228.69.0/24",
    "52.220.191.0/26",
    "13.210.67.128/26",
    "13.54.63.128/26",
    "43.218.56.128/26",
    "43.218.56.192/26",
    "43.218.56.64/26",
    "43.218.71.0/26",
    "99.79.169.0/24",
    "18.192.142.0/23",
    "35.158.136.0/24",
    "52.57.254.0/24",
    "13.48.32.0/24",
    "18.200.212.0/23",
    "52.212.248.0/26",
    "3.10.17.128/25",
    "3.11.53.0/24",
    "52.56.127.0/25",
    "15.188.184.0/24",
    "52.47.139.0/24",
    "3.29.40.128/26",
    "3.29.40.192/26",
    "3.29.40.64/26",
    "3.29.57.0/26",
    "18.229.220.192/26",
    "54.233.255.128/26",
    "3.231.2.0/25",
    "3.234.232.224/27",
    "3.236.169.192/26",
    "3.236.48.0/23",
    "34.195.252.0/24",
    "34.226.14.0/24",
    "13.59.250.0/26",
    "18.216.170.128/25",
    "3.128.93.0/24",
    "3.134.215.0/24",
    "52.15.127.128/26",
    "3.101.158.0/23",
    "52.52.191.128/26",
    "34.216.51.0/25",
    "34.223.12.224/27",
    "34.223.80.192/26",
    "35.162.63.192/26",
    "35.167.191.128/26",
    "44.227.178.0/24",
    "44.234.108.128/25",
    "44.234.90.252/30",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn rw(f: fn(&Name) -> Option<Name>, s: &str) -> Option<String> {
        f(&Name::from_str(&format!("{s}.")).unwrap())
            .map(|n| n.to_ascii().trim_end_matches('.').to_string())
    }

    #[test]
    fn akamai() {
        assert_eq!(
            rw(akamai_rewrite, "e123.akamaiedge.net").unwrap(),
            "dsce123.akamaiedge.net"
        );
        assert_eq!(
            rw(akamai_rewrite, "cj.akamai.net").unwrap(),
            "dscj.akamai.net"
        );
        assert!(rw(akamai_rewrite, "www.example.com").is_none());
    }

    #[test]
    fn awsglb() {
        assert_eq!(
            rw(awsglb_rewrite, "abc.awsglobalaccelerator.com").unwrap(),
            "abc.dualstack.awsglobalaccelerator.com"
        );
    }

    #[test]
    fn edgecast_limelight_azure() {
        assert_eq!(
            rw(edgecast_rewrite, "foo.bar.v0cdn.net").unwrap(),
            "cs21.bar.v0cdn.net"
        );
        assert_eq!(
            rw(limelight_rewrite, "a.b.llnwi.net").unwrap(),
            "msftstore.b.llnwi.net"
        );
        assert_eq!(
            rw(azure_rewrite, "site.azurewebsites.windows.net").unwrap(),
            "sip-v4andv6.azurewebsites.windows.net"
        );
    }

    #[test]
    fn cachefly_hostname() {
        assert_eq!(
            rw(cachefly_rewrite, "rvip1.g.cachefly.net").unwrap(),
            "rvip1-dstack.g.cachefly.net"
        );
        assert_eq!(
            rw(cachefly_rewrite, "vip1.g-anycast1.cachefly.net").unwrap(),
            "rvip1-dstack.g.cachefly.net"
        );
        assert_eq!(
            rw(cachefly_rewrite, "rvip33.g.cachefly.net").unwrap(),
            "rvip33-dstack.g.cachefly.net"
        );
        assert_eq!(
            rw(cachefly_rewrite, "vip9.eu-west.cachefly.net").unwrap(),
            "rvip9-dstack.eu-west.cachefly.net"
        );
        assert!(rw(cachefly_rewrite, "cachefly.cachefly.net").is_none());
        assert!(rw(cachefly_rewrite, "www.cachefly.com").is_none());
    }

    #[test]
    fn cachefly_ip() {
        assert_eq!(
            cachefly_v4to6("205.234.175.136".parse().unwrap()).unwrap(),
            "2605:4c40::175:136".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn s3() {
        let cases = [
            ("s3.amazonaws.com", "s3.dualstack.us-east-1.amazonaws.com"),
            (
                "s3-1-w.amazonaws.com",
                "s3-r-w.dualstack.us-east-1.amazonaws.com",
            ),
            (
                "s3-r-w.amazonaws.com",
                "s3-r-w.dualstack.us-east-1.amazonaws.com",
            ),
            (
                "s3-w.amazonaws.com",
                "s3-w.dualstack.us-east-1.amazonaws.com",
            ),
            (
                "redditstatic.s3.amazonaws.com",
                "redditstatic.s3.dualstack.us-east-1.amazonaws.com",
            ),
            (
                "github-production-release-asset-2e65be.s3.amazonaws.com",
                "github-production-release-asset-2e65be.s3.dualstack.us-east-1.amazonaws.com",
            ),
            (
                "2020awsreinvent.s3-us-west-2.amazonaws.com",
                "2020awsreinvent.s3.dualstack.us-west-2.amazonaws.com",
            ),
            (
                "s3-accesspoint.us-east-2.amazonaws.com",
                "s3-accesspoint.dualstack.us-east-2.amazonaws.com",
            ),
            (
                "s3-accelerate-speedtest.s3-accelerate.amazonaws.com",
                "s3-accelerate-speedtest.s3-accelerate.dualstack.amazonaws.com",
            ),
            (
                "cheetah-test-us-east-1-02.s3-accelerate.amazonaws.com",
                "cheetah-test-us-east-1-02.s3-accelerate.dualstack.amazonaws.com",
            ),
            (
                "s3.eu-central-1.amazonaws.com",
                "s3.dualstack.eu-central-1.amazonaws.com",
            ),
            (
                "account-id.s3-control.eu-central-1.amazonaws.com",
                "account-id.s3-control.dualstack.eu-central-1.amazonaws.com",
            ),
            (
                "s3-accesspoint.eu-central-1.amazonaws.com",
                "s3-accesspoint.dualstack.eu-central-1.amazonaws.com",
            ),
            (
                "web.s3-accesspoint.eu-central-1.amazonaws.com",
                "web.s3-accesspoint.dualstack.eu-central-1.amazonaws.com",
            ),
            (
                "s3.cn-north-1.amazonaws.com.cn",
                "s3.dualstack.cn-north-1.amazonaws.com.cn",
            ),
            (
                "account-id.s3-control.cn-north-1.amazonaws.com.cn",
                "account-id.s3-control.dualstack.cn-north-1.amazonaws.com.cn",
            ),
            (
                "web.s3-accesspoint.cn-north-1.amazonaws.com.cn",
                "web.s3-accesspoint.dualstack.cn-north-1.amazonaws.com.cn",
            ),
            (
                "s3.ap-southeast-1.amazonaws.com",
                "s3.dualstack.ap-southeast-1.amazonaws.com",
            ),
            (
                "download.opencontent.netflix.com.s3.amazonaws.com",
                "download.opencontent.netflix.com.s3.dualstack.us-east-1.amazonaws.com",
            ),
            (
                "s3-website-us-east-1.amazonaws.com",
                "s3-website.dualstack.us-east-1.amazonaws.com",
            ),
            (
                "s3-website.ap-southeast-3.amazonaws.com",
                "s3-website.dualstack.ap-southeast-3.amazonaws.com",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(rw(s3_rewrite, input).as_deref(), Some(want), "s3 {input}");
        }
        for none in [
            "s3.dualstack.us-east-1.amazonaws.com",
            "download.opencontent.netflix.com.s3.dualstack.us-east-1.amazonaws.com",
            "s3.dualstack.cn-north-1.amazonaws.com.cn",
            "pub-web-4b45fc8aac32a800.elb.eu-central-1.amazonaws.com",
            "cdn.assets.as2.amazonaws.com",
            "dynamodb.us-east-2.amazonaws.com",
            "lbr-optimized.s3.console-l.amazonaws.com",
            "amazonaws.com",
        ] {
            assert_eq!(rw(s3_rewrite, none), None, "s3 none {none}");
        }
        // China regions have no dualstack endpoint for these forms: the result
        // must not be the naive dualstack-with-.cn rewrite (dp1 = -1 suppresses
        // re-adding the cn TLD).
        for (input, naive) in [
            (
                "2020awsreinvent.s3-us-west-2.amazonaws.com.cn",
                "2020awsreinvent.s3.dualstack.us-west-2.amazonaws.com.cn",
            ),
            (
                "s3-accelerate.amazonaws.com.cn",
                "s3-accelerate.dualstack.amazonaws.com.cn",
            ),
            (
                "s3-website.cn-northwest-1.amazonaws.com.cn",
                "s3-website.dualstack.cn-northwest-1.amazonaws.com.cn",
            ),
        ] {
            assert_ne!(
                rw(s3_rewrite, input).as_deref(),
                Some(naive),
                "s3 cn {input}"
            );
        }
    }

    #[test]
    fn oss() {
        let cases = [
            ("oss.aliyuncs.com", "cn-hangzhou.oss.aliyuncs.com"),
            (
                "examplebucket.oss.aliyuncs.com",
                "cn-hangzhou.oss.aliyuncs.com",
            ),
            (
                "example-bucket.oss.aliyuncs.com",
                "cn-hangzhou.oss.aliyuncs.com",
            ),
            (
                "oss-cn-hangzhou.aliyuncs.com",
                "cn-hangzhou.oss.aliyuncs.com",
            ),
            ("oss-cn-beijing.aliyuncs.com", "cn-beijing.oss.aliyuncs.com"),
            (
                "oss-ap-southeast-1.aliyuncs.com",
                "ap-southeast-1.oss.aliyuncs.com",
            ),
            (
                "oss-eu-central-1.aliyuncs.com",
                "eu-central-1.oss.aliyuncs.com",
            ),
            (
                "examplebucket.oss-cn-hangzhou.aliyuncs.com",
                "cn-hangzhou.oss.aliyuncs.com",
            ),
            (
                "examplebucket.cn-hangzhou.oss.aliyun-inc.com",
                "examplebucket.cn-hangzhou.oss.aliyuncs.com",
            ),
            (
                "examplebucket.ap-southeast-1.oss.aliyun-inc.com",
                "examplebucket.ap-southeast-1.oss.aliyuncs.com",
            ),
            (
                "cn-hangzhou.oss.aliyuncs.com",
                "cn-hangzhou.oss.aliyuncs.com",
            ),
            (
                "examplebucket.cn-hangzhou.oss.aliyuncs.com",
                "examplebucket.cn-hangzhou.oss.aliyuncs.com",
            ),
            (
                "examplebucket.eu-central-1.oss.aliyuncs.com",
                "examplebucket.eu-central-1.oss.aliyuncs.com",
            ),
            (
                "alicloud-common.oss-ap-southeast-1.aliyuncs.com",
                "ap-southeast-1.oss.aliyuncs.com",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(rw(oss_rewrite, input).as_deref(), Some(want), "oss {input}");
        }
    }

    #[test]
    fn oracle() {
        let cases = [
            (
                "objectstorage.us-ashburn-1.oci.customer-oci.com",
                "objectstorage.us-ashburn-1.ds.oci.customer-oci.com",
            ),
            (
                "adwc4pm.objectstorage.us-ashburn-1.oci.customer-oci.com",
                "adwc4pm.objectstorage.us-ashburn-1.ds.oci.customer-oci.com",
            ),
            (
                "objectstorage.us-phoenix-1.oraclecloud.com",
                "objectstorage.us-phoenix-1.ds.oci.customer-oci.com",
            ),
            (
                "objectstorage.us-phoenix-1.ds.oraclecloud.com",
                "objectstorage.us-phoenix-1.ds.oraclecloud.com",
            ),
            (
                "compat.objectstorage.ap-mumbai-1.oraclecloud.com",
                "objectstorage.ap-mumbai-1.ds.oci.customer-oci.com",
            ),
            (
                "bmkltsly13vb.compat.objectstorage.ap-mumbai-1.oraclecloud.com",
                "bmkltsly13vb.compat.objectstorage.ap-mumbai-1.ds.oci.customer-oci.com",
            ),
            (
                "namespace.compat.objectstorage.us-phoenix-1.oci.customer-oci.com",
                "namespace.compat.objectstorage.us-phoenix-1.ds.oci.customer-oci.com",
            ),
            (
                "swiftobjectstorage.us-ashburn-1.oci.customer-oci.com",
                "swiftobjectstorage.us-ashburn-1.ds.oci.customer-oci.com",
            ),
            (
                "namespace.swiftobjectstorage.us-ashburn-1.oci.customer-oci.com",
                "namespace.swiftobjectstorage.us-ashburn-1.ds.oci.customer-oci.com",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(
                rw(oracle_rewrite, input).as_deref(),
                Some(want),
                "oracle {input}"
            );
        }
        assert_eq!(rw(oracle_rewrite, "www.oracle.com"), None);
        assert_eq!(rw(oracle_rewrite, "oraclecloud.com"), None);
    }

    #[test]
    fn fastly_hostid() {
        assert_eq!(fastly_v6hex("151.101.1.140".parse().unwrap(), false), 396);
        assert_eq!(fastly_v6hex("199.232.192.204".parse().unwrap(), false), 204);
        assert_eq!(fastly_v6hex("199.232.39.52".parse().unwrap(), false), 820);
        assert_eq!(fastly_v6hex("146.75.43.7".parse().unwrap(), false), 775);
        assert_eq!(fastly_v6hex("146.75.93.188".parse().unwrap(), false), 444);
        assert_eq!(fastly_v6hex("185.199.111.133".parse().unwrap(), true), 133);
    }

    #[test]
    fn fastly_fuse_places_low_bits() {
        let p: Ipv6Addr = "2a04:4e42::".parse().unwrap();
        assert_eq!(
            fastly_fuse(p, 396).unwrap(),
            "2a04:4e42::396".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn wpvip_embed() {
        let s = Wpvip;
        let ctx = SynthContext {
            name: Name::from_str("wpvip.com.").unwrap(),
            cname_targets: vec![],
            a_records: vec![("192.0.66.5".parse().unwrap(), 300)],
            authority: Default::default(),
        };
        let plan = s.detect(&ctx).unwrap();
        let out = (plan.combine)(&[], &ctx.a_addrs());
        assert_eq!(
            out,
            vec!["2a04:fa87:fffd::c000:4205".parse::<Ipv6Addr>().unwrap()]
        );
    }
}
