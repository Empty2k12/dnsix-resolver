//! The optional local **Blocklist**: domains the Forwarder refuses to resolve,
//! answering them locally with NXDOMAIN instead of relaying upstream.
//!
//! This is the project's one filtering behaviour, and it is opt-in: with no
//! `blocklists` configured nothing here runs and the Forwarder filters nothing,
//! exactly as before (see docs/adr/0004-local-blocklist.md). It is **static**:
//! the lists are fetched **once at startup** and immutable thereafter; to change
//! them, restart.
//!
//! Two source syntaxes are understood: **hosts** (`0.0.0.0 name`) and **adblock**
//! (`||name^`), plus bare-domain lines. Adblock `@@` exception rules populate an
//! allowlist that wins over a block (so a curated list like Hagezi `pro` works as
//! its author intended). Anything we cannot represent (wildcards, regex,
//! `$`-modifiers) is skipped and counted. All sources merge into one deduplicated
//! block set and one allow set; matching is **domain-suffix** (a listed name
//! blocks itself and every subdomain).
//!
//! Fetching reaches IPv4-only list hosts from an IPv6-only box the same way the
//! Forwarder serves clients: resolve the host's A through the configured upstream
//! `Pool`, keep the globally-routable addresses, embed one into the NAT64 prefix,
//! and connect there over HTTPS with SNI set to the original hostname. A source
//! that fails to fetch is **fail-open**: the Forwarder starts without it and the
//! gap is reported, because a list-CDN outage must never take DNS resolution down.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Context;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::synth::{eligible_addresses, embed};
use crate::upstream::Pool;

/// Overall timeout for fetching one list (handshake + transfer).
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard cap on a fetched body, so a misbehaving host can't exhaust memory.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// How many HTTP redirects we follow before giving up.
const MAX_REDIRECTS: usize = 3;

/// Load status of one configured source, for the dashboard's Blocklists page.
pub enum SourceStatus {
    /// Fetched and parsed.
    Ok,
    /// Fetch or parse failed; the Forwarder started without this source.
    Failed(String),
}

/// Per-source parse accounting, surfaced read-only in the dashboard so an operator
/// can see "did my lists actually load?" (the fail-open mitigation).
pub struct SourceStat {
    pub url: String,
    pub status: SourceStatus,
    /// Block entries contributed by this source (pre-dedup across sources).
    pub blocks: usize,
    /// Allowlist (`@@`) exceptions contributed by this source.
    pub allows: usize,
    /// Lines we could not represent (wildcards, regex, `$`-modifiers).
    pub skipped: usize,
}

/// A loaded blocklist: a merged, deduplicated block set, an allow set that wins
/// over it, and per-source stats. Built once at startup by [`load`].
pub struct Blocklist {
    block: HashSet<String>,
    allow: HashSet<String>,
    sources: Vec<SourceStat>,
}

impl Blocklist {
    /// Whether `name` is blocked: some suffix of it is in the block set and no
    /// suffix is in the allow set (allow beats block). Cheap on the hot path: a
    /// couple of set lookups per label.
    pub fn is_blocked(&self, name: &Name) -> bool {
        if self.block.is_empty() {
            return false;
        }
        let full = name.to_ascii();
        let full = full.trim_end_matches('.').to_ascii_lowercase();
        if full.is_empty() {
            return false;
        }
        let mut rest = full.as_str();
        let mut blocked = false;
        loop {
            // Allow anywhere up the chain un-blocks the name outright.
            if self.allow.contains(rest) {
                return false;
            }
            if self.block.contains(rest) {
                blocked = true;
            }
            match rest.find('.') {
                Some(i) => rest = &rest[i + 1..],
                None => break,
            }
        }
        blocked
    }

    /// Number of unique blocked domains (after dedup across all sources).
    pub fn block_count(&self) -> usize {
        self.block.len()
    }

    /// Number of unique allowlist exceptions.
    pub fn allow_count(&self) -> usize {
        self.allow.len()
    }

    /// Per-source load/parse stats, for the dashboard.
    pub fn sources(&self) -> &[SourceStat] {
        &self.sources
    }
}

/// Fetch and parse every configured list at startup, merging them into one
/// [`Blocklist`]. Per-source **fail-open**: a source that cannot be fetched or
/// parsed is logged and skipped, never aborting startup.
pub async fn load(urls: &[String], pool: &Pool, prefix: Ipv6Addr) -> Blocklist {
    let mut block = HashSet::new();
    let mut allow = HashSet::new();
    let mut sources = Vec::with_capacity(urls.len());

    for url in urls {
        let mut stat = SourceStat {
            url: url.clone(),
            status: SourceStatus::Ok,
            blocks: 0,
            allows: 0,
            skipped: 0,
        };
        match fetch_text(url, pool, prefix).await {
            Ok(text) => {
                for raw in text.lines() {
                    match parse_line(raw) {
                        Line::Block(domains) => {
                            for d in domains {
                                stat.blocks += 1;
                                block.insert(d);
                            }
                        }
                        Line::Allow(domain) => {
                            stat.allows += 1;
                            allow.insert(domain);
                        }
                        Line::Skip => stat.skipped += 1,
                        Line::Ignore => {}
                    }
                }
                tracing::info!(
                    url,
                    blocks = stat.blocks,
                    allows = stat.allows,
                    skipped = stat.skipped,
                    "blocklist source loaded"
                );
            }
            Err(err) => {
                tracing::error!(
                    url,
                    error = %format!("{err:#}"),
                    "blocklist source failed to load; continuing without it (fail-open)"
                );
                stat.status = SourceStatus::Failed(format!("{err:#}"));
            }
        }
        sources.push(stat);
    }

    Blocklist {
        block,
        allow,
        sources,
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// The classification of one source line.
enum Line {
    /// One or more domains to block (a hosts line may list several).
    Block(Vec<String>),
    /// An `@@` allowlist exception.
    Allow(String),
    /// A comment, blank, or noise line (not counted).
    Ignore,
    /// A rule we cannot represent (wildcard, regex, `$`-modifier); counted.
    Skip,
}

/// Hostnames that appear in hosts files but are not real block targets.
const HOST_NOISE: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "broadcasthost",
];

fn is_host_noise(h: &str) -> bool {
    let h = h.trim_end_matches('.');
    HOST_NOISE.iter().any(|n| h.eq_ignore_ascii_case(n)) || h.parse::<IpAddr>().is_ok()
}

/// Normalize and validate a domain: lowercase, no trailing dot, must have a dot,
/// only domain characters, and not a bare IP. `None` if it is not a plain domain
/// we can suffix-match on.
fn normalize_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.');
    if s.is_empty() || s.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !s.contains('.') {
        return None;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// Extract a plain domain from an adblock rule body (already past any `@@`). We
/// represent only `||domain^` / `||domain` / `domain^` shapes; anything carrying a
/// `$`-modifier, a path, a wildcard, or extra anchors returns `None` (→ skipped).
fn adblock_domain(s: &str) -> Option<String> {
    let s = s.strip_prefix("||").unwrap_or(s);
    let end = s.find(['^', '$', '/', '|']).unwrap_or(s.len());
    let (domain, rest) = s.split_at(end);
    // The only trailing content we model is a single `^` separator.
    if !(rest.is_empty() || rest == "^") {
        return None;
    }
    normalize_domain(domain)
}

/// Classify one source line across the hosts / adblock / bare-domain syntaxes.
fn parse_line(raw: &str) -> Line {
    let line = raw.trim();
    if line.is_empty() {
        return Line::Ignore;
    }
    let first = line.as_bytes()[0];
    // Comments and the `[Adblock Plus 2.0]` header.
    if first == b'#' || first == b'!' || first == b'[' {
        return Line::Ignore;
    }

    // Adblock exception (allow): `@@||domain^`.
    if let Some(rest) = line.strip_prefix("@@") {
        return match adblock_domain(rest) {
            Some(d) => Line::Allow(d),
            None => Line::Skip,
        };
    }
    // Adblock block rule: `||domain^`.
    if line.starts_with("||") {
        return match adblock_domain(line) {
            Some(d) => Line::Block(vec![d]),
            None => Line::Skip,
        };
    }
    // Other adblock constructs we cannot represent (anchors, regex, wildcards).
    if first == b'|' || first == b'/' || first == b'@' || line.contains('*') {
        return Line::Skip;
    }

    // Hosts format: `<ip> host [host...]`.
    let mut tokens = line.split_whitespace();
    let head = tokens.next().unwrap_or("");
    if head.parse::<IpAddr>().is_ok() {
        let domains: Vec<String> = tokens
            .filter(|h| !is_host_noise(h))
            .filter_map(normalize_domain)
            .collect();
        return if domains.is_empty() {
            Line::Ignore
        } else {
            Line::Block(domains)
        };
    }

    // Bare domain line.
    match normalize_domain(line) {
        Some(d) if !is_host_noise(line) => Line::Block(vec![d]),
        // Not a domain and not a recognized rule: ignore rather than over-count skips.
        _ => Line::Ignore,
    }
}

// ---------------------------------------------------------------------------
// Fetching: HTTPS GET over NAT64, on the existing rustls/ring + webpki stack
// ---------------------------------------------------------------------------

/// Fetch a list's text, following a few redirects. Each hop resolves the host
/// through the upstream `Pool` and NAT64-embeds it, so it works on an IPv6-only
/// host with no system resolver.
async fn fetch_text(url: &str, pool: &Pool, prefix: Ipv6Addr) -> anyhow::Result<String> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let (host, path) = split_https_url(&current)?;
        let addr = resolve_nat64(&host, pool, prefix).await?;
        let result = timeout(FETCH_TIMEOUT, https_get(&host, &path, addr))
            .await
            .map_err(|_| anyhow::anyhow!("timed out fetching {current}"))??;
        match result {
            HttpResult::Body(bytes) => return Ok(String::from_utf8_lossy(&bytes).into_owned()),
            HttpResult::Redirect(loc) => current = absolutize(&host, &loc),
        }
    }
    anyhow::bail!("too many redirects fetching {url}")
}

/// Split an `https://host[:port]/path` URL into `(host, path)`; the port is
/// ignored (we always connect on 443). Non-https URLs are rejected.
fn split_https_url(url: &str) -> anyhow::Result<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("blocklist URL must be https://: {url}"))?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = host_port.split(':').next().unwrap_or(host_port).to_string();
    if host.is_empty() {
        anyhow::bail!("empty host in URL {url}");
    }
    Ok((host, path.to_string()))
}

/// Resolve `host`'s A record through the `Pool`, keep the globally-routable
/// addresses, and NAT64-embed the first into a `:443` socket address: the
/// Forwarder dogfooding its own DNS64 to reach an IPv4-only list host.
async fn resolve_nat64(host: &str, pool: &Pool, prefix: Ipv6Addr) -> anyhow::Result<SocketAddr> {
    let name = Name::from_ascii(format!("{}.", host.trim_end_matches('.')))
        .with_context(|| format!("invalid host name {host}"))?;
    let mut query = Query::query(name.clone(), RecordType::A);
    query.set_query_class(DNSClass::IN);
    let mut msg = Message::new();
    msg.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(query);

    let resp = pool
        .resolve(msg)
        .await
        .ok_or_else(|| anyhow::anyhow!("A lookup for {host} failed (every upstream down)"))?;
    let v4: Vec<Ipv4Addr> = resp
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    let eligible = eligible_addresses(&name, &v4);
    let ip = eligible
        .first()
        .ok_or_else(|| anyhow::anyhow!("no globally-routable A record for {host}"))?;
    Ok(SocketAddr::new(IpAddr::V6(embed(prefix, *ip)), 443))
}

/// The two interesting HTTP outcomes for our purposes.
enum HttpResult {
    Body(Vec<u8>),
    Redirect(String),
}

/// One HTTPS GET to `addr` (the NAT64 address) with SNI/Host `host`. Reads the
/// whole response (we send `Connection: close`), then parses status, redirect, or
/// body.
async fn https_get(host: &str, path: &str, addr: SocketAddr) -> anyhow::Result<HttpResult> {
    let connector = TlsConnector::from(tls_config());
    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid TLS server name {host}"))?;
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr} (NAT64) for {host}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}"))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dnsix/{ver}\r\n\
         Accept: text/plain, */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        ver = env!("CARGO_PKG_VERSION"),
    );
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_BODY {
                    anyhow::bail!("response from {host} exceeds {MAX_BODY} bytes");
                }
            }
            // Many servers TCP-close without a TLS close_notify; treat as EOF.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("reading HTTPS response"),
        }
    }
    parse_http(&raw)
}

/// Parse an HTTP/1.1 response: 2xx → body (de-chunked if needed), 3xx → its
/// Location, anything else → error.
fn parse_http(raw: &[u8]) -> anyhow::Result<HttpResult> {
    let sep = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response (no header terminator)"))?;
    let head = std::str::from_utf8(&raw[..sep]).context("non-UTF8 HTTP headers")?;
    let body = &raw[sep + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed status line {status_line:?}"))?;

    let mut location = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim();
            match key.as_str() {
                "location" => location = Some(value.to_string()),
                "transfer-encoding" if value.eq_ignore_ascii_case("chunked") => chunked = true,
                _ => {}
            }
        }
    }

    if (300..400).contains(&code) {
        let loc =
            location.ok_or_else(|| anyhow::anyhow!("HTTP {code} redirect without Location"))?;
        return Ok(HttpResult::Redirect(loc));
    }
    if code != 200 {
        anyhow::bail!("unexpected HTTP status {code}");
    }
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok(HttpResult::Body(body))
}

/// Decode an HTTP/1.1 chunked transfer body.
fn dechunk(mut data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    loop {
        let nl = find_subslice(data, b"\r\n").context("malformed chunk header")?;
        let size_line = std::str::from_utf8(&data[..nl]).context("non-UTF8 chunk size")?;
        // A chunk size may carry `;ext` extensions we ignore.
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).context("bad chunk size")?;
        data = &data[nl + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            anyhow::bail!("truncated chunk body");
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        data = data
            .strip_prefix(b"\r\n")
            .context("missing CRLF after chunk")?;
    }
    Ok(out)
}

/// Resolve a redirect `Location` against the current host. Absolute URLs pass
/// through (a non-https one fails the https check on the next hop, which is fine).
fn absolutize(host: &str, loc: &str) -> String {
    if loc.starts_with("https://") || loc.starts_with("http://") {
        loc.to_string()
    } else if loc.starts_with('/') {
        format!("https://{host}{loc}")
    } else {
        format!("https://{host}/{loc}")
    }
}

/// First index of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The shared client TLS config: ring provider, bundled webpki roots (the same
/// trust the DoT upstreams use, independent of the host store). Built once.
fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn blocklist(block: &[&str], allow: &[&str]) -> Blocklist {
        Blocklist {
            block: block.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            sources: Vec::new(),
        }
    }

    fn blocks(line: &str) -> Vec<String> {
        match parse_line(line) {
            Line::Block(d) => d,
            other => panic!("expected Block for {line:?}, got {}", kind(&other)),
        }
    }

    fn kind(l: &Line) -> &'static str {
        match l {
            Line::Block(_) => "Block",
            Line::Allow(_) => "Allow",
            Line::Ignore => "Ignore",
            Line::Skip => "Skip",
        }
    }

    #[test]
    fn parses_hosts_format() {
        assert_eq!(blocks("0.0.0.0 doubleclick.net"), vec!["doubleclick.net"]);
        assert_eq!(blocks("127.0.0.1 Ads.Example.COM"), vec!["ads.example.com"]);
    }

    #[test]
    fn parses_adblock_block_rules() {
        assert_eq!(blocks("||doubleclick.net^"), vec!["doubleclick.net"]);
        assert_eq!(blocks("||ads.example.com"), vec!["ads.example.com"]);
    }

    #[test]
    fn parses_bare_domain() {
        assert_eq!(blocks("doubleclick.net"), vec!["doubleclick.net"]);
    }

    #[test]
    fn adblock_exception_is_allow() {
        match parse_line("@@||good.example.com^") {
            Line::Allow(d) => assert_eq!(d, "good.example.com"),
            other => panic!("expected Allow, got {}", kind(&other)),
        }
    }

    #[test]
    fn comments_and_headers_are_ignored() {
        for line in [
            "",
            "  ",
            "# a comment",
            "! adblock comment",
            "[Adblock Plus 2.0]",
        ] {
            assert!(matches!(parse_line(line), Line::Ignore), "{line:?}");
        }
    }

    #[test]
    fn host_noise_is_ignored() {
        for line in [
            "0.0.0.0 0.0.0.0",
            "127.0.0.1 localhost",
            "255.255.255.255 broadcasthost",
        ] {
            assert!(matches!(parse_line(line), Line::Ignore), "{line:?}");
        }
    }

    #[test]
    fn unrepresentable_rules_are_skipped() {
        for line in [
            "||example.*^",
            "||example.com^$third-party",
            "||example.com$important",
            "/banner\\d+/",
            "||ads.example.com/path",
            "*.example.com",
        ] {
            assert!(matches!(parse_line(line), Line::Skip), "{line:?}");
        }
    }

    #[test]
    fn multi_host_line_yields_all_domains() {
        assert_eq!(
            blocks("0.0.0.0 a.example.com b.example.com"),
            vec!["a.example.com", "b.example.com"]
        );
    }

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn suffix_match_blocks_subdomains() {
        let bl = blocklist(&["doubleclick.net"], &[]);
        assert!(bl.is_blocked(&name("doubleclick.net.")));
        assert!(bl.is_blocked(&name("ad.doubleclick.net.")));
        assert!(bl.is_blocked(&name("stats.g.doubleclick.net.")));
        assert!(!bl.is_blocked(&name("doubleclick.net.evil.com.")));
        assert!(!bl.is_blocked(&name("example.com.")));
    }

    #[test]
    fn match_is_case_insensitive() {
        let bl = blocklist(&["doubleclick.net"], &[]);
        assert!(bl.is_blocked(&name("AD.DoubleClick.NET.")));
    }

    #[test]
    fn allow_beats_block_for_name_and_subdomains() {
        let bl = blocklist(&["example.com"], &["good.example.com"]);
        assert!(bl.is_blocked(&name("ads.example.com.")));
        assert!(!bl.is_blocked(&name("good.example.com.")));
        assert!(!bl.is_blocked(&name("api.good.example.com.")));
    }

    #[test]
    fn empty_blocklist_blocks_nothing() {
        let bl = blocklist(&[], &[]);
        assert!(!bl.is_blocked(&name("doubleclick.net.")));
    }
}
