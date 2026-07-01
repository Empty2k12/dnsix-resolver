//! The observability dashboard: a small, read-only, server-rendered web UI.
//!
//! Three views — Overview (counter-derived stats + a recent-rate sparkline),
//! Live log (the Query log, server-rendered then tailed live over Server-Sent
//! Events), and Top (recent-window rankings). It observes only: it never changes
//! the Forwarder's configuration or behaviour, and it filters nothing.
//!
//! HTML is rendered with `maud` (compile-time, auto-escaping — important since we
//! render untrusted client IPs and queried names). CSS and the tiny SSE script
//! are embedded below, so the binary stays self-contained. The server is
//! best-effort: a bind failure disables the dashboard but never aborts the
//! Forwarder. There is no built-in auth (see ADR 0003) — bind it somewhere
//! trusted.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::Stream;
use hickory_proto::op::ResponseCode;
use maud::{html, Markup, PreEscaped, DOCTYPE};
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};
use tokio_stream::StreamExt;
use tracing::{error, info};

use crate::blocklist::{Blocklist, SourceStat};
use crate::metrics::Metrics;
use crate::querylog::{Entry, Outcome, QueryLog};

/// How often the Overview pushes a refreshed stats block over SSE. One second
/// keeps the uptime ticking smoothly; the payload is a couple of KB.
const OVERVIEW_TICK: Duration = Duration::from_secs(1);

/// Shared handler state. Cheap to clone (two `Arc`s plus two `Copy` instants).
#[derive(Clone)]
struct AppState {
    metrics: Arc<Metrics>,
    log: Arc<QueryLog>,
    /// Present only when blocking is configured; drives the Blocklists page.
    blocklist: Option<Arc<Blocklist>>,
    started: Instant,
    started_wall: SystemTime,
}

/// Serve the dashboard forever. Logs and returns if the bind fails (the rest of
/// the Forwarder keeps running — the dashboard is best-effort).
pub async fn serve(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    log: Arc<QueryLog>,
    blocklist: Option<Arc<Blocklist>>,
    started: Instant,
    started_wall: SystemTime,
) {
    let state = AppState {
        metrics,
        log,
        blocklist,
        started,
        started_wall,
    };
    let app = Router::new()
        .route("/", get(overview))
        .route("/log", get(log_page))
        .route("/top", get(top_page))
        .route("/blocklists", get(blocklists_page))
        .route("/events", get(events))
        .route("/events/overview", get(overview_events))
        .route("/style.css", get(stylesheet))
        .layer(middleware::from_fn(rebinding_guard))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(err) => {
            error!(error = %err, %addr, "dashboard: failed to bind; UI disabled");
            return;
        }
    };
    info!(%addr, "dashboard listening (read-only, unauthenticated)");
    if let Err(err) = axum::serve(listener, app).await {
        error!(error = %err, "dashboard: server error");
    }
}

/// Anti-DNS-rebinding guard. The dashboard has no auth (ADR 0003) and serves the
/// Query log (client IPs and every queried name), so a browser on the trusted
/// network could otherwise be rebound — an attacker page whose hostname re-resolves
/// to this server's address — and read `/events` cross-origin. That risk is sharper
/// here because this server is itself a resolver the rebinding name may resolve
/// through. A rebound request still carries the attacker's *hostname* in `Host`,
/// whereas an operator reaches the UI by IP literal or over `localhost`, so we
/// accept only those and reject anything else with 403.
async fn rebinding_guard(req: axum::extract::Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    if host_is_allowed(host) {
        next.run(req).await
    } else {
        (
            StatusCode::FORBIDDEN,
            "forbidden: unexpected Host header (reach the dashboard by IP address or localhost)\n",
        )
            .into_response()
    }
}

/// Whether a `Host` header value is an IP literal or `localhost` (optionally with a
/// port) — the only forms a legitimate operator uses, and the ones a DNS-rebinding
/// attack cannot forge (it is stuck with its own hostname).
fn host_is_allowed(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let hostname = strip_port(host);
    hostname.eq_ignore_ascii_case("localhost") || hostname.parse::<IpAddr>().is_ok()
}

/// Strip a trailing `:port` from a `Host` value, leaving the hostname/IP. Handles a
/// bracketed IPv6 literal (`[::1]:8080` -> `::1`) and only strips an unbracketed
/// port when a single `:` is present, so a bare IPv6 literal (`::1`, many colons)
/// is left intact.
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((h, _port)) if !h.contains(':') => h,
        _ => host,
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

async fn overview(State(st): State<AppState>) -> Markup {
    page(
        "Overview",
        "overview",
        None,
        html! {
            // Re-rendered live over SSE (see `overview_events`); the initial copy
            // is server-rendered so it works even with JS disabled.
            div id="dash" { (overview_dash(&st)) }
            (OVERVIEW_JS)
        },
    )
}

/// SSE: push a freshly-rendered stats block on a fixed tick so the Overview's
/// counters, uptime, and sparkline stay live without a page reload.
async fn overview_events(
    State(st): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let ticks = IntervalStream::new(tokio::time::interval(OVERVIEW_TICK));
    let stream = ticks.map(move |_| {
        Ok::<_, Infallible>(
            Event::default()
                .event("stats")
                .data(overview_dash(&st).into_string()),
        )
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// The dynamic part of the Overview — everything inside `#dash`. Rendered both
/// for the initial page load and for each SSE tick.
fn overview_dash(st: &AppState) -> Markup {
    let m = st.metrics.snapshot();
    let entries = st.log.snapshot_newest_first();

    let total = m.queries_dns64 + m.queries_passthrough + m.blocked;
    let blocked_pct = if total > 0 {
        m.blocked as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    let cache_total = m.cache_hits + m.cache_misses;
    let hit_rate = if cache_total > 0 {
        m.cache_hits as f64 / cache_total as f64 * 100.0
    } else {
        0.0
    };
    let since = fmt_utc(st.started_wall);

    let kind = vec![
        ("dns64 (AAAA synthesis)", m.queries_dns64),
        ("passthrough", m.queries_passthrough),
        ("blocked", m.blocked),
    ];
    let dns64 = vec![
        ("native AAAA", m.native_aaaa),
        ("nxdomain", m.nxdomain64),
        ("nodata → chain", m.nodata),
        ("synthesized", m.synthesized),
        ("empty (no synth)", m.empty),
    ];
    let cache = vec![
        ("hits", m.cache_hits),
        ("misses", m.cache_misses),
        ("negative hits", m.negative_cache_hits),
        ("served stale", m.served_stale),
        ("prefetches", m.prefetches),
        ("upstream failed", m.upstream_failed),
    ];

    html! {
        section.cards {
            (card(&total.to_string(), "Total queries", &format!("since {since}")))
            (card(&fmt_uptime(st.started.elapsed()), "Uptime", &format!("started {since}")))
            (card(&format!("{hit_rate:.1}%"), "Cache hit rate", &format!("{} hits · {} misses", m.cache_hits, m.cache_misses)))
            (card(&m.synthesized.to_string(), "Synthesized", &format!("{} nodata · {} empty", m.nodata, m.empty)))
            (card(&m.blocked.to_string(), "Blocked", &format!("{blocked_pct:.1}% of queries")))
        }
        section.panel {
            h2 { "Query rate" }
            (sparkline(&entries))
        }
        div.grid {
            section.panel { h2 { "Query kind" } (count_table(&kind, false)) }
            section.panel { h2 { "DNS64 disposition" } (count_table(&dns64, false)) }
            section.panel { h2 { "Cache & resilience" } (count_table(&cache, false)) }
            section.panel { h2 { "Responses by code" } (count_table(&m.rcode, true)) }
            section.panel { h2 { "Queries by type" } (count_table(&m.qtype, true)) }
            section.panel { h2 { "Synthesizer hits" } (count_table(&m.synth, false)) }
        }
    }
}

async fn log_page(State(st): State<AppState>) -> Markup {
    let entries = st.log.snapshot_newest_first();
    page(
        "Live log",
        "log",
        None,
        html! {
            section.panel {
                div.loghead {
                    h2 { "Live query log" }
                    span.live { "live" }
                }
                p.muted.small { "Newest first. New queries stream in via Server-Sent Events." }
                div.tablewrap {
                    table.log {
                        thead {
                            tr {
                                th { "Time" } th { "Client" } th { "Name" } th { "Type" }
                                th { "Code" } th { "Cache" } th { "Outcome" } th.num { "Latency" }
                            }
                        }
                        tbody id="rows" {
                            @for e in &entries { (row(e)) }
                        }
                    }
                }
            }
            (LOG_JS)
        },
    )
}

async fn top_page(State(st): State<AppState>) -> Markup {
    let entries = st.log.snapshot_newest_first();
    let domains = top_counts(entries.iter().map(|e| e.name.clone()));
    let clients = top_counts(entries.iter().map(|e| e.client.to_string()));
    let outcomes = top_counts(entries.iter().map(|e| e.outcome.label()));
    let blocked = top_counts(
        entries
            .iter()
            .filter(|e| matches!(e.outcome, Outcome::Blocked))
            .map(|e| e.name.clone()),
    );

    page(
        "Top",
        "top",
        Some(10),
        html! {
            p.muted { "Computed from the " (entries.len()) " queries currently in the log buffer — a recent window, not all-time." }
            div.grid {
                section.panel { h2 { "Top domains" } (top_table(&domains)) }
                section.panel { h2 { "Top clients" } (top_table(&clients)) }
                section.panel { h2 { "Top outcomes" } (top_table(&outcomes)) }
                section.panel { h2 { "Top blocked domains" } (top_table(&blocked)) }
            }
        },
    )
}

/// The Blocklists page: a read-only view of the statically-loaded blocklist,
/// what loaded, what failed, and the deduplicated totals. The dashboard reports
/// blocking; it never edits it (the lists are static config).
async fn blocklists_page(State(st): State<AppState>) -> Markup {
    page(
        "Blocklists",
        "blocklists",
        None,
        html! {
            @match &st.blocklist {
                None => {
                    section.panel {
                        h2 { "Blocklist" }
                        p.muted { "Blocking is disabled. Set " code { "blocklists" } " in the config to enable it." }
                    }
                }
                Some(bl) => {
                    section.cards {
                        (card(&fmt_count(bl.block_count()), "Blocked domains", "unique, after dedup"))
                        (card(&fmt_count(bl.allow_count()), "Allowlist exceptions", "@@ rules honored"))
                        (card(&bl.sources().len().to_string(), "Sources", "fetched once at startup"))
                    }
                    section.panel {
                        h2 { "Sources" }
                        p.muted.small { "Fetched once at startup and immutable; restart to update. A failed source is skipped (fail-open)." }
                        div.tablewrap {
                            table.log {
                                thead {
                                    tr {
                                        th { "Source" } th { "Status" }
                                        th.num { "Blocked" } th.num { "Allowed" } th.num { "Skipped" }
                                    }
                                }
                                tbody {
                                    @for s in bl.sources() { (source_row(s)) }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// One row of the Blocklists "Sources" table.
fn source_row(s: &SourceStat) -> Markup {
    let (cls, label) = match &s.status {
        crate::blocklist::SourceStatus::Ok => ("ok", "ok".to_string()),
        crate::blocklist::SourceStatus::Failed(why) => ("failed", format!("failed: {why}")),
    };
    html! {
        tr {
            td.mono.name { (s.url) }
            td { span class={ "badge source-" (cls) } { (label) } }
            td.num { (fmt_count(s.blocks)) }
            td.num { (fmt_count(s.allows)) }
            td.num { (fmt_count(s.skipped)) }
        }
    }
}

/// SSE: stream each new Query-log entry as a rendered `<tr>` fragment the page's
/// script prepends to the table.
async fn events(State(st): State<AppState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = st.log.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| {
        // Drop lagged/closed errors; a live tail need not be gap-free.
        res.ok().map(|e| {
            Ok::<_, Infallible>(Event::default().event("query").data(row(&e).into_string()))
        })
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn stylesheet() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CSS)
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// The shared page chrome. `refresh` adds a meta-refresh (seconds) for the
/// counter views; the live log opts out (it updates over SSE).
fn page(title: &str, active: &str, refresh: Option<u32>, body: Markup) -> Markup {
    let is = |n: &str| n == active;
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                @if let Some(secs) = refresh {
                    meta http-equiv="refresh" content=(secs);
                }
                title { "dnsix · " (title) }
                link rel="stylesheet" href="/style.css";
            }
            body {
                header.topbar {
                    span.brand { "dnsix" }
                    nav {
                        a.active[is("overview")] href="/" { "Overview" }
                        a.active[is("log")] href="/log" { "Live log" }
                        a.active[is("top")] href="/top" { "Top" }
                        a.active[is("blocklists")] href="/blocklists" { "Blocklists" }
                    }
                }
                main { (body) }
            }
        }
    }
}

fn card(value: &str, label: &str, sub: &str) -> Markup {
    html! {
        div.card {
            div.card-value { (value) }
            div.card-label { (label) }
            div.card-sub { (sub) }
        }
    }
}

/// A two-column label/count table. `hide_zero` skips rows with a zero count
/// (useful for the long, mostly-empty qtype and rcode families).
fn count_table(rows: &[(&str, u64)], hide_zero: bool) -> Markup {
    let visible: Vec<&(&str, u64)> = rows.iter().filter(|(_, v)| !hide_zero || *v > 0).collect();
    html! {
        @if visible.is_empty() {
            p.muted.small { "Nothing yet." }
        } @else {
            table.kv {
                tbody {
                    @for (k, v) in visible {
                        tr { td { (k) } td.num { (v) } }
                    }
                }
            }
        }
    }
}

fn top_table(rows: &[(String, u64)]) -> Markup {
    html! {
        @if rows.is_empty() {
            p.muted.small { "Nothing yet." }
        } @else {
            table.kv {
                tbody {
                    @for (k, v) in rows {
                        tr { td.mono { (k) } td.num { (v) } }
                    }
                }
            }
        }
    }
}

/// One query-log row. Also the SSE payload, so it must be a self-contained
/// single `<tr>`.
fn row(e: &Entry) -> Markup {
    html! {
        tr {
            td.mono.muted { (fmt_clock(e.time)) }
            td.mono { (e.client) }
            td.mono.name { (e.name) }
            td { (e.qtype) }
            td { (rcode_label(e.rcode)) }
            td { span class={ "badge cache-" (e.cache.label()) } { (e.cache.label()) } }
            td { span class={ "badge outcome-" (e.outcome.kind()) } { (e.outcome.label()) } }
            td.num { (fmt_ms(e.latency)) }
        }
    }
}

/// A recent-rate sparkline drawn as inline SVG from the buffer's timestamps —
/// no chart library, no background sampler.
fn sparkline(entries: &[Entry]) -> Markup {
    const BINS: usize = 60;
    const W: f64 = 600.0;
    const H: f64 = 80.0;

    if entries.len() < 2 {
        return html! { p.muted.small { "Not enough data yet for a rate chart." } };
    }

    let now = unix_secs(SystemTime::now());
    let oldest = entries
        .iter()
        .map(|e| unix_secs(e.time))
        .min()
        .unwrap_or(now);
    let span = (now - oldest).max(1);

    let mut bins = [0u32; BINS];
    for e in entries {
        let frac = (unix_secs(e.time) - oldest) as f64 / span as f64;
        let idx = ((frac * (BINS as f64 - 1.0)) as usize).min(BINS - 1);
        bins[idx] += 1;
    }
    let max = bins.iter().copied().max().unwrap_or(1).max(1);

    let points = bins
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            let x = i as f64 / (BINS as f64 - 1.0) * W;
            let y = H - (c as f64 / max as f64) * H;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");

    html! {
        svg.spark viewbox=(format!("0 0 {W} {H}")) preserveaspectratio="none" {
            polyline points=(points);
        }
        p.muted.small {
            "spanning " (fmt_uptime(Duration::from_secs(span as u64)))
            " · " (entries.len()) " queries in buffer · peak " (max) " per bin"
        }
    }
}

// ---------------------------------------------------------------------------
// Small formatting / aggregation utilities
// ---------------------------------------------------------------------------

/// Tally an iterator of keys into a descending top-10 (ties broken by key).
fn top_counts<I, K>(it: I) -> Vec<(String, u64)>
where
    I: Iterator<Item = K>,
    K: Into<String>,
{
    let mut map: HashMap<String, u64> = HashMap::new();
    for k in it {
        *map.entry(k.into()).or_insert(0) += 1;
    }
    let mut v: Vec<(String, u64)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(10);
    v
}

/// Group a count with thin spaces every three digits, so blocklist sizes in the
/// hundreds of thousands stay readable (e.g. `1 234 567`).
fn fmt_count(n: usize) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in digits.chars().enumerate() {
        // A thin space before every group of three counted from the right.
        if i != 0 && (len - i).is_multiple_of(3) {
            out.push('\u{2009}');
        }
        out.push(ch);
    }
    out
}

fn rcode_label(c: ResponseCode) -> String {
    match c {
        ResponseCode::NoError => "noerror".to_string(),
        ResponseCode::NXDomain => "nxdomain".to_string(),
        ResponseCode::ServFail => "servfail".to_string(),
        ResponseCode::NotImp => "notimp".to_string(),
        ResponseCode::FormErr => "formerr".to_string(),
        ResponseCode::Refused => "refused".to_string(),
        other => format!("{other:?}").to_lowercase(),
    }
}

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms >= 10.0 {
        format!("{ms:.0} ms")
    } else {
        format!("{ms:.1} ms")
    }
}

fn fmt_uptime(d: Duration) -> String {
    let s = d.as_secs();
    let (days, h, m, sec) = (s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60);
    if days > 0 {
        format!("{days}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {sec}s")
    } else if m > 0 {
        format!("{m}m {sec}s")
    } else {
        format!("{sec}s")
    }
}

fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Full UTC timestamp, e.g. `2026-06-29 14:03:51 UTC`.
fn fmt_utc(t: SystemTime) -> String {
    let secs = unix_secs(t);
    let day = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(day);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Just the wall-clock time-of-day in UTC, e.g. `14:03:51`.
fn fmt_clock(t: SystemTime) -> String {
    let rem = unix_secs(t).rem_euclid(86400);
    format!("{:02}:{:02}:{:02}", rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Civil date from a day count since the Unix epoch (Howard Hinnant's algorithm),
/// so we can render dates without pulling in a date/time crate.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

// ---------------------------------------------------------------------------
// Embedded assets
// ---------------------------------------------------------------------------

const OVERVIEW_JS: PreEscaped<&str> = PreEscaped(
    r#"<script>
(function () {
  var el = document.getElementById('dash');
  if (!el || !window.EventSource) return;
  var es = new EventSource('/events/overview');
  es.addEventListener('stats', function (e) { el.innerHTML = e.data; });
})();
</script>"#,
);

const LOG_JS: PreEscaped<&str> = PreEscaped(
    r#"<script>
(function () {
  var tb = document.getElementById('rows');
  if (!tb || !window.EventSource) return;
  var es = new EventSource('/events');
  es.addEventListener('query', function (e) {
    tb.insertAdjacentHTML('afterbegin', e.data);
    while (tb.rows.length > 500) tb.deleteRow(-1);
  });
})();
</script>"#,
);

const CSS: &str = r#"
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #1c2024; --muted: #6b7280;
  --border: #e6e8eb; --accent: #4f46e5; --accent-soft: #eef2ff;
  --ok: #047857; --ok-bg: #ecfdf5; --warn: #b45309; --warn-bg: #fffbeb;
  --bad: #b91c1c; --bad-bg: #fef2f2;
  --neutral: #475569; --neutral-bg: #f1f5f9;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1115; --panel: #171a21; --text: #e5e7eb; --muted: #9aa3b2;
    --border: #262b36; --accent: #818cf8; --accent-soft: #1e2230;
    --ok: #34d399; --ok-bg: #07271d; --warn: #fbbf24; --warn-bg: #2a1f06;
    --bad: #f87171; --bad-bg: #2a0f0f;
    --neutral: #cbd5e1; --neutral-bg: #1c222d;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.topbar {
  display: flex; align-items: center; gap: 24px;
  padding: 14px 24px; background: var(--panel);
  border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 10;
}
.brand { font-weight: 700; letter-spacing: -0.02em; font-size: 16px; }
.topbar nav { display: flex; gap: 4px; }
.topbar nav a {
  color: var(--muted); text-decoration: none; padding: 6px 12px;
  border-radius: 8px; font-weight: 500;
}
.topbar nav a:hover { color: var(--text); background: var(--accent-soft); }
.topbar nav a.active { color: var(--accent); background: var(--accent-soft); }
main { max-width: 1100px; margin: 0 auto; padding: 24px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 16px; margin-bottom: 20px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 18px; }
.card-value { font-size: 28px; font-weight: 700; letter-spacing: -0.02em; }
.card-label { color: var(--text); font-weight: 600; margin-top: 2px; }
.card-sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 18px; margin-bottom: 16px; }
.panel h2 { margin: 0 0 12px; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
.muted { color: var(--muted); }
.small { font-size: 12px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
table { width: 100%; border-collapse: collapse; }
.kv td { padding: 5px 0; border-bottom: 1px solid var(--border); }
.kv tr:last-child td { border-bottom: 0; }
.num { text-align: right; font-variant-numeric: tabular-nums; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.tablewrap { overflow-x: auto; }
table.log { font-size: 12.5px; }
table.log th { text-align: left; color: var(--muted); font-weight: 600; padding: 6px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
table.log td { padding: 6px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
table.log td.name { max-width: 360px; overflow: hidden; text-overflow: ellipsis; }
table.log tbody tr:hover { background: var(--accent-soft); }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: var(--neutral-bg); color: var(--neutral); }
.cache-hit { background: var(--ok-bg); color: var(--ok); }
.cache-stale { background: var(--warn-bg); color: var(--warn); }
.cache-miss, .cache-uncached { background: var(--neutral-bg); color: var(--neutral); }
.outcome-native { background: var(--ok-bg); color: var(--ok); }
.outcome-synth { background: var(--warn-bg); color: var(--warn); }
.outcome-nat64 { background: var(--bad-bg); color: var(--bad); }
.outcome-passthrough { background: var(--neutral-bg); color: var(--neutral); }
.outcome-nxdomain, .outcome-empty { background: var(--neutral-bg); color: var(--muted); }
.outcome-servfail { background: var(--bad-bg); color: var(--bad); }
/* Blocked is a policy disposition, not a reachability grade: its own accent. */
.outcome-blocked { background: var(--accent-soft); color: var(--accent); }
/* Refused: a client outside the allowlist, never resolved. */
.outcome-refused { background: var(--bad-bg); color: var(--bad); }
.source-ok { background: var(--ok-bg); color: var(--ok); }
.source-failed { background: var(--bad-bg); color: var(--bad); }
.loghead { display: flex; align-items: center; gap: 10px; }
.loghead h2 { margin: 0; }
.live { display: inline-flex; align-items: center; gap: 6px; color: var(--ok); font-size: 11px; font-weight: 700; text-transform: uppercase; }
.live::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--ok); animation: pulse 1.6s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
svg.spark { width: 100%; height: 90px; display: block; }
svg.spark polyline { fill: none; stroke: var(--accent); stroke-width: 2; vector-effect: non-scaling-stroke; }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// Digit grouping must not panic at any length (regression: the 5- and
    /// 8-digit cases used to subtract with overflow).
    #[test]
    fn fmt_count_groups_without_overflow() {
        const NB: char = '\u{2009}';
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(7), "7");
        assert_eq!(fmt_count(42), "42");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), format!("1{NB}000"));
        assert_eq!(fmt_count(12_345), format!("12{NB}345"));
        assert_eq!(fmt_count(123_456), format!("123{NB}456"));
        assert_eq!(fmt_count(1_234_567), format!("1{NB}234{NB}567"));
        // Exercise every length 1..=9 to be sure none panic.
        for len in 1..=9 {
            let n: usize = "9".repeat(len).parse().unwrap();
            let _ = fmt_count(n);
        }
    }

    #[test]
    fn rebinding_guard_accepts_ip_and_localhost_only() {
        // Accepted: IP literals (with or without port) and localhost.
        assert!(host_is_allowed(Some("[::1]:8080")));
        assert!(host_is_allowed(Some("[2001:db8::1]:8080")));
        assert!(host_is_allowed(Some("::1")));
        assert!(host_is_allowed(Some("fe80::1")));
        assert!(host_is_allowed(Some("127.0.0.1")));
        assert!(host_is_allowed(Some("127.0.0.1:8080")));
        assert!(host_is_allowed(Some("localhost")));
        assert!(host_is_allowed(Some("localhost:8080")));
        assert!(host_is_allowed(Some("LOCALHOST")));

        // Rejected: any domain name (the rebinding attacker's form) and no Host.
        assert!(!host_is_allowed(Some("attacker.example")));
        assert!(!host_is_allowed(Some("dnsix.local:8080")));
        assert!(!host_is_allowed(Some("")));
        assert!(!host_is_allowed(None));
    }
}
