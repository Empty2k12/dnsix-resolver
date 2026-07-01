# 3. Read-only observability dashboard with an in-memory query log

Date: 2026-06-29

## Status

Accepted. The "`dnsix` filters nothing" stance (see Context, and the rejected "Add real
filtering" alternative) is **superseded in part by ADR 0004**, which adds an optional,
static, local blocklist. The observability and PII decisions in this record stand
unchanged; the dashboard gains a read-only view of blocking but still configures nothing.

## Context

`dnsix` has, until now, been deliberately **stateless** apart from an optional
in-memory response cache, and **observable only in aggregate**: a hand-rolled
`GET /metrics` endpoint exposes Prometheus counters (totals, RCODE mix, cache
hit rate, per-synthesizer hits) and nothing else. That is enough for trend
graphs in Grafana/Zabbix, but it cannot answer the question an operator most
often has when something looks wrong: *"what did this client just ask for, and
how did we answer it?"* The counters name no individual query — no domain, no
client, no per-query outcome.

We want a small, human-facing dashboard in the spirit of NextDNS: a live view of
recent queries plus at-a-glance stats. NextDNS itself is a *filtering* service;
`dnsix` filters nothing (it is a DNS64 forwarder that synthesizes AAAA records),
so the dashboard is **observability only** — it never blocks, allows, or changes
configuration. Its signature column is not "blocked/allowed" but *how the answer
was produced* (which CDN Provider matched, NAT64 fallback, native AAAA,
passthrough, cache hit/stale).

Two things make this more than a cosmetic addition:

1. To show recent individual queries the server must **record them**, which means
   holding, in memory, the **first potentially-sensitive data** in the project:
   client IP addresses and queried names. That is a real departure from "stateless
   forwarder."
2. Serving a multi-page, server-rendered UI with a live stream is well beyond the
   single bespoke route in `metrics.rs`, so it pulls in a **web framework** —
   something the project has so far avoided on purpose.

## Decision

Add an optional, **read-only** dashboard and the **in-memory Query log** that
feeds it.

- **Query log.** A bounded ring buffer of the most recent queries. Each entry
  records the client IP, queried name and type, RCODE, cache disposition
  (miss/hit/stale), the synthesis outcome (which Provider / NAT64-fallback /
  native-AAAA / passthrough), and the query's latency. It stores **no resolved
  addresses**. Size is operator-set via `query_log_size` (default 1000).
- **Privacy boundary.** Capture runs **only while the dashboard is enabled**
  (`ui_listen` set). With the UI off, nothing is captured and nothing is stored.
  The log is purely in-memory and **lost on restart**; there is no on-disk
  persistence.
- **Serving.** Use **axum** for the UI on its **own listener** (`ui_listen`,
  `Option`, off by default — mirroring `metrics_listen`). The existing
  hand-rolled `/metrics` server is left untouched. HTML is rendered server-side
  with **maud** (compile-time, auto-escaping); CSS and a ~20-line `EventSource`
  script are embedded in the binary, which stays self-contained (no Node, no
  build step). The live log updates via **Server-Sent Events**.
- **Exposure.** No built-in authentication. As with `metrics_listen`, the
  operator is responsible for binding the listener to a trusted address or
  fronting it with an authenticating reverse proxy. The default-off posture keeps
  the sensitive surface from existing unless explicitly turned on. The shipped
  example config binds it to loopback (`[::1]`), not all interfaces.
- **Anti-DNS-rebinding.** "Bind somewhere trusted" does not by itself stop a
  browser on the trusted network from being **DNS-rebound**: an attacker page on a
  hostname that re-resolves to the dashboard's address could read `/events`
  cross-origin and exfiltrate the query log — a risk sharpened by this server being
  itself a resolver the rebinding name may resolve through. The dashboard therefore
  validates the `Host` header and serves only requests whose host is an **IP literal
  or `localhost`** (the forms an operator actually uses, and the ones a rebinding
  attacker — stuck with its own hostname — cannot present); anything else gets 403.
  A reverse proxy in front must reach the dashboard by IP/loopback accordingly.
- **Aggregates** come from the existing counters (cumulative since boot, so the
  Overview shows the process start time and uptime to make them interpretable);
  **Top lists** and the rate sparkline are derived from the ring buffer's recent
  window and labelled as such, not all-time.

## Consequences

**Positive**

- Operators get the per-query view the counters could never provide, with
  `dnsix`'s unique synthesis-outcome attribution front and centre.
- The privacy-sensitive store is opt-in, ephemeral, bounded, and absent by
  default; the blast radius of "we now log queries" is small and operator-chosen.
- The metrics endpoint and its scrapers are unaffected.

**Negative / trade-offs**

- First stateful PII in the project. Even bounded and in-memory, the server now
  holds client identities and queried names while the UI is on; an operator who
  exposes `ui_listen` carelessly leaks resolution history. Mitigated by
  default-off + documentation, not by code-enforced auth.
- `axum` (and its tower/hyper tree) is a substantial dependency in a previously
  lean, framework-free project. Accepted because hand-rolling routing, SSE, and
  HTML escaping for a multi-page live UI is more error-prone (notably XSS with
  untrusted names/IPs) than the framework it replaces.
- Per-query capture adds a small amount of work and lock contention on the hot
  path. Bounded by the ring buffer and only paid when the UI is enabled.
- Top lists reflect only the recent window, not all-time; true all-time rankings
  would need unbounded per-name aggregation we are deliberately not adding.

## Alternatives considered

- **Counters-only dashboard (no query log).** Visualize just the existing
  aggregates. Keeps the server fully stateless and PII-free, but loses the live
  query view that is the whole point of a NextDNS-like UI. Rejected.
- **Keep hand-rolling HTTP** (extend `metrics.rs`). Zero new dependencies, but we
  would own routing, content negotiation, SSE framing, and HTML escaping by hand
  across several pages — the XSS surface alone (domain names and client IPs
  rendered into HTML) argues for an escaping template engine. Rejected.
- **Persist the query log to disk.** More history across restarts, but turns an
  ephemeral debugging aid into a durable PII store with retention, rotation, and
  on-disk-encryption questions. Out of scope for an observability view. Rejected.
- **Add real filtering (become NextDNS).** A different product. Out of scope; the
  forwarder filters nothing by design.
