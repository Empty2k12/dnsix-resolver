# 4. An optional, static, locally-enforced blocklist

Date: 2026-06-29

## Status

Accepted. Supersedes, in part, the "filters nothing" stance of ADR 0003 (the rejected
"Add real filtering" alternative there).

## Context

`dnsix` has, by design, been a DNS64 forwarder that **synthesizes or relays, but never
filters**. ADR 0003 made that explicit and rejected "become NextDNS / add real filtering"
as a different product. We are now reversing that one stance: operators want to block
ad/tracker/malware domains at the forwarder.

The defining constraint the operator set is **"blocking must not be done via an upstream."**
That rules out the easy non-feature, pointing the configured upstreams at a filtering
resolver (NextDNS, Quad9, an AdGuard endpoint), and commits us to enforcing the block
**locally, in this process, from operator-controlled config.** That is the real decision
this record captures; everything else follows from it.

Two facts about the deployment shape the design:

1. The target host is **IPv6-only** with a NAT64 path (the forwarder's whole reason to
   exist). The popular blocklist sources are hosted on **IPv4-only** CDNs (e.g.
   `raw.githubusercontent.com` publishes no AAAA).
2. The project is deliberately lean and, per ADR 0003's privacy boundary, holds no durable
   on-disk state. Upstream resolution is an **explicitly configured** list, never the host's
   `resolv.conf`.

## Decision

Add an optional **Blocklist**: a set of domains the forwarder answers locally, off by
default in the binary and enabled in the shipped example config.

- **Response.** A blocked name is answered **NXDOMAIN**, for **every** query type, fixed (not
  configurable). NXDOMAIN is the modern default (AdGuard Home, RPZ), gives the fastest
  client-side failure with no wasted socket, and avoids the IPv6-only trap where a
  `0.0.0.0` sinkhole is meaningless. NODATA and `::`/`0.0.0.0` sinkholes were considered and
  rejected.
- **Placement.** The check runs in the request handler **before any cache lookup or upstream
  query**, immediately after question validation. A match short-circuits to NXDOMAIN and
  records the query-log entry; it never produces an upstream packet. This is the literal
  "not via an upstream" guarantee.
- **Matching.** **Domain-suffix**: a listed name blocks itself and all subdomains (a
  label-wise walk of the queried name against the set). Names are normalized (lowercased,
  trailing dot stripped) on both sides. No wildcards, regex, or path rules in v1. This
  matches the dnsmasq/AdGuard/Blocky convention and the intent of the lists; Pi-hole's
  exact-match (subdomains leak unless enumerated) is the anti-pattern we avoid.
- **DNSSEC bits.** Blocking is applied **unconditionally**, ignoring the client's CD and DO
  bits. Those govern DNSSEC validation, not content policy, so honoring them would be a
  block-bypass. (This intentionally differs from the synthesis path, which backs off on CD/DO
  to avoid minting data a validator would reject; blocking is a deliberate policy override,
  not a fidelity concern.)
- **Sources and formats.** Config field `blocklists`, a plain list of URLs. Two source
  syntaxes are parsed, **hosts** (`0.0.0.0 name` / `127.0.0.1 name`) and **adblock**
  (`||name^`), plus bare-domain lines. The adblock `||name^` form already means
  domain-suffix, so it maps onto our matching exactly. Adblock **`@@` exception rules are
  honored**: they populate a second (allowlist) set, and **allow beats block**, so we use a
  curated list like Hagezi `pro` as its author intended rather than over-blocking what it
  deliberately un-blocks. Everything unrepresentable (wildcards, `/regex/`, `$`-modifiers,
  element rules) is **skipped and counted**. All sources are merged and deduplicated into one
  block set and one allow set; **no per-list attribution** is kept.
- **Acquisition.** The forwarder **fetches the lists itself at startup** (operator chose this
  over reading local files). To reach IPv4-only list hosts from an IPv6-only box, it resolves
  each list host through its **own** configured Upstream Resolvers and **NAT64-embeds** the
  result via `nat64_prefix`, then connects over HTTPS with SNI set to the original hostname:
  the DNS64 forwarder dogfooding its own DNS64 to bootstrap. This deliberately keeps the
  fetch off the host's `resolv.conf`, preserving the "resolution is explicitly configured"
  invariant.
- **Lifecycle.** Fetched **once at startup, immutable thereafter** (this is what "not dynamic"
  means operationally). No periodic refresh, no SIGHUP reload, no disk cache. To update the
  lists, restart. A per-source **fail-open**: if a list cannot be fetched or parsed, the
  forwarder starts anyway with the remaining lists and reports the failure, because a
  resolver's first duty is resolving and a list-CDN outage must not take DNS down.
- **Default posture.** The binary default is **off** (absent `blocklists` = today's behaviour,
  byte for byte), so existing deployments are unaffected on upgrade. The shipped
  `config.example.toml` enables the two lists, so a fresh install set up from the example
  blocks out of the box. ("On by default" lives in the example, not the binary.)
- **Observability (the "adapt the UI" piece).** A new `Outcome::Blocked` query-log
  disposition (its own badge, on a policy axis distinct from the synthesis
  reachability-gradient), a new `blocked` Metrics counter (incremented in the hot path
  regardless of whether the UI is on), an Overview "Blocked" card and a "blocked" query-kind
  row, a "Top blocked domains" panel, and a read-only **Blocklists** status page showing per
  source: URL, load status (ok/failed), entries parsed, lines skipped, `@@` exceptions, and
  the deduplicated totals. The dashboard still **configures nothing**: it reports blocking, it
  does not edit the (static) blocklist.

## Consequences

**Positive**

- Local ad/tracker/malware blocking with no dependency on a filtering upstream, honoring the
  operator's founding constraint.
- The block path is the cheapest path in the server (a set lookup, then NXDOMAIN), short of
  cache and upstream entirely.
- Off-by-default in the binary means zero behaviour change for existing deployments;
  example-config-on means new installs are protected without a code-level surprise.
- Honoring `@@` exceptions lets curated adblock lists work as intended instead of
  over-blocking.

**Negative / trade-offs**

- **Identity change.** `dnsix` is no longer "filters nothing." Mitigated by keeping it a
  single, opt-in, secondary behaviour bolted onto an unchanged synth/relay core.
- **New startup dependencies.** An HTTP+TLS client and a startup network dependency on the
  list CDNs, reachable only with the NAT64 path live. Heavier than the lean baseline; the
  cost of the operator's "fetch, don't read local files" choice.
- **Boot-time-only freshness with no disk cache.** A restart during a list-CDN outage boots
  **silently unfiltered** until a later successful restart (fail-open). Accepted as the right
  trade for a resolver; mitigated by the Blocklists page showing "0 entries". A last-known-good
  disk cache is the obvious future addition if this bites (the lists are public, so unlike the
  query log it carries no PII concern).
- **NXDOMAIN for blocked names breaks DNSSEC-validating clients** for those names and is
  indistinguishable on the wire from a genuine NXDOMAIN. Inherent to DNS blocking; accepted.
- **Coarse matching.** Suffix-only, no wildcards/regex/exact-only, so some list constructs are
  dropped (counted, not silently). Acceptable for v1; the surfaced skip count keeps it honest.

## Alternatives considered

- **Block via a filtering upstream.** Point `upstreams` at NextDNS/Quad9. Zero code, but
  violates the founding "not via an upstream" constraint and moves resolution policy
  off-box. Rejected.
- **Read local files instead of fetching.** Operator refreshes lists out-of-band (cron +
  `curl`), `dnsix` just reads paths. Far less code, no HTTP/TLS client, no IPv6/NAT64
  bootstrapping, cleanly "not dynamic". Rejected by operator preference for self-contained
  fetching; recorded here as the cheaper design if the fetch machinery proves troublesome.
- **NODATA or `::`/`0.0.0.0` sinkhole responses.** Softer or address-returning blocks.
  Rejected: ambiguous (NODATA) or wasteful/meaningless on IPv6-only (`0.0.0.0`).
- **Exact-match (Pi-hole gravity style).** Rejected: subdomains leak unless enumerated, the
  well-known footgun.
- **Rich entry syntax (wildcards, regex, operator allowlist).** More expressive, more matcher
  complexity. Deferred; suffix + honored `@@` exceptions cover the chosen sources.
- **Periodic refresh / SIGHUP reload / disk cache.** Turns a static feature into an appliance
  refresh scheduler. Rejected for v1 as out of step with "not dynamic"; disk cache noted as a
  cheap future resilience add.
- **Per-list attribution in the UI.** Track which source blocked each name. Rejected: the
  operator does not need it, and merging to one deduplicated set is simpler.
