# Zabbix monitoring for dnsix

`template_dnsix.yaml` is an importable Zabbix template (export format **7.0**) that
monitors the dnsix Prometheus metrics endpoint described in
[ADR 0004](../docs/adr/0004-metrics-endpoint.md).

It scrapes `GET /metrics` **once** per interval with a single HTTP-agent master item;
every number is a dependent item or an LLD prototype parsed from that one scrape via
Zabbix's *Prometheus pattern* / *Prometheus to JSON* preprocessing.

## Import

1. In Zabbix: **Data collection → Templates → Import**, select
   `zabbix/template_dnsix.yaml`. Tested against Zabbix 7.0; for 6.0/6.4 change the
   `version:` field at the top of the file to `6.0` / `6.4` (the item, LLD, and
   preprocessing schema used here is compatible).
2. Link the template **dnsix by HTTP** to the host running dnsix.
3. Set the host macros (defaults shown):

   | Macro | Default | Notes |
   |-------|---------|-------|
   | `{$DNSIX.METRICS.HOST}` | `[::1]` | **IPv6 literals must be bracketed** — this deployment is IPv6-only. Use the firewalled/loopback address the endpoint binds. |
   | `{$DNSIX.METRICS.PORT}` | `9153` | Must match `metrics_listen` in dnsix's `config.toml`. |
   | `{$DNSIX.UPSTREAM.FAIL.WINDOW}` | `5m` | Window over which a counter increase raises the upstream-failure trigger. |

The endpoint is **unauthenticated** (ADR 0004), so point it at a loopback or
firewalled bind. The master item's URL is
`http://{$DNSIX.METRICS.HOST}:{$DNSIX.METRICS.PORT}/metrics`.

## What gets discovered

Four LLD rules turn the label-bearing metric families into items automatically. Each
rule is a dependent item on the master scrape with a *Prometheus to JSON* step; the
label becomes an LLD macro, and the item prototype pulls the matching series with a
*Prometheus pattern* step.

| Discovery rule | Metric family | LLD macro | Item prototype key |
|----------------|---------------|-----------|--------------------|
| Discover query kinds | `dns_queries_total{kind}` | `{#KIND}` | `dnsix.queries[{#KIND}]` |
| Discover query types | `dns_queries_by_qtype_total{qtype}` | `{#QTYPE}` | `dnsix.queries_by_qtype[{#QTYPE}]` |
| Discover response codes | `dns_responses_total{rcode}` | `{#RCODE}` | `dnsix.responses[{#RCODE}]` |
| Discover synthesizers | `synth_hits_total{synthesizer}` | `{#SYNTHESIZER}` | `dnsix.synth_hits[{#SYNTHESIZER}]` |

The **synthesizer** rule is the headline: dnsix emits one `synth_hits_total` series per
*enabled* synthesizer (config order, including `nat64`), so adding a new CDN provider
to the chain makes a new item appear with no template edit — and a provider that never
fires shows up as a flat zero, which is exactly the "is it earning its place" signal
ADR 0004 wanted.

## Scalar (unlabeled) items

These have no labels, so they are plain dependent items rather than discovery:

`dnsix.upstream_failed_total`, `dnsix.cache_hits_total`, `dnsix.cache_misses_total`,
`dnsix.dns64_native_aaaa_total`, `dnsix.dns64_nxdomain_total`,
`dnsix.dns64_nodata_total`, `dnsix.dns64_synthesized_total`, `dnsix.dns64_empty_total`.

## Rates, not totals

dnsix exposes monotonic (ever-climbing) counters, but every item here stores a
**per-second rate**, not the absolute total. Each item (scalar and prototype) has two
preprocessing steps:

1. *Prometheus pattern* — pull the series out of the scrape as a number.
2. *Change per second* — `(value − prev) / Δt`.

Items are therefore `value_type: FLOAT` with unit `/s`. A dnsix restart resets the
counter to 0; *Change per second* discards that one negative delta and resumes on the
next sample, so a restart costs a single missing point, not a spike.

If you ever want the raw total back for one item, delete its *Change per second* step
in the item's **Preprocessing** tab and set the value type to *Numeric (unsigned)*.

## Triggers

- **Metrics endpoint unreachable** (HIGH) — `nodata(...,5m)` on the master scrape.
- **Upstream failures occurring** (AVERAGE) — a non-zero `dns_upstream_failed_total`
  rate within `{$DNSIX.UPSTREAM.FAIL.WINDOW}`.

### Adding a SERVFAIL alert

A per-RCODE trigger isn't shipped because a trigger prototype attaches to *every*
discovered RCODE (an increasing `noerror` counter is normal and would alert constantly).
After first discovery the `dnsix.responses[servfail]` item exists, so add a regular
trigger on the host/template:

```
max(/dnsix by HTTP/dnsix.responses[servfail],5m)>0
```
