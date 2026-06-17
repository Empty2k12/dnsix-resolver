//! Configuration, loaded from a TOML file.

use std::net::{Ipv6Addr, SocketAddr};

use serde::Deserialize;

/// The well-known NAT64 prefix (RFC 6052 / RFC 6147), the default and the prefix
/// this operator runs.
pub const WELL_KNOWN_NAT64_PREFIX: Ipv6Addr = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the Forwarder listens on for client queries. Must be IPv6 — the
    /// Listen interface is IPv6-only by design.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// NAT64 prefix to embed IPv4 addresses into. Only `/96` is supported, so this
    /// is the network address with the low 32 bits zero.
    #[serde(default = "default_prefix")]
    pub nat64_prefix: Ipv6Addr,

    /// Optional cap on the TTL of synthesized AAAA records. `None` = inherit the A
    /// record's TTL uncapped.
    #[serde(default)]
    pub ttl_cap: Option<u32>,

    /// Explicit list of upstream resolvers, tried in order with failover. May be
    /// IPv4 or IPv6 — the upstream path is independent of the IPv6-only listener.
    pub upstreams: Vec<SocketAddr>,

    /// Maximum number of cached upstream answers, where each cached name+type is
    /// one entry. `0` disables the response cache. The cache is positive-only and
    /// bypassed for DNSSEC-aware (DO-bit) queries.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    /// Serve-stale (RFC 8767): when an upstream refresh is slow or failing, answer
    /// from expired cache rather than failing the query. A stale answer is returned
    /// only after a short client-response timer (so a healthy upstream still wins),
    /// carries a brief TTL so it self-corrects, and is served for at most ~1 day
    /// past expiry. Needs the cache (`cache_size > 0`) to have anything to fall back
    /// on. Default `true`.
    #[serde(default = "default_serve_stale")]
    pub serve_stale: bool,

    /// Ordered list of enabled Synthesizers (config order = chain precedence;
    /// `nat64` is just an entry, intended last). Absent = `["nat64"]`, i.e. the
    /// original DNS64-only behaviour.
    #[serde(default = "default_synthesizers")]
    pub synthesizers: Vec<String>,

    /// When a CDN Provider synthesizes a native-IPv6 AAAA, also append the
    /// NAT64-embedded address as a fallback (CDN-native ordered first), so a
    /// broken CDN-native edge degrades to reachable-via-translator: the client's
    /// RFC 6724 / Happy Eyeballs logic prefers the native address and uses the
    /// NAT64 one only if native won't connect. Only takes effect when `nat64` is
    /// among the enabled `synthesizers` (i.e. a NAT64 translator exists);
    /// otherwise it is a no-op. Default `true`.
    #[serde(default = "default_nat64_fallback")]
    pub nat64_fallback: bool,

    /// Optional address for the Prometheus metrics endpoint (`GET /metrics`).
    /// Absent = metrics server disabled. On an IPv6-only host use an IPv6 address
    /// (e.g. `[::]:9153`).
    #[serde(default)]
    pub metrics_listen: Option<SocketAddr>,

    /// Log verbosity, as a `tracing` env-filter directive (e.g. `"off"`, `"warn"`,
    /// `"info"`, `"debug"`, or per-target like `"dnsix=debug"`). Logging is opt-in:
    /// the default is `"off"`, so nothing is written unless you raise it. The
    /// `RUST_LOG` environment variable, if set, overrides this. Fatal startup
    /// errors are always reported on stderr regardless of this setting.
    #[serde(default = "default_log")]
    pub log: String,
}

fn default_listen() -> SocketAddr {
    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 53)
}

fn default_prefix() -> Ipv6Addr {
    WELL_KNOWN_NAT64_PREFIX
}

fn default_cache_size() -> usize {
    4096
}

fn default_serve_stale() -> bool {
    true
}

fn default_synthesizers() -> Vec<String> {
    vec!["nat64".to_string()]
}

fn default_nat64_fallback() -> bool {
    true
}

fn default_log() -> String {
    "off".to_string()
}

impl Config {
    /// Parse a TOML config and validate the invariants we rely on elsewhere.
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if !self.listen.is_ipv6() {
            anyhow::bail!(
                "listen address {} is not IPv6; the Forwarder serves clients over IPv6 only",
                self.listen
            );
        }
        if self.upstreams.is_empty() {
            anyhow::bail!("at least one upstream resolver must be configured");
        }
        // We only support /96 embedding, so the low 32 bits of the prefix must be zero.
        if self.nat64_prefix.octets()[12..16] != [0, 0, 0, 0] {
            anyhow::bail!(
                "nat64_prefix {} has non-zero low 32 bits; only /96 prefixes are supported",
                self.nat64_prefix
            );
        }
        // A NAT64-embedded address inherits the prefix's high bits, so a non-global
        // prefix (loopback/link-local/ULA/multicast) would produce addresses the
        // synthesis filter strips — yielding silent empty answers. Reject it loudly.
        if !crate::synth::is_global_unicast_v6(self.nat64_prefix) {
            anyhow::bail!(
                "nat64_prefix {} is not globally-routable IPv6; embedded addresses would be \
                 unservable (synthesis drops loopback/link-local/ULA/multicast)",
                self.nat64_prefix
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = Config::from_toml("upstreams = [\"192.0.2.1:53\"]").unwrap();
        assert_eq!(cfg.listen, "[::]:53".parse().unwrap());
        assert_eq!(cfg.nat64_prefix, WELL_KNOWN_NAT64_PREFIX);
        assert_eq!(cfg.ttl_cap, None);
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.cache_size, 4096);
        assert!(cfg.serve_stale);
    }

    #[test]
    fn serve_stale_defaults_on_and_parses() {
        let cfg = Config::from_toml("upstreams = [\"192.0.2.1:53\"]").unwrap();
        assert!(cfg.serve_stale);

        let cfg = Config::from_toml("serve_stale = false\nupstreams = [\"192.0.2.1:53\"]").unwrap();
        assert!(!cfg.serve_stale);
    }

    #[test]
    fn metrics_listen_defaults_off_and_parses() {
        let cfg = Config::from_toml("upstreams = [\"192.0.2.1:53\"]").unwrap();
        assert_eq!(cfg.metrics_listen, None);

        let cfg =
            Config::from_toml("metrics_listen = \"[::]:9153\"\nupstreams = [\"192.0.2.1:53\"]")
                .unwrap();
        assert_eq!(cfg.metrics_listen, "[::]:9153".parse().ok());
    }

    #[test]
    fn log_defaults_off_and_parses() {
        let cfg = Config::from_toml("upstreams = [\"192.0.2.1:53\"]").unwrap();
        assert_eq!(cfg.log, "off");

        let cfg =
            Config::from_toml("log = \"dnsix=debug\"\nupstreams = [\"192.0.2.1:53\"]").unwrap();
        assert_eq!(cfg.log, "dnsix=debug");
    }

    #[test]
    fn nat64_fallback_defaults_on_and_parses() {
        let cfg = Config::from_toml("upstreams = [\"192.0.2.1:53\"]").unwrap();
        assert!(cfg.nat64_fallback);

        let cfg =
            Config::from_toml("nat64_fallback = false\nupstreams = [\"192.0.2.1:53\"]").unwrap();
        assert!(!cfg.nat64_fallback);
    }

    #[test]
    fn cache_can_be_disabled() {
        let cfg = Config::from_toml("cache_size = 0\nupstreams = [\"192.0.2.1:53\"]").unwrap();
        assert_eq!(cfg.cache_size, 0);
    }

    #[test]
    fn rejects_ipv4_listen() {
        let err = Config::from_toml("listen = \"0.0.0.0:53\"\nupstreams = [\"192.0.2.1:53\"]")
            .unwrap_err();
        assert!(err.to_string().contains("IPv6 only"));
    }

    #[test]
    fn rejects_empty_upstreams() {
        let err = Config::from_toml("upstreams = []").unwrap_err();
        assert!(err.to_string().contains("upstream"));
    }

    #[test]
    fn rejects_non_96_prefix() {
        let err =
            Config::from_toml("nat64_prefix = \"64:ff9b::1\"\nupstreams = [\"192.0.2.1:53\"]")
                .unwrap_err();
        assert!(err.to_string().contains("/96"));
    }

    #[test]
    fn rejects_non_global_prefix() {
        // A ULA /96 prefix is well-formed but its embedded addresses would be
        // filtered out at synthesis time, so it must be rejected at startup.
        let err = Config::from_toml("nat64_prefix = \"fd00:64::\"\nupstreams = [\"192.0.2.1:53\"]")
            .unwrap_err();
        assert!(err.to_string().contains("globally-routable"));
    }
}
