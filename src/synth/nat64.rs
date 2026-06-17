//! The NAT64 Synthesizer: embed an eligible IPv4 address into the NAT64 prefix
//! (RFC 6147 / RFC 6052). This is the original DNS64 behaviour, now one entry in
//! the chain — the intended last (fallback) one, used when no Provider matches.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::Name;

use super::{Plan, SynthContext, Synthesizer};

/// `ipv4only.arpa.` — the RFC 7050 name hosts query to discover the NAT64 prefix.
/// Its A records are non-global, but we synthesize for it anyway so 464XLAT/CLAT
/// clients can learn the prefix.
pub fn is_ipv4only_arpa(name: &Name) -> bool {
    name.to_ascii().eq_ignore_ascii_case("ipv4only.arpa.")
}

/// Whether an IPv4 address may be embedded into the NAT64 prefix.
///
/// Non-global addresses (private, loopback, link-local, CGNAT, multicast,
/// reserved, documentation, broadcast, "this network") must not be translated
/// through the well-known prefix (RFC 6052 §3.1). We apply the filter for any
/// prefix — translating private space across NAT64 is virtually never intended.
pub fn is_globally_routable(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(
        o[0] == 0                                   // 0.0.0.0/8   "this network"
        || ip.is_private()                          // 10/8, 172.16/12, 192.168/16
        || (o[0] == 100 && (o[1] & 0xc0) == 64)     // 100.64/10   CGNAT (RFC 6598)
        || ip.is_loopback()                         // 127/8
        || ip.is_link_local()                       // 169.254/16
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)  // 192.0.0/24  IETF protocol assignments
        || ip.is_documentation()                    // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18)     // 198.18/15   benchmarking
        || ip.is_multicast()                        // 224/4
        || o[0] >= 240
        // 240/4 reserved + 255.255.255.255 broadcast
    )
}

/// Embed an IPv4 address into a `/96` NAT64 prefix: `prefix | ipv4`.
pub fn embed(prefix: Ipv6Addr, ip: Ipv4Addr) -> Ipv6Addr {
    let mut octets = prefix.octets();
    octets[12..16].copy_from_slice(&ip.octets());
    Ipv6Addr::from(octets)
}

/// Decide which of a name's A addresses are eligible for embedding.
///
/// Normally only globally-routable addresses are eligible. For `ipv4only.arpa`
/// the global-routability filter is bypassed (RFC 7050 prefix discovery).
pub fn eligible_addresses(name: &Name, a_records: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    if is_ipv4only_arpa(name) {
        return a_records.to_vec();
    }
    a_records
        .iter()
        .copied()
        .filter(|ip| is_globally_routable(*ip))
        .collect()
}

/// The NAT64 prefix-embedding Synthesizer.
pub struct Nat64 {
    prefix: Ipv6Addr,
}

impl Nat64 {
    pub fn new(prefix: Ipv6Addr) -> Self {
        Self { prefix }
    }
}

impl Synthesizer for Nat64 {
    fn id(&self) -> &'static str {
        "nat64"
    }

    fn detect(&self, ctx: &SynthContext) -> Option<Plan> {
        if ctx.a_records.is_empty() {
            return None;
        }
        let prefix = self.prefix;
        let name = ctx.name.clone();
        Some(Plan::pure(Box::new(move |_resolved, v4| {
            eligible_addresses(&name, v4)
                .into_iter()
                .map(|ip| embed(prefix, ip))
                .collect()
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const WK: Ipv6Addr = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0);

    #[test]
    fn embeds_into_well_known_prefix() {
        let v6 = embed(WK, Ipv4Addr::new(192, 0, 2, 33));
        assert_eq!(v6, "64:ff9b::c000:221".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn embeds_into_network_specific_prefix() {
        let prefix = "2001:db8:64::".parse().unwrap();
        let v6 = embed(prefix, Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(v6, "2001:db8:64::cb00:7105".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn global_addresses_are_routable() {
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "203.0.114.1"] {
            assert!(
                is_globally_routable(ip.parse().unwrap()),
                "{ip} should be routable"
            );
        }
    }

    #[test]
    fn non_global_addresses_are_filtered() {
        for ip in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.170",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !is_globally_routable(ip.parse().unwrap()),
                "{ip} should be filtered"
            );
        }
    }

    #[test]
    fn ipv4only_arpa_bypasses_filter() {
        let name = Name::from_str("ipv4only.arpa.").unwrap();
        let addrs = vec![Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];
        assert!(eligible_addresses(&Name::from_str("example.com.").unwrap(), &addrs).is_empty());
        assert_eq!(eligible_addresses(&name, &addrs), addrs);
    }

    #[test]
    fn eligible_addresses_filters_mixed_set() {
        let name = Name::from_str("dual.example.com.").unwrap();
        let addrs = vec![
            Ipv4Addr::new(10, 0, 0, 1),      // filtered
            Ipv4Addr::new(93, 184, 216, 34), // kept
        ];
        assert_eq!(
            eligible_addresses(&name, &addrs),
            vec![Ipv4Addr::new(93, 184, 216, 34)]
        );
    }

    fn ctx(name: &str, addrs: &[Ipv4Addr]) -> SynthContext {
        SynthContext::new(
            Name::from_str(name).unwrap(),
            vec![],
            addrs.iter().map(|ip| (*ip, 300)).collect(),
            Default::default(),
        )
    }

    #[test]
    fn detect_embeds_eligible_only() {
        let nat = Nat64::new(WK);
        let c = ctx(
            "dual.example.com.",
            &[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(93, 184, 216, 34)],
        );
        let plan = nat.detect(&c).expect("nat64 always plans when A present");
        let out = (plan.combine)(&[], &c.a_addrs());
        assert_eq!(out, vec!["64:ff9b::5db8:d822".parse::<Ipv6Addr>().unwrap()]);
    }

    #[test]
    fn detect_none_without_a_records() {
        let nat = Nat64::new(WK);
        assert!(nat.detect(&ctx("x.example.com.", &[])).is_none());
    }
}
