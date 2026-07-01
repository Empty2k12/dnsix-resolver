//! Client access control: an optional allowlist of IPv6 networks permitted to
//! query the Forwarder.
//!
//! An empty allowlist means "allow every client" — the historical behaviour, an
//! open resolver on whatever interface the Listen address binds. When one or more
//! networks are configured, a client whose address falls in none of them is
//! **REFUSED** before any cache lookup or upstream query, making the DNS trust
//! boundary explicit rather than purely a matter of where the socket is bound.
//!
//! The Listen interface is IPv6-only (IPv4-mapped acceptance is disabled), so
//! clients are always IPv6 and the allowlist carries only IPv6 prefixes; an IPv4
//! entry can never match and is rejected at load.

use std::net::{IpAddr, Ipv6Addr};

/// One IPv6 CIDR network.
#[derive(Debug, Clone, Copy)]
struct Net6 {
    /// Network address with the host bits already masked off.
    base: u128,
    /// Prefix length in bits, `0..=128`.
    prefix: u32,
}

impl Net6 {
    fn contains(&self, addr: Ipv6Addr) -> bool {
        (u128::from(addr) & mask(self.prefix)) == self.base
    }
}

/// The all-ones/host mask for a prefix length. A `/0` masks nothing (matches all);
/// avoids the undefined `u128 << 128` shift.
fn mask(prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// A parsed client allowlist. Empty = allow every client.
#[derive(Debug, Clone, Default)]
pub struct ClientAcl {
    nets: Vec<Net6>,
}

impl ClientAcl {
    /// Parse CIDR strings (e.g. `"2001:db8::/32"`; a bare address is treated as a
    /// `/128` host route). Returns an error naming the offending entry — including
    /// a targeted message for an IPv4 entry, which the IPv6-only listener could
    /// never match.
    pub fn parse(entries: &[String]) -> anyhow::Result<Self> {
        let mut nets = Vec::with_capacity(entries.len());
        for e in entries {
            nets.push(parse_net6(e)?);
        }
        Ok(Self { nets })
    }

    /// Whether `client` may query: always when the allowlist is empty, otherwise
    /// only when the address falls in one of the configured networks. A non-IPv6
    /// client (which the IPv6-only listener never yields) is denied once an
    /// allowlist is set.
    pub fn allows(&self, client: IpAddr) -> bool {
        if self.nets.is_empty() {
            return true;
        }
        match client {
            IpAddr::V6(v6) => self.nets.iter().any(|n| n.contains(v6)),
            IpAddr::V4(_) => false,
        }
    }

    /// True when no networks are configured (allow-all).
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }
}

fn parse_net6(entry: &str) -> anyhow::Result<Net6> {
    let (addr_part, prefix) = match entry.split_once('/') {
        Some((a, p)) => {
            let prefix: u32 = p.parse().map_err(|_| {
                anyhow::anyhow!("client_networks: invalid prefix length in {entry:?}")
            })?;
            (a, prefix)
        }
        None => (entry, 128),
    };
    if prefix > 128 {
        anyhow::bail!("client_networks: prefix /{prefix} exceeds 128 in {entry:?}");
    }
    let addr: Ipv6Addr = addr_part.parse().map_err(|_| {
        if addr_part.parse::<std::net::Ipv4Addr>().is_ok() {
            anyhow::anyhow!(
                "client_networks entry {entry:?} is IPv4; the listener is IPv6-only, \
                 so only IPv6 networks can match clients"
            )
        } else {
            anyhow::anyhow!("client_networks: {entry:?} is not a valid IPv6 network")
        }
    })?;
    Ok(Net6 {
        base: u128::from(addr) & mask(prefix),
        prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from_str(s).unwrap())
    }

    #[test]
    fn empty_allowlist_allows_everyone() {
        let acl = ClientAcl::parse(&[]).unwrap();
        assert!(acl.is_empty());
        assert!(acl.allows(v6("2001:db8::1")));
        assert!(acl.allows(v6("::1")));
    }

    #[test]
    fn matches_within_prefix_and_rejects_outside() {
        let acl = ClientAcl::parse(&["2001:db8::/32".to_string()]).unwrap();
        assert!(acl.allows(v6("2001:db8::1")));
        assert!(acl.allows(v6("2001:db8:ffff::abcd")));
        assert!(!acl.allows(v6("2001:db9::1")));
        assert!(!acl.allows(v6("fe80::1")));
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let acl = ClientAcl::parse(&["2001:db8::5".to_string()]).unwrap();
        assert!(acl.allows(v6("2001:db8::5")));
        assert!(!acl.allows(v6("2001:db8::6")));
    }

    #[test]
    fn multiple_networks_union() {
        let acl = ClientAcl::parse(&[
            "2001:db8::/64".to_string(),
            "fd00::/8".to_string(),
            "::1/128".to_string(),
        ])
        .unwrap();
        assert!(acl.allows(v6("2001:db8::abcd")));
        assert!(acl.allows(v6("fd12::1")));
        assert!(acl.allows(v6("::1")));
        assert!(!acl.allows(v6("2001:dead::1")));
    }

    #[test]
    fn ipv4_client_is_denied_when_allowlist_set() {
        let acl = ClientAcl::parse(&["2001:db8::/32".to_string()]).unwrap();
        assert!(!acl.allows("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_entry_is_rejected_with_targeted_error() {
        let err = ClientAcl::parse(&["192.0.2.0/24".to_string()]).unwrap_err();
        assert!(err.to_string().contains("IPv6-only"), "{err}");
    }

    #[test]
    fn garbage_and_oversize_prefix_are_rejected() {
        assert!(ClientAcl::parse(&["not-an-addr".to_string()]).is_err());
        assert!(ClientAcl::parse(&["2001:db8::/200".to_string()]).is_err());
        assert!(ClientAcl::parse(&["2001:db8::/xyz".to_string()]).is_err());
    }

    #[test]
    fn zero_prefix_matches_all() {
        let acl = ClientAcl::parse(&["::/0".to_string()]).unwrap();
        assert!(acl.allows(v6("2001:db8::1")));
        assert!(acl.allows(v6("fe80::1")));
    }
}
