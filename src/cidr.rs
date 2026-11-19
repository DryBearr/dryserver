//! IPv4 addresses and subnets.

use std::net::Ipv4Addr;

/// Parses a dotted IPv4 address. Like Go's net.ParseIP plus To4, it also
/// accepts the IPv4-mapped IPv6 form ::ffff:a.b.c.d.
pub fn parse_ip4(s: &str) -> Option<Ipv4Addr> {
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    match s.parse::<std::net::Ipv6Addr>() {
        Ok(ip6) => ip6.to_ipv4_mapped(),
        Err(_) => None,
    }
}

/// An IPv4 subnet as written in CIDR form: the address may have host bits
/// set ("10.66.0.5/24").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: u32,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, bits) = s.split_once('/')?;
        if bits.is_empty() || bits.len() > 2 || !bits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = bits.parse().ok()?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some(Cidr { addr: u32::from(ip), prefix })
    }

    pub fn mask(&self) -> u32 {
        if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) }
    }

    pub fn network(&self) -> u32 {
        self.addr & self.mask()
    }

    /// Number of addresses in the subnet.
    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == self.network()
    }

    /// The network in CIDR form, e.g. "10.66.0.0/24".
    pub fn network_string(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network()), self.prefix)
    }

    pub fn network_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network())
    }
}
