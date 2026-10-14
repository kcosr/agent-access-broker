use agent_access_core::SourceContext;
use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(crate) struct SourceResolver {
    trusted_proxies: Vec<TrustedProxy>,
}

impl SourceResolver {
    pub(crate) fn new(entries: &[String]) -> Self {
        Self {
            trusted_proxies: entries
                .iter()
                .filter_map(|entry| TrustedProxy::parse(entry))
                .collect(),
        }
    }

    pub(crate) fn source_context(
        &self,
        remote_addr: SocketAddr,
        headers: &HeaderMap,
    ) -> SourceContext {
        let proxy_chain = forwarded_chain(headers);
        let trusted_source = self.trusted_proxy_source(remote_addr.ip(), &proxy_chain);
        SourceContext {
            listener: "http".to_string(),
            remote: trusted_source
                .map(|source| source.to_string())
                .unwrap_or_else(|| remote_addr.to_string()),
            proxy_chain: trusted_source
                .map(|_| proxy_chain.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            agent_request_id_generated: None,
        }
    }

    fn trusted_proxy_source(&self, remote: IpAddr, chain: &[IpAddr]) -> Option<IpAddr> {
        if !self.is_trusted(remote) || chain.is_empty() {
            return None;
        }
        for candidate in chain.iter().rev() {
            if !self.is_trusted(*candidate) {
                return Some(*candidate);
            }
        }
        chain.first().copied()
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|proxy| proxy.matches(ip))
    }
}

/// The well-known NAT64 prefix `64:ff9b::/96` (RFC 6052): the top 96 bits of
/// an IPv6 address, as a 96-bit value.
const NAT64_WELL_KNOWN_PREFIX: u128 = 0x0064_ff9b_0000_0000_0000_0000;

/// Groups the resolved client address (after `trusted_proxies`) for every
/// authentication-class budget (`auth_requests_per_source_per_minute`, the
/// login `(principal, source)` budget) and local-password lockouts. IPv4
/// uses the full address and IPv6 its /64 prefix, so rotating addresses
/// within one allocation does not reset a count. IPv4-mapped addresses and
/// addresses in the well-known NAT64 prefix `64:ff9b::/96` use their embedded
/// IPv4 address. Logs and audit keep the full address.
pub(crate) fn auth_source_key(source: &SourceContext) -> String {
    let address = source
        .remote
        .parse::<SocketAddr>()
        .map(|address| address.ip())
        .or_else(|_| source.remote.parse::<IpAddr>());
    match address.map(|address| address.to_canonical()) {
        Ok(IpAddr::V4(address)) => address.to_string(),
        Ok(IpAddr::V6(address)) => {
            let bits = u128::from(address);
            if bits >> 32 == NAT64_WELL_KNOWN_PREFIX {
                return Ipv4Addr::from(bits as u32).to_string();
            }
            let prefix = Ipv6Addr::from(bits & (u128::MAX << 64));
            format!("{prefix}/64")
        }
        Err(_) => "unknown".to_string(),
    }
}

#[derive(Debug, Clone)]
pub(crate) enum TrustedProxy {
    Address(IpAddr),
    Cidr(IpAddr, u8),
}

impl TrustedProxy {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value == "*" {
            return None;
        }
        if let Some((addr, prefix)) = value.split_once('/') {
            let addr = addr.parse().ok()?;
            let prefix = prefix.parse().ok()?;
            let max_prefix = if matches!(addr, IpAddr::V4(_)) {
                32
            } else {
                128
            };
            if prefix == 0 || prefix > max_prefix {
                return None;
            }
            return Some(Self::Cidr(addr, prefix));
        }
        Some(Self::Address(value.parse().ok()?))
    }

    fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Address(address) => *address == ip,
            Self::Cidr(network, prefix) => ip_in_cidr(ip, *network, *prefix),
        }
    }
}

fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

fn forwarded_chain(headers: &HeaderMap) -> Vec<IpAddr> {
    if let Some(value) = single_header_value(headers, "Forwarded") {
        let chain = parse_forwarded_header(value);
        if !chain.is_empty() {
            return chain;
        }
    }
    single_header_value(headers, "X-Forwarded-For")
        .map(parse_x_forwarded_for)
        .unwrap_or_default()
}

fn single_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

fn parse_forwarded_header(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .filter_map(|entry| {
            entry.split(';').find_map(|part| {
                let (key, value) = part.trim().split_once('=')?;
                key.eq_ignore_ascii_case("for")
                    .then(|| parse_forwarded_ip(value.trim()))
                    .flatten()
            })
        })
        .collect()
}

fn parse_x_forwarded_for(value: &str) -> Vec<IpAddr> {
    value.split(',').filter_map(parse_forwarded_ip).collect()
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if let Some(bracketed) = value.strip_prefix('[') {
        let (ip, _) = bracketed.split_once(']')?;
        return ip.parse().ok();
    }
    if let Ok(socket) = value.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    value.parse().ok()
}
