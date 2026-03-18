use std::{fmt, net::IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCollector {
    Ebpf,
}

impl fmt::Display for NetworkCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Ebpf => "ebpf",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveBoundary {
    pub collector: NetworkCollector,
    pub raw_fields: Vec<&'static str>,
    pub raw_connect_kinds: Vec<&'static str>,
    pub address_families: Vec<&'static str>,
}

impl ObserveBoundary {
    pub fn outbound_connect_poc() -> Self {
        Self {
            collector: NetworkCollector::Ebpf,
            raw_fields: vec![
                "pid",
                "sock_fd",
                "address_family",
                "transport",
                "destination_addr",
                "destination_port",
            ],
            raw_connect_kinds: vec!["connect"],
            address_families: vec!["inet", "inet6"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationBoundary {
    pub collector: NetworkCollector,
    pub semantic_fields: Vec<&'static str>,
    pub emitted_verbs: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationScope {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Public,
}

impl DestinationScope {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => {
                if ip.is_loopback() {
                    Self::Loopback
                } else if ip.is_private() {
                    Self::Private
                } else if ip.is_link_local() {
                    Self::LinkLocal
                } else if ip.is_multicast() {
                    Self::Multicast
                } else {
                    Self::Public
                }
            }
            IpAddr::V6(ip) => {
                if ip.is_loopback() {
                    Self::Loopback
                } else if ip.is_unique_local() {
                    Self::Private
                } else if ip.is_unicast_link_local() {
                    Self::LinkLocal
                } else if ip.is_multicast() {
                    Self::Multicast
                } else {
                    Self::Public
                }
            }
        }
    }
}

impl fmt::Display for DestinationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link_local",
            Self::Multicast => "multicast",
            Self::Public => "public",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedNetworkConnect {
    pub pid: u32,
    pub sock_fd: u32,
    pub destination_ip: String,
    pub destination_port: u16,
    pub transport: String,
    pub address_family: String,
    pub destination_scope: DestinationScope,
    pub domain_candidate: Option<String>,
    pub domain_attribution_source: Option<String>,
}
