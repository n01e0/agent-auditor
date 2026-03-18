use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use agent_auditor_hostd_ebpf as poc_ebpf;

use super::contract::{NetworkCollector, ObserveBoundary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Inet,
    Inet6,
}

impl AddressFamily {
    fn from_raw(value: u16) -> Result<Self, ObserveDecodeError> {
        match value {
            poc_ebpf::AF_INET => Ok(Self::Inet),
            poc_ebpf::AF_INET6 => Ok(Self::Inet6),
            actual => Err(ObserveDecodeError::UnsupportedAddressFamily { actual }),
        }
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Inet => "inet",
            Self::Inet6 => "inet6",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    fn from_raw(value: u16) -> Result<Self, ObserveDecodeError> {
        match value {
            poc_ebpf::IPPROTO_TCP => Ok(Self::Tcp),
            poc_ebpf::IPPROTO_UDP => Ok(Self::Udp),
            actual => Err(ObserveDecodeError::UnsupportedTransport { actual }),
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEvent {
    pub pid: u32,
    pub sock_fd: u32,
    pub address_family: AddressFamily,
    pub transport: TransportProtocol,
    pub destination: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredConnectEvent {
    pub raw_len: usize,
    pub event: ConnectEvent,
    pub log_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveDecodeError {
    WrongLength {
        event_kind: &'static str,
        expected: usize,
        actual: usize,
    },
    UnsupportedAddressFamily {
        actual: u16,
    },
    UnsupportedTransport {
        actual: u16,
    },
}

impl fmt::Display for ObserveDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength {
                event_kind,
                expected,
                actual,
            } => write!(
                f,
                "invalid {event_kind} event length: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAddressFamily { actual } => {
                write!(f, "unsupported address family for connect event: {actual}")
            }
            Self::UnsupportedTransport { actual } => {
                write!(f, "unsupported transport for connect event: {actual}")
            }
        }
    }
}

impl Error for ObserveDecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservePlan {
    pub collector: NetworkCollector,
    pub attach_scope: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    handoff: ObserveBoundary,
}

impl Default for ObservePlan {
    fn default() -> Self {
        Self {
            collector: NetworkCollector::Ebpf,
            attach_scope: vec!["outbound IPv4 connect hooks", "outbound IPv6 connect hooks"],
            responsibilities: vec![
                "attach outbound-connect eBPF programs and own their kernel-facing lifecycle",
                "capture raw socket-connect tuples and transport hints from connect attempts",
                "preserve pid and socket context needed for later session attribution",
                "handoff raw outbound-connect candidates without domain or policy semantics",
            ],
            handoff: ObserveBoundary::outbound_connect_poc(),
        }
    }
}

impl ObservePlan {
    pub fn handoff(&self) -> ObserveBoundary {
        self.handoff.clone()
    }

    pub fn deliver_connect_to_log(
        &self,
        bytes: &[u8],
    ) -> Result<DeliveredConnectEvent, ObserveDecodeError> {
        let event = ConnectEvent::from_bytes(bytes)?;
        let log_line = event.log_line(self.collector);

        Ok(DeliveredConnectEvent {
            raw_len: bytes.len(),
            event,
            log_line,
        })
    }

    pub fn preview_connect_delivery(&self) -> Result<DeliveredConnectEvent, ObserveDecodeError> {
        let fixture = poc_ebpf::fixture_connect_event_bytes();
        self.deliver_connect_to_log(&fixture)
    }

    pub fn summary(&self) -> String {
        format!(
            "collector={} hooks={} raw_fields={} raw_connect_kinds={} address_families={}",
            self.collector,
            self.attach_scope.join(","),
            self.handoff.raw_fields.join(","),
            self.handoff.raw_connect_kinds.join(","),
            self.handoff.address_families.join(",")
        )
    }
}

impl ConnectEvent {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ObserveDecodeError> {
        if bytes.len() != poc_ebpf::CONNECT_EVENT_LEN {
            return Err(ObserveDecodeError::WrongLength {
                event_kind: "connect",
                expected: poc_ebpf::CONNECT_EVENT_LEN,
                actual: bytes.len(),
            });
        }

        let pid = read_u32(bytes, 0);
        let sock_fd = read_u32(bytes, 4);
        let address_family = AddressFamily::from_raw(read_u16(bytes, 8))?;
        let transport = TransportProtocol::from_raw(read_u16(bytes, 10))?;
        let destination_port = read_u16(bytes, 12);
        let destination = socket_addr_from_bytes(address_family, &bytes[16..32], destination_port);

        Ok(Self {
            pid,
            sock_fd,
            address_family,
            transport,
            destination,
        })
    }

    pub fn log_line(&self, collector: NetworkCollector) -> String {
        format!(
            "event=network.connect collector={} pid={} fd={} family={} transport={} destination={}",
            collector,
            self.pid,
            self.sock_fd,
            self.address_family,
            self.transport,
            self.destination
        )
    }
}

fn socket_addr_from_bytes(address_family: AddressFamily, bytes: &[u8], port: u16) -> SocketAddr {
    match address_family {
        AddressFamily::Inet => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            port,
        ),
        AddressFamily::Inet6 => {
            let octets: [u8; poc_ebpf::CONNECT_ADDR_LEN] = bytes[..poc_ebpf::CONNECT_ADDR_LEN]
                .try_into()
                .expect("slice length should match");
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
    }
}

fn read_u32(bytes: &[u8], start: usize) -> u32 {
    u32::from_le_bytes(
        bytes[start..start + 4]
            .try_into()
            .expect("slice length should match"),
    )
}

fn read_u16(bytes: &[u8], start: usize) -> u16 {
    u16::from_le_bytes(
        bytes[start..start + 2]
            .try_into()
            .expect("slice length should match"),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use agent_auditor_hostd_ebpf as poc_ebpf;

    use super::{AddressFamily, ConnectEvent, ObserveDecodeError, ObservePlan, TransportProtocol};

    #[test]
    fn connect_fixture_decodes_into_outbound_destination_metadata() {
        let event = ConnectEvent::from_bytes(&poc_ebpf::fixture_connect_event_bytes())
            .expect("fixture connect event should decode");

        assert_eq!(event.pid, 4242);
        assert_eq!(event.sock_fd, 7);
        assert_eq!(event.address_family, AddressFamily::Inet);
        assert_eq!(event.transport, TransportProtocol::Tcp);
        assert_eq!(
            event.destination,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)
        );
    }

    #[test]
    fn preview_connect_delivery_emits_a_network_connect_log_line() {
        let plan = ObservePlan::default();
        let delivered = plan
            .preview_connect_delivery()
            .expect("fixture connect delivery should succeed");

        assert_eq!(delivered.raw_len, poc_ebpf::CONNECT_EVENT_LEN);
        assert_eq!(delivered.event.pid, 4242);
        assert_eq!(delivered.event.sock_fd, 7);
        assert_eq!(delivered.event.address_family, AddressFamily::Inet);
        assert_eq!(delivered.event.transport, TransportProtocol::Tcp);
        assert!(delivered.log_line.contains("event=network.connect"));
        assert!(delivered.log_line.contains("collector=ebpf"));
        assert!(delivered.log_line.contains("family=inet"));
        assert!(delivered.log_line.contains("transport=tcp"));
        assert!(delivered.log_line.contains("destination=93.184.216.34:443"));
    }

    #[test]
    fn invalid_connect_payload_length_is_rejected() {
        let error = ObservePlan::default()
            .deliver_connect_to_log(&[0; 8])
            .expect_err("short payload should fail");

        assert_eq!(
            error,
            ObserveDecodeError::WrongLength {
                event_kind: "connect",
                expected: poc_ebpf::CONNECT_EVENT_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn unsupported_address_family_is_rejected() {
        let mut bytes = poc_ebpf::fixture_connect_event_bytes();
        bytes[8..10].copy_from_slice(&99_u16.to_le_bytes());

        let error = ObservePlan::default()
            .deliver_connect_to_log(&bytes)
            .expect_err("unknown family should fail");

        assert_eq!(
            error,
            ObserveDecodeError::UnsupportedAddressFamily { actual: 99 }
        );
    }

    #[test]
    fn unsupported_transport_is_rejected() {
        let mut bytes = poc_ebpf::fixture_connect_event_bytes();
        bytes[10..12].copy_from_slice(&255_u16.to_le_bytes());

        let error = ObservePlan::default()
            .deliver_connect_to_log(&bytes)
            .expect_err("unknown transport should fail");

        assert_eq!(
            error,
            ObserveDecodeError::UnsupportedTransport { actual: 255 }
        );
    }
}
