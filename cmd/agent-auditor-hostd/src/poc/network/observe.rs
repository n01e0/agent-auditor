use super::contract::{NetworkCollector, ObserveBoundary};

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
