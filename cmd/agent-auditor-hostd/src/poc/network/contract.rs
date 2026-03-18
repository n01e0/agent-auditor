use std::fmt;

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
