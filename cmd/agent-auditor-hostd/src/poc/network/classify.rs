use super::{
    contract::{
        ClassificationBoundary, ClassifiedNetworkConnect, DestinationScope, NetworkCollector,
        ObserveBoundary,
    },
    observe::ConnectEvent,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub collector: NetworkCollector,
    pub input_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    handoff: ClassificationBoundary,
}

impl ClassifyPlan {
    pub fn from_observe_boundary(boundary: ObserveBoundary) -> Self {
        Self {
            collector: boundary.collector,
            input_fields: boundary.raw_fields,
            responsibilities: vec![
                "translate raw socket tuples into destination candidates with stable IP / port / protocol meaning",
                "attach classifier-owned address-family, destination-scope, and transport hints for policy evaluation",
                "reserve the seam for lossy domain attribution without coupling it to kernel observation",
                "handoff semantic network connect candidates without normalizing or publishing them",
            ],
            handoff: ClassificationBoundary {
                collector: boundary.collector,
                semantic_fields: vec![
                    "destination_ip",
                    "destination_port",
                    "transport",
                    "address_family",
                    "destination_scope",
                    "domain_candidate",
                ],
                emitted_verbs: vec!["connect"],
            },
        }
    }

    pub fn handoff(&self) -> ClassificationBoundary {
        self.handoff.clone()
    }

    pub fn classify_connect(&self, event: &ConnectEvent) -> ClassifiedNetworkConnect {
        ClassifiedNetworkConnect {
            pid: event.pid,
            sock_fd: event.sock_fd,
            destination_ip: event.destination.ip().to_string(),
            destination_port: event.destination.port(),
            transport: event.transport.to_string(),
            address_family: event.address_family.to_string(),
            destination_scope: DestinationScope::from_ip(event.destination.ip()),
            domain_candidate: None,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "collector={} input_fields={} semantic_fields={} verbs={}",
            self.collector,
            self.input_fields.join(","),
            self.handoff.semantic_fields.join(","),
            self.handoff.emitted_verbs.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::poc::network::{
        classify::ClassifyPlan,
        contract::{DestinationScope, ObserveBoundary},
        observe::{AddressFamily, ObservePlan, TransportProtocol},
    };

    #[test]
    fn classify_connect_projects_destination_ip_port_and_protocol() {
        let observe = ObservePlan::default();
        let connect = observe
            .preview_connect_delivery()
            .expect("fixture connect delivery should succeed");
        let classify = ClassifyPlan::from_observe_boundary(ObserveBoundary::outbound_connect_poc());

        let classified = classify.classify_connect(&connect.event);

        assert_eq!(classified.pid, 4242);
        assert_eq!(classified.sock_fd, 7);
        assert_eq!(classified.destination_ip, "93.184.216.34");
        assert_eq!(classified.destination_port, 443);
        assert_eq!(classified.transport, TransportProtocol::Tcp.to_string());
        assert_eq!(classified.address_family, AddressFamily::Inet.to_string());
        assert_eq!(classified.destination_scope, DestinationScope::Public);
        assert_eq!(classified.domain_candidate, None);
    }
}
