use std::net::IpAddr;

use super::{
    contract::{
        ClassificationBoundary, ClassifiedNetworkConnect, DestinationScope, NetworkCollector,
        ObserveBoundary,
    },
    observe::ConnectEvent,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentDnsAnswer {
    pub domain: String,
    pub addresses: Vec<IpAddr>,
}

impl RecentDnsAnswer {
    pub fn new(domain: impl Into<String>, addresses: Vec<IpAddr>) -> Self {
        Self {
            domain: domain.into(),
            addresses,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAttribution {
    pub domain: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAttributor {
    recent_answers: Vec<RecentDnsAnswer>,
}

impl Default for DomainAttributor {
    fn default() -> Self {
        Self::from_recent_answers(vec![RecentDnsAnswer::new(
            "example.com",
            vec![IpAddr::from([93, 184, 216, 34])],
        )])
    }
}

impl DomainAttributor {
    pub fn from_recent_answers(recent_answers: Vec<RecentDnsAnswer>) -> Self {
        Self { recent_answers }
    }

    pub fn recent_answers(&self) -> &[RecentDnsAnswer] {
        &self.recent_answers
    }

    pub fn attribute(&self, destination_ip: IpAddr) -> Option<DomainAttribution> {
        let mut matches = self
            .recent_answers
            .iter()
            .filter(|answer| answer.addresses.contains(&destination_ip));

        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }

        Some(DomainAttribution {
            domain: first.domain.clone(),
            source: "dns_answer_cache_exact_ip",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub collector: NetworkCollector,
    pub input_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub domain_attributor: DomainAttributor,
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
                "perform domain attribution only from recent DNS answer cache exact-IP matches",
                "handoff semantic network connect candidates without normalizing or publishing them",
            ],
            domain_attributor: DomainAttributor::default(),
            handoff: ClassificationBoundary {
                collector: boundary.collector,
                semantic_fields: vec![
                    "destination_ip",
                    "destination_port",
                    "transport",
                    "address_family",
                    "destination_scope",
                    "domain_candidate",
                    "domain_attribution_source",
                ],
                emitted_verbs: vec!["connect"],
            },
        }
    }

    pub fn handoff(&self) -> ClassificationBoundary {
        self.handoff.clone()
    }

    pub fn classify_connect(&self, event: &ConnectEvent) -> ClassifiedNetworkConnect {
        let domain_attribution = self.domain_attributor.attribute(event.destination.ip());

        ClassifiedNetworkConnect {
            pid: event.pid,
            sock_fd: event.sock_fd,
            destination_ip: event.destination.ip().to_string(),
            destination_port: event.destination.port(),
            transport: event.transport.to_string(),
            address_family: event.address_family.to_string(),
            destination_scope: DestinationScope::from_ip(event.destination.ip()),
            domain_candidate: domain_attribution.as_ref().map(|item| item.domain.clone()),
            domain_attribution_source: domain_attribution
                .as_ref()
                .map(|item| item.source.to_owned()),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "collector={} input_fields={} semantic_fields={} verbs={} domain_strategy=recent_dns_answer_exact_ip answers={}",
            self.collector,
            self.input_fields.join(","),
            self.handoff.semantic_fields.join(","),
            self.handoff.emitted_verbs.join(","),
            self.domain_attributor.recent_answers().len()
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::poc::network::{
        classify::{ClassifyPlan, DomainAttributor, RecentDnsAnswer},
        contract::{DestinationScope, ObserveBoundary},
        observe::{AddressFamily, ObservePlan, TransportProtocol},
    };

    #[test]
    fn classify_connect_projects_destination_ip_port_protocol_and_domain_candidate() {
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
        assert_eq!(classified.domain_candidate.as_deref(), Some("example.com"));
        assert_eq!(
            classified.domain_attribution_source.as_deref(),
            Some("dns_answer_cache_exact_ip")
        );
    }

    #[test]
    fn domain_attributor_returns_none_without_exact_ip_match() {
        let attributor = DomainAttributor::from_recent_answers(vec![RecentDnsAnswer::new(
            "internal.example",
            vec![IpAddr::from([10, 0, 0, 7])],
        )]);

        let attribution = attributor.attribute(IpAddr::from([93, 184, 216, 34]));

        assert_eq!(attribution, None);
    }

    #[test]
    fn domain_attributor_returns_none_for_ambiguous_ip_reuse() {
        let shared_ip = IpAddr::from([203, 0, 113, 10]);
        let attributor = DomainAttributor::from_recent_answers(vec![
            RecentDnsAnswer::new("api.example.com", vec![shared_ip]),
            RecentDnsAnswer::new("cdn.example.net", vec![shared_ip]),
        ]);

        let attribution = attributor.attribute(shared_ip);

        assert_eq!(attribution, None);
    }
}
