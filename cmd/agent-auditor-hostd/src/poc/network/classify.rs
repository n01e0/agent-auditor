use super::contract::{ClassificationBoundary, NetworkCollector, ObserveBoundary};

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
