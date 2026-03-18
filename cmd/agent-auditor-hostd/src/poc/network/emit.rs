use super::contract::{ClassificationBoundary, NetworkCollector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitPlan {
    pub collector: NetworkCollector,
    pub semantic_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub stages: Vec<&'static str>,
}

impl EmitPlan {
    pub fn from_classification_boundary(boundary: ClassificationBoundary) -> Self {
        Self {
            collector: boundary.collector,
            semantic_fields: boundary.semantic_fields,
            responsibilities: vec![
                "normalize classified outbound-connect candidates toward agenta-core event shapes",
                "fan out network connect events to logs and later control-plane sinks",
                "preserve destination classifier metadata for downstream policy, audit, and approval stages",
            ],
            sinks: vec!["structured_log", "control_plane"],
            stages: vec!["normalize", "publish"],
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "collector={} semantic_fields={} stages={} sinks={}",
            self.collector,
            self.semantic_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}
