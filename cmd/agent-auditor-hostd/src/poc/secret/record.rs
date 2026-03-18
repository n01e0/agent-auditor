use super::contract::{RecordBoundary, SecretSignalSource};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub sources: Vec<SecretSignalSource>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl RecordPlan {
    pub fn from_evaluation_boundary(boundary: RecordBoundary) -> Self {
        Self {
            sources: boundary.sources,
            record_fields: boundary.record_fields,
            responsibilities: vec![
                "persist redaction-safe secret access audit records",
                "persist approval requests created by approval-gated secret access decisions",
                "fan out recorded artifacts to local logs and later control-plane sinks",
                "avoid re-classifying or re-evaluating policy while recording results",
            ],
            sinks: vec!["structured_log", "audit_store", "approval_store"],
            stages: vec!["persist", "publish"],
            redaction_contract: boundary.redaction_contract,
        }
    }

    pub fn summary(&self) -> String {
        let sources = self
            .sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "sources={} record_fields={} stages={} sinks={}",
            sources,
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::RecordPlan;
    use crate::poc::secret::{
        classify::ClassifyPlan, contract::SecretSignalSource, evaluate::EvaluatePlan,
        persist::SecretPocStore,
    };

    #[test]
    fn record_plan_preserves_redaction_contract_and_sources() {
        let plan = RecordPlan::from_evaluation_boundary(
            EvaluatePlan::from_classification_boundary(ClassifyPlan::default().handoff()).handoff(),
        );

        assert_eq!(
            plan.sources,
            vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter
            ]
        );
        assert_eq!(
            plan.redaction_contract,
            "plaintext secret material must not cross the classify boundary"
        );
    }

    #[test]
    fn record_plan_exposes_storage_and_publish_sinks() {
        let plan = RecordPlan::from_evaluation_boundary(
            EvaluatePlan::from_classification_boundary(ClassifyPlan::default().handoff()).handoff(),
        );

        assert_eq!(
            plan.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
        assert_eq!(plan.stages, vec!["persist", "publish"]);
    }

    #[test]
    fn record_plan_store_bootstrap_exposes_audit_and_approval_logs() {
        let store = SecretPocStore::bootstrap().expect("secret store should bootstrap");

        assert!(store.paths().audit_log.ends_with("audit-records.jsonl"));
        assert!(
            store
                .paths()
                .approval_log
                .ends_with("approval-requests.jsonl")
        );
    }
}
