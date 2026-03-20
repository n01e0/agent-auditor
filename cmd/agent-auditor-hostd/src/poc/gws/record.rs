use super::contract::{GwsSemanticSurface, GwsSignalSource, RecordBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
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
            semantic_surfaces: boundary.semantic_surfaces,
            record_fields: boundary.record_fields,
            responsibilities: vec![
                "persist redaction-safe GWS audit records",
                "persist approval requests created by approval-gated GWS semantic actions",
                "fan out recorded artifacts to structured logs and later control-plane sinks",
                "avoid re-linking sessions, re-classifying GWS semantics, or re-evaluating policy while recording results",
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
        let surfaces = self
            .semantic_surfaces
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "sources={} surfaces={} record_fields={} stages={} sinks={}",
            sources,
            surfaces,
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::RecordPlan;
    use crate::poc::gws::{
        classify::ClassifyPlan, contract::GwsSignalSource, evaluate::EvaluatePlan,
        session_linkage::SessionLinkagePlan,
    };

    #[test]
    fn record_plan_preserves_sources_and_redaction_contract() {
        let plan = RecordPlan::from_evaluation_boundary(
            EvaluatePlan::from_classification_boundary(
                ClassifyPlan::from_session_linkage_boundary(
                    SessionLinkagePlan::default().handoff(),
                )
                .handoff(),
            )
            .handoff(),
        );

        assert_eq!(
            plan.sources,
            vec![
                GwsSignalSource::ApiObservation,
                GwsSignalSource::NetworkObservation,
            ]
        );
        assert_eq!(
            plan.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
        );
    }

    #[test]
    fn record_plan_exposes_publish_sinks() {
        let plan = RecordPlan::from_evaluation_boundary(
            EvaluatePlan::from_classification_boundary(
                ClassifyPlan::from_session_linkage_boundary(
                    SessionLinkagePlan::default().handoff(),
                )
                .handoff(),
            )
            .handoff(),
        );

        assert_eq!(plan.stages, vec!["persist", "publish"]);
        assert_eq!(
            plan.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
    }

    #[test]
    fn record_summary_mentions_record_fields_and_sinks() {
        let summary = RecordPlan::from_evaluation_boundary(
            EvaluatePlan::from_classification_boundary(
                ClassifyPlan::from_session_linkage_boundary(
                    SessionLinkagePlan::default().handoff(),
                )
                .handoff(),
            )
            .handoff(),
        )
        .summary();

        assert!(summary.contains(
            "record_fields=normalized_event,policy_decision,approval_request,redaction_status"
        ));
        assert!(summary.contains("sinks=structured_log,audit_store,approval_store"));
    }
}
