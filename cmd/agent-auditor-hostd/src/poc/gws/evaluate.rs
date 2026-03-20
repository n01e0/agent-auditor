use super::contract::{
    ClassificationBoundary, GwsSemanticSurface, GwsSignalSource, RecordBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatePlan {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub classification_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: RecordBoundary,
}

impl EvaluatePlan {
    pub fn from_classification_boundary(boundary: ClassificationBoundary) -> Self {
        Self {
            sources: boundary.sources.clone(),
            semantic_surfaces: boundary.semantic_surfaces.clone(),
            linkage_fields: boundary.linkage_fields,
            classification_fields: boundary.classification_fields,
            responsibilities: vec![
                "normalize classified GWS semantic action candidates toward agenta-core event shapes",
                "bridge normalized GWS semantic actions into agenta-policy without re-linking sessions or re-running semantic classification",
                "project allow, deny, and require_approval outcomes plus approval-request candidates for recording",
                "carry the GWS redaction contract forward so downstream audit never needs raw HTTP payloads or document or message content",
            ],
            stages: vec!["normalize", "policy", "approval_projection"],
            handoff: RecordBoundary {
                sources: boundary.sources,
                semantic_surfaces: boundary.semantic_surfaces,
                record_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "redaction_status",
                ],
                redaction_contract: boundary.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> RecordBoundary {
        self.handoff.clone()
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
            "sources={} surfaces={} linkage_fields={} classification_fields={} stages={}",
            sources,
            surfaces,
            self.linkage_fields.join(","),
            self.classification_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::EvaluatePlan;
    use crate::poc::gws::{
        classify::ClassifyPlan,
        contract::{GwsSemanticSurface, GwsSignalSource},
        session_linkage::SessionLinkagePlan,
    };

    #[test]
    fn evaluate_plan_threads_gws_surfaces_and_upstream_fields() {
        let plan = EvaluatePlan::from_classification_boundary(
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
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
            plan.semantic_surfaces,
            vec![
                GwsSemanticSurface::GoogleWorkspace,
                GwsSemanticSurface::GoogleWorkspaceDrive,
                GwsSemanticSurface::GoogleWorkspaceGmail,
                GwsSemanticSurface::GoogleWorkspaceAdmin,
            ]
        );
        assert!(plan.linkage_fields.contains(&"session_id"));
        assert!(
            plan.classification_fields
                .contains(&"semantic_action_label")
        );
    }

    #[test]
    fn evaluate_handoff_prepares_record_stage_inputs() {
        let handoff = EvaluatePlan::from_classification_boundary(
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .handoff(),
        )
        .handoff();

        assert_eq!(
            handoff.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
        assert_eq!(
            handoff.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
        );
    }

    #[test]
    fn evaluate_summary_mentions_policy_projection_stages() {
        let summary = EvaluatePlan::from_classification_boundary(
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .handoff(),
        )
        .summary();

        assert!(summary.contains("sources=api_observation,network_observation"));
        assert!(summary.contains("stages=normalize->policy->approval_projection"));
        assert!(summary.contains("classification_fields=semantic_surface,semantic_action_label,target_hint,classifier_labels,classifier_reasons,content_retained"));
    }
}
