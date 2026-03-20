use super::contract::{
    ClassificationBoundary, GwsSemanticSurface, GwsSignalSource, SessionLinkageBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub classification_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: ClassificationBoundary,
}

impl ClassifyPlan {
    pub fn from_session_linkage_boundary(boundary: SessionLinkageBoundary) -> Self {
        Self {
            sources: boundary.sources.clone(),
            semantic_surfaces: boundary.semantic_surfaces.clone(),
            linkage_fields: boundary.linkage_fields.clone(),
            classification_fields: vec![
                "semantic_surface",
                "semantic_action_label",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ],
            responsibilities: vec![
                "accept session-linked API/network action candidates without reopening session identity resolution",
                "classify GWS request and network context into semantic action candidates and target hints",
                "attach classifier-owned labels and rationale without retaining raw HTTP payloads or document or message content",
                "handoff classified semantic actions downstream without normalizing agenta-core events or writing durable records",
            ],
            stages: vec!["service_map", "taxonomy", "handoff"],
            handoff: ClassificationBoundary {
                sources: boundary.sources,
                semantic_surfaces: boundary.semantic_surfaces,
                linkage_fields: boundary.linkage_fields,
                classification_fields: vec![
                    "semantic_surface",
                    "semantic_action_label",
                    "target_hint",
                    "classifier_labels",
                    "classifier_reasons",
                    "content_retained",
                ],
                redaction_contract: boundary.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> ClassificationBoundary {
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
    use super::ClassifyPlan;
    use crate::poc::gws::{
        contract::{GwsSemanticSurface, GwsSignalSource},
        session_linkage::SessionLinkagePlan,
    };

    #[test]
    fn classify_plan_threads_linkage_inputs_and_surfaces() {
        let plan =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());

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
        assert!(plan.linkage_fields.contains(&"semantic_surface_hint"));
    }

    #[test]
    fn classify_handoff_defines_semantic_action_fields_without_content_retention() {
        let handoff =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .handoff();

        assert_eq!(
            handoff.classification_fields,
            vec![
                "semantic_surface",
                "semantic_action_label",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ]
        );
        assert_eq!(
            handoff.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
        );
    }

    #[test]
    fn classify_summary_mentions_linkage_and_classification_fields() {
        let summary =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .summary();

        assert!(summary.contains("sources=api_observation,network_observation"));
        assert!(summary.contains("classification_fields=semantic_surface,semantic_action_label,target_hint,classifier_labels,classifier_reasons,content_retained"));
        assert!(summary.contains("stages=service_map->taxonomy->handoff"));
    }
}
