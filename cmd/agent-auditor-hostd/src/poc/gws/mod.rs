pub mod classify;
pub mod contract;
pub mod evaluate;
pub mod record;
pub mod session_linkage;

use self::{
    classify::ClassifyPlan, evaluate::EvaluatePlan, record::RecordPlan,
    session_linkage::SessionLinkagePlan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiNetworkGwsPocPlan {
    pub session_linkage: SessionLinkagePlan,
    pub classify: ClassifyPlan,
    pub evaluate: EvaluatePlan,
    pub record: RecordPlan,
}

impl ApiNetworkGwsPocPlan {
    pub fn bootstrap() -> Self {
        let session_linkage = SessionLinkagePlan::default();
        let classify = ClassifyPlan::from_session_linkage_boundary(session_linkage.handoff());
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let record = RecordPlan::from_evaluation_boundary(evaluate.handoff());

        Self {
            session_linkage,
            classify,
            evaluate,
            record,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{ActionClass, EventType, SessionRecord};

    use super::ApiNetworkGwsPocPlan;
    use crate::poc::gws::contract::{GwsSemanticSurface, GwsSignalSource};

    #[test]
    fn bootstrap_plan_keeps_gws_phase_responsibilities_separate() {
        let plan = ApiNetworkGwsPocPlan::bootstrap();

        assert!(
            plan.session_linkage
                .responsibilities
                .iter()
                .any(|item| item.contains("same session identity"))
        );
        assert!(
            plan.session_linkage
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .any(|item| item.contains("semantic action candidates"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .any(|item| item.contains("drive.permissions.update"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .all(|item| !item.contains("same session identity used by runtime hostd events"))
        );
        assert!(
            plan.evaluate
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-core"))
        );
        assert!(
            plan.evaluate
                .responsibilities
                .iter()
                .all(|item| !item.contains("request adapters and egress observation"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_gws_contracts_across_the_pipeline() {
        let plan = ApiNetworkGwsPocPlan::bootstrap();

        assert_eq!(
            plan.session_linkage.sources,
            vec![
                GwsSignalSource::ApiObservation,
                GwsSignalSource::NetworkObservation,
            ]
        );
        assert_eq!(plan.session_linkage.sources, plan.classify.sources);
        assert_eq!(plan.classify.sources, plan.evaluate.sources);
        assert_eq!(plan.evaluate.sources, plan.record.sources);
        assert_eq!(
            plan.session_linkage.semantic_surfaces,
            vec![
                GwsSemanticSurface::GoogleWorkspace,
                GwsSemanticSurface::GoogleWorkspaceDrive,
                GwsSemanticSurface::GoogleWorkspaceGmail,
                GwsSemanticSurface::GoogleWorkspaceAdmin,
            ]
        );
        assert_eq!(
            plan.session_linkage.semantic_surfaces,
            plan.classify.semantic_surfaces
        );
        assert_eq!(
            plan.classify.semantic_surfaces,
            plan.evaluate.semantic_surfaces
        );
        assert_eq!(
            plan.evaluate.semantic_surfaces,
            plan.record.semantic_surfaces
        );
        assert_eq!(
            plan.classify.classification_fields,
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
            plan.classify.semantic_actions,
            vec![
                crate::poc::gws::contract::GwsActionKind::DrivePermissionsUpdate,
                crate::poc::gws::contract::GwsActionKind::DriveFilesGetMedia,
                crate::poc::gws::contract::GwsActionKind::GmailUsersMessagesSend,
                crate::poc::gws::contract::GwsActionKind::AdminReportsActivitiesList,
            ]
        );
        assert_eq!(
            plan.record.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
        assert_eq!(
            plan.record.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
        );
    }

    #[test]
    fn bootstrap_plan_normalizes_preview_gws_action_into_agenta_core() {
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_bootstrap");
        let classified = plan
            .classify
            .classify_action(
                &plan
                    .session_linkage
                    .preview_session_linked_api_action(&session),
            )
            .expect("preview api action should classify");

        let normalized = plan
            .evaluate
            .normalize_classified_action(&classified, &session);

        assert_eq!(normalized.event_type, EventType::GwsAction);
        assert_eq!(normalized.action.class, ActionClass::Gws);
        assert_eq!(
            normalized.action.verb.as_deref(),
            Some("drive.permissions.update")
        );
        assert_eq!(
            normalized.action.target.as_deref(),
            Some("drive.files/abc123/permissions/perm456")
        );
    }
}
