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
pub struct BrowserGwsPocPlan {
    pub session_linkage: SessionLinkagePlan,
    pub classify: ClassifyPlan,
    pub evaluate: EvaluatePlan,
    pub record: RecordPlan,
}

impl BrowserGwsPocPlan {
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
    use super::BrowserGwsPocPlan;
    use crate::poc::browser::contract::{BrowserSemanticSurface, BrowserSignalSource};

    #[test]
    fn bootstrap_plan_keeps_browser_phase_responsibilities_separate() {
        let plan = BrowserGwsPocPlan::bootstrap();

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
                .all(|item| !item.contains("relay and automation surfaces"))
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
    fn bootstrap_plan_threads_browser_contracts_across_the_pipeline() {
        let plan = BrowserGwsPocPlan::bootstrap();

        assert_eq!(
            plan.session_linkage.sources,
            vec![
                BrowserSignalSource::ExtensionRelay,
                BrowserSignalSource::AutomationBridge,
            ]
        );
        assert_eq!(plan.session_linkage.sources, plan.classify.sources);
        assert_eq!(plan.classify.sources, plan.evaluate.sources);
        assert_eq!(plan.evaluate.sources, plan.record.sources);
        assert_eq!(
            plan.session_linkage.semantic_surfaces,
            vec![
                BrowserSemanticSurface::Browser,
                BrowserSemanticSurface::GoogleWorkspaceDrive,
                BrowserSemanticSurface::GoogleWorkspaceGmail,
                BrowserSemanticSurface::GoogleWorkspaceAdmin,
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
            "raw page bodies, email bodies, and document contents must not cross the browser linkage boundary"
        );
    }
}
