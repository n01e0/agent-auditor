pub mod approval;
pub mod audit;
pub mod contract;
pub mod generic_rest;
pub mod policy;
pub mod proxy_seam;
pub mod semantic_conversion;
pub mod session_correlation;

use self::{
    approval::ApprovalPlan, audit::AuditPlan, policy::PolicyPlan, proxy_seam::ProxySeamPlan,
    semantic_conversion::SemanticConversionPlan, session_correlation::SessionCorrelationPlan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProxyInterceptionPlan {
    pub proxy_seam: ProxySeamPlan,
    pub session_correlation: SessionCorrelationPlan,
    pub semantic_conversion: SemanticConversionPlan,
    pub policy: PolicyPlan,
    pub approval: ApprovalPlan,
    pub audit: AuditPlan,
}

impl LiveProxyInterceptionPlan {
    pub fn bootstrap() -> Self {
        let proxy_seam = ProxySeamPlan::default();
        let session_correlation =
            SessionCorrelationPlan::from_proxy_seam_boundary(proxy_seam.handoff());
        let semantic_conversion = SemanticConversionPlan::from_session_correlation_boundary(
            session_correlation.handoff(),
        );
        let policy = PolicyPlan::from_semantic_conversion_boundary(semantic_conversion.handoff());
        let approval = ApprovalPlan::from_policy_boundary(policy.handoff());
        let audit =
            AuditPlan::from_policy_and_approval_boundaries(policy.handoff(), approval.handoff());

        Self {
            proxy_seam,
            session_correlation,
            semantic_conversion,
            policy,
            approval,
            audit,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::live::GenericLiveActionEnvelope;

    use super::{LiveProxyInterceptionPlan, generic_rest::GenericRestLivePreviewPlan};
    use crate::poc::live_proxy::contract::{
        LIVE_PROXY_INTERCEPTION_REDACTION_RULE, LiveHttpRequestContract,
    };

    #[test]
    fn bootstrap_plan_keeps_live_proxy_phase_responsibilities_separate() {
        let plan = LiveProxyInterceptionPlan::bootstrap();

        assert!(
            plan.proxy_seam
                .responsibilities
                .iter()
                .any(|item| item.contains("redaction-safe live HTTP request metadata"))
        );
        assert!(
            plan.proxy_seam
                .responsibilities
                .iter()
                .all(|item| !item.contains("same runtime session identity"))
        );

        assert!(
            plan.session_correlation
                .responsibilities
                .iter()
                .any(|item| item.contains("same runtime session identity"))
        );
        assert!(
            plan.session_correlation
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );

        assert!(
            plan.semantic_conversion
                .responsibilities
                .iter()
                .any(|item| item.contains("generic live action seam"))
        );
        assert!(
            plan.semantic_conversion
                .responsibilities
                .iter()
                .all(|item| !item.contains("approval-request state"))
        );

        assert!(
            plan.policy
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-policy"))
        );
        assert!(
            plan.policy
                .responsibilities
                .iter()
                .all(|item| !item.contains("append-only"))
        );

        assert!(
            plan.approval
                .responsibilities
                .iter()
                .any(|item| item.contains("approval-request state"))
        );
        assert!(
            plan.approval
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );

        assert!(plan.audit.responsibilities.iter().any(|item| {
            item.contains("append live preview, enforce-preview, or unsupported audit records")
        }));
        assert!(
            plan.audit
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_live_proxy_fields_across_pipeline_boundaries() {
        let plan = LiveProxyInterceptionPlan::bootstrap();

        assert_eq!(
            plan.proxy_seam.sources,
            vec!["forward_proxy", "browser_relay", "sidecar_proxy"]
        );
        assert_eq!(
            plan.proxy_seam.request_fields,
            LiveHttpRequestContract::field_names().to_vec()
        );
        assert_eq!(
            plan.proxy_seam.request_fields,
            plan.session_correlation.input_fields
        );
        assert_eq!(
            plan.session_correlation.correlation_fields,
            plan.semantic_conversion.input_fields
        );
        assert_eq!(
            plan.semantic_conversion.semantic_fields,
            GenericLiveActionEnvelope::field_names().to_vec()
        );
        assert_eq!(
            plan.semantic_conversion.semantic_fields,
            plan.policy.input_fields
        );
        assert_eq!(plan.policy.decision_fields, plan.approval.input_fields);
        assert_eq!(
            plan.semantic_conversion.consumers,
            vec!["generic_rest", "gws", "github", "messaging"]
        );
        assert_eq!(plan.semantic_conversion.consumers, plan.policy.consumers);
        assert_eq!(
            plan.approval.modes,
            vec!["shadow", "enforce_preview", "unsupported"]
        );
        assert_eq!(plan.approval.modes, plan.audit.modes);
        assert_eq!(
            plan.audit.record_fields,
            vec![
                "live_request_summary",
                "normalized_event",
                "policy_decision",
                "approval_request",
                "mode_status",
                "coverage_gap",
                "realized_enforcement",
                "redaction_status",
            ]
        );
    }

    #[test]
    fn bootstrap_plan_preserves_one_redaction_rule_across_all_live_proxy_handoffs() {
        let plan = LiveProxyInterceptionPlan::bootstrap();

        assert_eq!(
            plan.proxy_seam.handoff().redaction_contract,
            LIVE_PROXY_INTERCEPTION_REDACTION_RULE
        );
        assert_eq!(
            plan.proxy_seam.handoff().redaction_contract,
            plan.session_correlation.handoff().redaction_contract
        );
        assert_eq!(
            plan.session_correlation.handoff().redaction_contract,
            plan.semantic_conversion.handoff().redaction_contract
        );
        assert_eq!(
            plan.semantic_conversion.handoff().redaction_contract,
            plan.policy.handoff().redaction_contract
        );
        assert_eq!(
            plan.policy.handoff().redaction_contract,
            plan.approval.handoff().redaction_contract
        );
        assert_eq!(
            plan.approval.handoff().redaction_contract,
            plan.audit.handoff().redaction_contract
        );
    }

    #[test]
    fn summaries_expose_stages_for_each_live_proxy_phase() {
        let plan = LiveProxyInterceptionPlan::bootstrap();

        assert!(
            plan.proxy_seam
                .summary()
                .contains("stages=ingest->redact->request_identity->handoff")
        );
        assert!(
            plan.session_correlation
                .summary()
                .contains("stages=lookup->bind_session->lineage_hint->handoff")
        );
        assert!(plan.semantic_conversion.summary().contains(
            "stages=provider_hint->generic_live_envelope->provider_taxonomy_input->handoff"
        ));
        assert!(
            plan.policy
                .summary()
                .contains("stages=normalize->policy_input->evaluate->handoff")
        );
        assert!(
            plan.approval
                .summary()
                .contains("stages=eligibility->hold_projection->approval_request->handoff")
        );
        assert!(
            plan.audit
                .summary()
                .contains("stages=reflect->annotate_mode->append->publish")
        );
    }

    #[test]
    fn semantic_conversion_preview_enters_agenta_core_before_provider_taxonomy() {
        let plan = LiveProxyInterceptionPlan::bootstrap();
        let envelope = plan
            .semantic_conversion
            .preview_generic_live_action_envelope();

        assert_eq!(
            envelope.request_id.as_str(),
            "req_live_proxy_github_repos_update_visibility_preview"
        );
        assert_eq!(envelope.live_surface.as_str(), "http.request");
        assert_eq!(envelope.transport.as_str(), "https");
        assert_eq!(
            envelope.provider_hint.map(|provider| provider.to_string()),
            Some("github".to_owned())
        );
        assert_eq!(
            envelope.target_hint,
            Some("repos/n01e0/agent-auditor/visibility".to_owned())
        );
        assert!(!envelope.content_retained);
    }

    #[test]
    fn generic_rest_live_preview_plan_consumes_the_shared_live_envelope_contract() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let generic_rest = GenericRestLivePreviewPlan::default();

        assert_eq!(
            live_proxy.semantic_conversion.semantic_fields,
            generic_rest.upstream_fields
        );
        assert_eq!(
            generic_rest.preview_actions,
            vec![
                "admin.reports.activities.list",
                "gmail.users.messages.send",
                "actions.secrets.create_or_update",
            ]
        );
        assert!(generic_rest.summary().contains(
            "stages=match_preview_route->join_provider_metadata->normalize_generic_rest_event"
        ));
    }
}
