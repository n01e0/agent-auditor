use agenta_core::{ApprovalRequest, EnforcementDirective, EnforcementInfo, EnforcementStatus};
use agenta_policy::{
    apply_decision_to_event, apply_enforcement_to_approval_request, approval_request_from_decision,
};
use thiserror::Error;

use super::{
    contract::{
        ApprovalBoundary, LIVE_INTERCEPTION_MODE_LABELS, LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
        PolicyBoundary,
    },
    policy::{ApprovalEligibility, LivePreviewPolicyEvaluation},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPlan {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub approval_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: ApprovalBoundary,
}

impl ApprovalPlan {
    pub fn from_policy_boundary(boundary: PolicyBoundary) -> Self {
        let modes = LIVE_INTERCEPTION_MODE_LABELS.to_vec();
        let input_fields = boundary.decision_fields;
        let approval_fields = vec![
            "approval_request",
            "approval_hold_allowed",
            "hold_reason",
            "expiry_hint",
            "resume_token_hint",
            "wait_state",
        ];

        Self {
            modes: modes.clone(),
            input_fields: input_fields.clone(),
            approval_fields: approval_fields.clone(),
            responsibilities: vec![
                "decide whether a live require_approval result can be represented as a real hold, an enforce-preview hold, or an unsupported fallback for the intercepted request class",
                "materialize approval-request state and release or cancel handles without re-running policy evaluation or semantic conversion",
                "keep pause or resume feasibility separate from durable audit persistence so later reviewers can see what the runtime actually could hold",
                "handoff approval state for append-only audit reflection without owning the long-term operator UX or reconciliation loop",
            ],
            stages: vec![
                "eligibility",
                "hold_projection",
                "approval_request",
                "handoff",
            ],
            handoff: ApprovalBoundary {
                modes,
                input_fields,
                approval_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn project_preview_approval(
        &self,
        evaluation: &LivePreviewPolicyEvaluation,
    ) -> Result<LivePreviewApprovalProjection, LivePreviewApprovalError> {
        match evaluation.approval_eligibility {
            ApprovalEligibility::NotRequired => Ok(LivePreviewApprovalProjection {
                approval_request: None,
                approval_hold_allowed: false,
                hold_reason: None,
                expiry_hint: None,
                resume_token_hint: None,
                wait_state: None,
            }),
            ApprovalEligibility::RecordOnly => {
                let decision_applied = apply_decision_to_event(
                    &evaluation.normalized_event,
                    &evaluation.policy_decision,
                );
                let approval_request =
                    approval_request_from_decision(&decision_applied, &evaluation.policy_decision)
                        .ok_or_else(|| LivePreviewApprovalError::MissingApprovalRequest {
                            event_id: evaluation.normalized_event.event_id.clone(),
                        })?;
                let hold_reason =
                    "live preview path can record approval intent but cannot pause or resume the in-flight provider request yet"
                        .to_owned();
                let enforcement = EnforcementInfo {
                    directive: EnforcementDirective::Hold,
                    status: EnforcementStatus::ObserveOnlyFallback,
                    status_reason: Some(hold_reason.clone()),
                    enforced: false,
                    coverage_gap: Some(
                        "live_preview_path_has_no_inline_hold_deny_or_resume".to_owned(),
                    ),
                    approval_id: Some(approval_request.approval_id.clone()),
                    expires_at: approval_request.expires_at,
                };
                let approval_request =
                    apply_enforcement_to_approval_request(&approval_request, &enforcement);

                Ok(LivePreviewApprovalProjection {
                    expiry_hint: approval_request.expires_at,
                    approval_request: Some(approval_request),
                    approval_hold_allowed: false,
                    hold_reason: Some(hold_reason),
                    resume_token_hint: None,
                    wait_state: Some("pending_approval_record_only".to_owned()),
                })
            }
        }
    }

    pub fn handoff(&self) -> ApprovalBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "modes={} approval_fields={} stages={}",
            self.modes.join(","),
            self.approval_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LivePreviewApprovalProjection {
    pub approval_request: Option<ApprovalRequest>,
    pub approval_hold_allowed: bool,
    pub hold_reason: Option<String>,
    pub expiry_hint: Option<chrono::DateTime<chrono::Utc>>,
    pub resume_token_hint: Option<String>,
    pub wait_state: Option<String>,
}

impl LivePreviewApprovalProjection {
    pub fn summary(&self) -> String {
        format!(
            "approval_request={} approval_hold_allowed={} expiry_hint={} wait_state={}",
            self.approval_request
                .as_ref()
                .map(|request| request.approval_id.as_str())
                .unwrap_or("none"),
            self.approval_hold_allowed,
            self.expiry_hint
                .map(|timestamp| timestamp.to_rfc3339())
                .unwrap_or_else(|| "none".to_owned()),
            self.wait_state.as_deref().unwrap_or("none")
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LivePreviewApprovalError {
    #[error(
        "live preview approval projection required an approval request but could not create one for event `{event_id}`"
    )]
    MissingApprovalRequest { event_id: String },
}

#[cfg(test)]
mod tests {
    use agenta_core::{ApprovalStatus, EnforcementStatus};

    use super::ApprovalPlan;
    use crate::poc::live_proxy::{
        LiveProxyInterceptionPlan, generic_rest::GenericRestLivePreviewPlan,
        policy::LivePreviewConsumer,
    };

    #[test]
    fn approval_plan_projects_preview_only_approval_requests_without_claiming_a_real_hold() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let event = GenericRestLivePreviewPlan::default().preview_hold_gmail_users_messages_send();
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("policy evaluation should succeed");
        let projection = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("approval projection should succeed");
        let request = projection
            .approval_request
            .as_ref()
            .expect("hold preview should create an approval request");

        assert!(!projection.approval_hold_allowed);
        assert_eq!(
            projection.wait_state.as_deref(),
            Some("pending_approval_record_only")
        );
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(
            request
                .enforcement
                .as_ref()
                .map(|enforcement| enforcement.status),
            Some(EnforcementStatus::ObserveOnlyFallback)
        );
        assert_eq!(
            request
                .enforcement
                .as_ref()
                .and_then(|enforcement| enforcement.coverage_gap.as_deref()),
            Some("live_preview_path_has_no_inline_hold_deny_or_resume")
        );
    }

    #[test]
    fn approval_plan_skips_request_materialization_for_non_gated_preview_decisions() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let event = GenericRestLivePreviewPlan::default()
            .preview_deny_github_actions_secrets_create_or_update();
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("policy evaluation should succeed");
        let projection = ApprovalPlan::from_policy_boundary(live_proxy.policy.handoff())
            .project_preview_approval(&evaluation)
            .expect("deny preview should not require approval");

        assert!(projection.approval_request.is_none());
        assert!(!projection.approval_hold_allowed);
        assert!(projection.hold_reason.is_none());
        assert!(projection.wait_state.is_none());
    }
}
