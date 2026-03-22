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
    mode::ApprovalEligibility,
    policy::LivePreviewPolicyEvaluation,
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
                "decide whether a live require_approval result should stay advisory in shadow mode, create record-only approval state in enforce-preview mode, or surface an unsupported fallback",
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
        let mode_projection = evaluation
            .live_mode
            .project(evaluation.policy_decision.decision);

        match mode_projection.approval_eligibility {
            ApprovalEligibility::NotRequired => Ok(LivePreviewApprovalProjection {
                approval_request: None,
                approval_hold_allowed: false,
                hold_reason: None,
                expiry_hint: None,
                resume_token_hint: None,
                wait_state: None,
            }),
            ApprovalEligibility::AdvisoryOnly | ApprovalEligibility::Unsupported => {
                Ok(LivePreviewApprovalProjection {
                    approval_request: None,
                    approval_hold_allowed: false,
                    hold_reason: mode_projection.hold_reason.map(str::to_owned),
                    expiry_hint: None,
                    resume_token_hint: None,
                    wait_state: mode_projection.wait_state.map(str::to_owned),
                })
            }
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
                let enforcement = EnforcementInfo {
                    directive: EnforcementDirective::Hold,
                    status: EnforcementStatus::ObserveOnlyFallback,
                    status_reason: Some(mode_projection.status_reason.to_owned()),
                    enforced: false,
                    coverage_gap: Some(mode_projection.coverage_gap.to_owned()),
                    approval_id: Some(approval_request.approval_id.clone()),
                    expires_at: approval_request.expires_at,
                };
                let approval_request =
                    apply_enforcement_to_approval_request(&approval_request, &enforcement);

                Ok(LivePreviewApprovalProjection {
                    expiry_hint: approval_request.expires_at,
                    approval_request: Some(approval_request),
                    approval_hold_allowed: false,
                    hold_reason: mode_projection.hold_reason.map(str::to_owned),
                    resume_token_hint: None,
                    wait_state: mode_projection.wait_state.map(str::to_owned),
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

    use crate::poc::live_proxy::{
        LiveProxyInterceptionPlan, generic_rest::GenericRestLivePreviewPlan,
        policy::LivePreviewConsumer,
    };

    #[test]
    fn approval_plan_projects_record_only_approval_requests_in_enforce_preview_mode() {
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
            Some("enforce_preview_has_no_inline_hold_deny_or_resume")
        );
    }

    #[test]
    fn approval_plan_keeps_shadow_mode_require_approval_results_advisory_only() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let event = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::GenericRest,
            &GenericRestLivePreviewPlan::default().preview_hold_gmail_users_messages_send(),
            "shadow",
            "consumer=generic_rest provider=gws action=gmail.users.messages.send target=gmail.users/me",
        );
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("shadow policy evaluation should succeed");
        let projection = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("shadow preview should not materialize approval state");

        assert!(projection.approval_request.is_none());
        assert_eq!(
            projection.wait_state.as_deref(),
            Some("shadow_observe_only")
        );
        assert_eq!(
            projection.hold_reason.as_deref(),
            Some(
                "shadow mode is observe-only and records approval intent as an advisory signal without creating approval queue state"
            )
        );
    }

    #[test]
    fn approval_plan_marks_unsupported_mode_require_approval_as_unmaterialized() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let event = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::GenericRest,
            &GenericRestLivePreviewPlan::default().preview_hold_gmail_users_messages_send(),
            "unsupported",
            "consumer=generic_rest provider=gws action=gmail.users.messages.send target=gmail.users/me",
        );
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("unsupported policy evaluation should succeed");
        let projection = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("unsupported preview should not materialize approval state");

        assert!(projection.approval_request.is_none());
        assert_eq!(
            projection.wait_state.as_deref(),
            Some("unsupported_mode_no_approval_path")
        );
    }
}
