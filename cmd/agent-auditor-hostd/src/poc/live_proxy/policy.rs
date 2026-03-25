use agenta_core::{EventEnvelope, PolicyDecision};
use agenta_policy::{PolicyEvaluator, PolicyInput, RegoPolicyEvaluator};
use serde_json::json;
use thiserror::Error;

use super::{
    contract::{
        LIVE_PROXY_INTERCEPTION_REDACTION_RULE, PolicyBoundary, SemanticConversionBoundary,
    },
    mode::{
        ApprovalEligibility, LiveCoverageDisplayRule, LiveCoveragePosture, LiveMode,
        LiveModeBehavior,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: PolicyBoundary,
}

impl PolicyPlan {
    pub fn from_semantic_conversion_boundary(boundary: SemanticConversionBoundary) -> Self {
        let consumers = boundary.consumers.clone();
        let input_fields = boundary.semantic_fields;
        let decision_fields = vec![
            "normalized_event",
            "policy_decision",
            "coverage_posture",
            "mode_behavior",
            "mode_status",
            "record_status",
            "approval_eligibility",
            "coverage_display_rule",
        ];

        Self {
            consumers: consumers.clone(),
            input_fields: input_fields.clone(),
            decision_fields: decision_fields.clone(),
            responsibilities: vec![
                "bridge generic live semantic envelopes into agenta-policy without re-running proxy capture or session ownership logic",
                "evaluate live requests against existing generic REST, GWS, GitHub, and messaging policy surfaces using only redaction-safe semantic fields",
                "project live coverage posture, mode behavior, and record status alongside allow, deny, or require_approval decisions so downstream code can distinguish shadow, enforce-preview, and unsupported behavior",
                "handoff policy outputs to approval and audit stages without owning request pause/resume mechanics or durable record persistence",
            ],
            stages: vec!["normalize", "policy_input", "evaluate", "handoff"],
            handoff: PolicyBoundary {
                consumers,
                input_fields,
                decision_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn annotate_preview_event(
        &self,
        consumer: LivePreviewConsumer,
        event: &EventEnvelope,
        mode: impl Into<String>,
        live_request_summary: impl Into<String>,
    ) -> EventEnvelope {
        let mut event = event.clone();
        let mode = mode.into();
        let live_request_summary = live_request_summary.into();

        event
            .action
            .attributes
            .insert("live_preview_consumer".to_owned(), json!(consumer.label()));
        event
            .action
            .attributes
            .insert("mode".to_owned(), json!(mode));
        event.action.attributes.insert(
            "live_request_summary".to_owned(),
            json!(live_request_summary),
        );
        event
    }

    pub fn evaluate_preview_event(
        &self,
        consumer: LivePreviewConsumer,
        event: &EventEnvelope,
    ) -> Result<LivePreviewPolicyEvaluation, LivePreviewPolicyError> {
        let evaluator = consumer.evaluator();
        let input = PolicyInput::from_event(event);
        let decision =
            evaluator
                .evaluate(&input)
                .map_err(|source| LivePreviewPolicyError::Evaluation {
                    consumer,
                    event_id: event.event_id.clone(),
                    source,
                })?;
        let live_mode = LiveMode::from_event(event);
        let mode_projection = live_mode.project(decision.decision);

        let mut normalized_event = event.clone();
        normalized_event.action.attributes.insert(
            "coverage_posture".to_owned(),
            json!(mode_projection.coverage_posture.label()),
        );
        normalized_event.action.attributes.insert(
            "mode_behavior".to_owned(),
            json!(mode_projection.mode_behavior.label()),
        );
        normalized_event
            .action
            .attributes
            .insert("mode_status".to_owned(), json!(mode_projection.mode_status));
        normalized_event.action.attributes.insert(
            "record_status".to_owned(),
            json!(mode_projection.record_status),
        );
        normalized_event.action.attributes.insert(
            "approval_eligibility".to_owned(),
            json!(mode_projection.approval_eligibility.label()),
        );
        normalized_event.action.attributes.insert(
            "coverage_display_rule".to_owned(),
            json!(mode_projection.coverage_display_rule.label()),
        );

        Ok(LivePreviewPolicyEvaluation {
            consumer,
            normalized_event,
            policy_decision: decision,
            live_mode,
            coverage_posture: mode_projection.coverage_posture,
            mode_behavior: mode_projection.mode_behavior,
            mode_status: mode_projection.mode_status.to_owned(),
            record_status: mode_projection.record_status.to_owned(),
            approval_eligibility: mode_projection.approval_eligibility,
            coverage_display_rule: mode_projection.coverage_display_rule,
        })
    }

    pub fn handoff(&self) -> PolicyBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "consumers={} decision_fields={} stages={}",
            self.consumers.join(","),
            self.decision_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePreviewConsumer {
    GenericRest,
    Gws,
    GitHub,
    Messaging,
}

impl LivePreviewConsumer {
    pub fn label(self) -> &'static str {
        match self {
            Self::GenericRest => "generic_rest",
            Self::Gws => "gws",
            Self::GitHub => "github",
            Self::Messaging => "messaging",
        }
    }

    fn evaluator(self) -> RegoPolicyEvaluator {
        match self {
            Self::GenericRest => RegoPolicyEvaluator::generic_rest_action_example(),
            Self::Gws => RegoPolicyEvaluator::gws_action_example(),
            Self::GitHub => RegoPolicyEvaluator::github_action_example(),
            Self::Messaging => RegoPolicyEvaluator::messaging_action_example(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LivePreviewPolicyEvaluation {
    pub consumer: LivePreviewConsumer,
    pub normalized_event: EventEnvelope,
    pub policy_decision: PolicyDecision,
    pub live_mode: LiveMode,
    pub coverage_posture: LiveCoveragePosture,
    pub mode_behavior: LiveModeBehavior,
    pub mode_status: String,
    pub record_status: String,
    pub approval_eligibility: ApprovalEligibility,
    pub coverage_display_rule: LiveCoverageDisplayRule,
}

impl LivePreviewPolicyEvaluation {
    pub fn summary(&self) -> String {
        format!(
            "consumer={} event_id={} decision={:?} coverage_posture={} mode_behavior={} mode_status={} record_status={} approval_eligibility={} coverage_display_rule={}",
            self.consumer.label(),
            self.normalized_event.event_id,
            self.policy_decision.decision,
            self.coverage_posture.label(),
            self.mode_behavior.label(),
            self.mode_status,
            self.record_status,
            self.approval_eligibility.label(),
            self.coverage_display_rule.label()
        )
    }
}

#[derive(Debug, Error)]
pub enum LivePreviewPolicyError {
    #[error("failed to evaluate {consumer:?} live preview policy for event `{event_id}`: {source}")]
    Evaluation {
        consumer: LivePreviewConsumer,
        event_id: String,
        #[source]
        source: agenta_policy::PolicyError,
    },
}

#[cfg(test)]
mod tests {
    use agenta_core::PolicyDecisionKind;

    use super::{LivePreviewConsumer, PolicyPlan};
    use crate::poc::live_proxy::{
        LiveProxyInterceptionPlan,
        generic_rest::GenericRestLivePreviewPlan,
        mode::{
            ApprovalEligibility, LiveCoverageDisplayRule, LiveCoveragePosture, LiveMode,
            LiveModeBehavior,
        },
    };

    #[test]
    fn policy_plan_evaluates_generic_rest_live_preview_and_projects_mode_specific_metadata() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let plan = live_proxy.policy;
        let generic_rest = GenericRestLivePreviewPlan::default();
        let event = generic_rest.preview_hold_gmail_users_messages_send();
        let evaluation = plan
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("generic REST live preview should evaluate");

        assert_eq!(
            evaluation.policy_decision.decision,
            PolicyDecisionKind::RequireApproval
        );
        assert_eq!(evaluation.live_mode, LiveMode::EnforcePreview);
        assert_eq!(
            evaluation.coverage_posture,
            LiveCoveragePosture::RecordOnlyPreview
        );
        assert_eq!(evaluation.mode_behavior, LiveModeBehavior::RecordOnly);
        assert_eq!(evaluation.mode_status, "enforce_preview_record_only");
        assert_eq!(
            evaluation.record_status,
            "enforce_preview_approval_request_recorded"
        );
        assert_eq!(
            evaluation.approval_eligibility,
            ApprovalEligibility::RecordOnly
        );
        assert_eq!(
            evaluation.coverage_display_rule,
            LiveCoverageDisplayRule::ShowPreviewSupportedAndFailOpen
        );
        assert_eq!(
            evaluation
                .normalized_event
                .action
                .attributes
                .get("coverage_posture")
                .and_then(|value| value.as_str()),
            Some("record_only_preview")
        );
        assert_eq!(
            evaluation
                .normalized_event
                .action
                .attributes
                .get("mode_behavior")
                .and_then(|value| value.as_str()),
            Some("record_only")
        );
        assert_eq!(
            evaluation
                .normalized_event
                .action
                .attributes
                .get("record_status")
                .and_then(|value| value.as_str()),
            Some("enforce_preview_approval_request_recorded")
        );
        assert_eq!(
            evaluation
                .normalized_event
                .action
                .attributes
                .get("coverage_display_rule")
                .and_then(|value| value.as_str()),
            Some("show_preview_supported_and_fail_open")
        );
    }

    #[test]
    fn shadow_mode_projects_advisory_only_status_for_require_approval_results() {
        let plan = PolicyPlan::from_semantic_conversion_boundary(
            LiveProxyInterceptionPlan::bootstrap()
                .semantic_conversion
                .handoff(),
        );
        let generic_rest = GenericRestLivePreviewPlan::default();
        let event = plan.annotate_preview_event(
            LivePreviewConsumer::GenericRest,
            &generic_rest.preview_hold_gmail_users_messages_send(),
            "shadow",
            "consumer=generic_rest provider=gws action=gmail.users.messages.send target=gmail.users/me",
        );
        let evaluation = plan
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("shadow preview should evaluate");

        assert_eq!(evaluation.live_mode, LiveMode::Shadow);
        assert_eq!(
            evaluation.coverage_posture,
            LiveCoveragePosture::ObserveOnlyPreview
        );
        assert_eq!(evaluation.mode_behavior, LiveModeBehavior::ObserveOnly);
        assert_eq!(evaluation.record_status, "shadow_require_approval_recorded");
        assert_eq!(
            evaluation.approval_eligibility,
            ApprovalEligibility::AdvisoryOnly
        );
        assert_eq!(
            evaluation.coverage_display_rule,
            LiveCoverageDisplayRule::ShowPreviewSupportedAndFailOpen
        );
    }

    #[test]
    fn annotate_preview_event_preserves_live_request_summary_and_consumer_hint() {
        let plan = PolicyPlan::from_semantic_conversion_boundary(
            LiveProxyInterceptionPlan::bootstrap()
                .semantic_conversion
                .handoff(),
        );
        let generic_rest = GenericRestLivePreviewPlan::default();
        let event = generic_rest.preview_allow_admin_reports_activities_list();
        let annotated = plan.annotate_preview_event(
            LivePreviewConsumer::GenericRest,
            &event,
            "shadow",
            "consumer=generic_rest provider=gws action=admin.reports.activities.list target=admin.reports/users/all/applications/drive",
        );

        assert_eq!(
            annotated
                .action
                .attributes
                .get("live_preview_consumer")
                .and_then(|value| value.as_str()),
            Some("generic_rest")
        );
        assert_eq!(
            annotated
                .action
                .attributes
                .get("live_request_summary")
                .and_then(|value| value.as_str()),
            Some(
                "consumer=generic_rest provider=gws action=admin.reports.activities.list target=admin.reports/users/all/applications/drive"
            )
        );
    }
}
