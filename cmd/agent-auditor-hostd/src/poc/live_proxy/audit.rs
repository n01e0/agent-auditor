use agenta_core::{
    ApprovalRequest, EnforcementDirective, EnforcementInfo, EnforcementStatus, EventEnvelope,
};
use agenta_policy::{apply_decision_to_event, apply_enforcement_to_event};
use serde_json::json;
use thiserror::Error;

use crate::poc::{
    github::persist::GitHubPocStore, gws::persist::GwsPocStore,
    messaging::persist::MessagingPocStore, rest::persist::GenericRestPocStore,
};

use super::{
    approval::LivePreviewApprovalProjection,
    contract::{
        ApprovalBoundary, AuditBoundary, LIVE_PROXY_INTERCEPTION_REDACTION_RULE, PolicyBoundary,
    },
    policy::LivePreviewPolicyEvaluation,
};

const LIVE_PREVIEW_REDACTION_STATUS: &str = "redaction_safe_preview_only";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPlan {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: AuditBoundary,
}

impl AuditPlan {
    pub fn from_policy_and_approval_boundaries(
        policy: PolicyBoundary,
        approval: ApprovalBoundary,
    ) -> Self {
        let modes = approval.modes;
        let input_fields = vec![
            "normalized_event",
            "policy_decision",
            "coverage_posture",
            "mode_behavior",
            "mode_status",
            "record_status",
            "approval_eligibility",
            "coverage_display_rule",
            "approval_request",
            "approval_hold_allowed",
            "hold_reason",
            "expiry_hint",
            "resume_token_hint",
            "wait_state",
        ];
        let record_fields = vec![
            "live_request_summary",
            "normalized_event",
            "policy_decision",
            "approval_request",
            "mode_behavior",
            "mode_status",
            "record_status",
            "failure_posture",
            "coverage_support",
            "coverage_display_rule",
            "coverage_summary",
            "coverage_gap",
            "realized_enforcement",
            "redaction_status",
        ];

        debug_assert!(
            policy
                .decision_fields
                .iter()
                .all(|field| input_fields.contains(field))
        );

        Self {
            modes: modes.clone(),
            input_fields: input_fields.clone(),
            record_fields: record_fields.clone(),
            responsibilities: vec![
                "append live preview, enforce-preview, or unsupported audit records without replaying proxy capture, session correlation, semantic conversion, or policy evaluation",
                "record the exact realized interception status, fail-open/fail-closed posture, and unsupported/preview-supported coverage claim so operators can tell modeled intent from real runtime effect",
                "preserve correlation ids and redaction-safe live request summaries for later control-plane reconciliation",
                "stay append-only and avoid becoming the owner of approval queue state, policy decisions, or provider-specific taxonomy",
            ],
            stages: vec!["reflect", "annotate_mode", "append", "publish"],
            handoff: AuditBoundary {
                modes,
                input_fields,
                record_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn reflect_preview_records(
        &self,
        evaluation: &LivePreviewPolicyEvaluation,
        approval: &LivePreviewApprovalProjection,
    ) -> LivePreviewAuditReflection {
        let decision_applied =
            apply_decision_to_event(&evaluation.normalized_event, &evaluation.policy_decision);
        let mode_projection = evaluation
            .live_mode
            .project(evaluation.policy_decision.decision);
        let enforcement = preview_enforcement_info(evaluation, approval);
        let mut audit_record = apply_enforcement_to_event(&decision_applied, &enforcement);
        let live_request_summary = live_request_summary(&audit_record);

        audit_record.action.attributes.insert(
            "coverage_posture".to_owned(),
            json!(evaluation.coverage_posture.label()),
        );
        audit_record.action.attributes.insert(
            "mode_behavior".to_owned(),
            json!(evaluation.mode_behavior.label()),
        );
        audit_record.action.attributes.insert(
            "mode_status".to_owned(),
            json!(evaluation.mode_status.clone()),
        );
        audit_record.action.attributes.insert(
            "record_status".to_owned(),
            json!(evaluation.record_status.clone()),
        );
        audit_record.action.attributes.insert(
            "approval_eligibility".to_owned(),
            json!(evaluation.approval_eligibility.label()),
        );
        audit_record.action.attributes.insert(
            "approval_hold_allowed".to_owned(),
            json!(approval.approval_hold_allowed),
        );
        audit_record.action.attributes.insert(
            "hold_reason".to_owned(),
            json!(approval.hold_reason.clone()),
        );
        audit_record
            .action
            .attributes
            .insert("wait_state".to_owned(), json!(approval.wait_state.clone()));
        audit_record.action.attributes.insert(
            "live_request_summary".to_owned(),
            json!(live_request_summary.clone()),
        );
        audit_record.action.attributes.insert(
            "failure_posture".to_owned(),
            json!(mode_projection.failure_posture.label()),
        );
        audit_record.action.attributes.insert(
            "coverage_support".to_owned(),
            json!(mode_projection.coverage_support.label()),
        );
        audit_record.action.attributes.insert(
            "coverage_display_rule".to_owned(),
            json!(mode_projection.coverage_display_rule.label()),
        );
        audit_record.action.attributes.insert(
            "coverage_summary".to_owned(),
            json!(mode_projection.coverage_summary),
        );
        audit_record.action.attributes.insert(
            "coverage_gap".to_owned(),
            json!(mode_projection.coverage_gap),
        );
        audit_record.action.attributes.insert(
            "redaction_status".to_owned(),
            json!(LIVE_PREVIEW_REDACTION_STATUS),
        );

        LivePreviewAuditReflection {
            live_request_summary,
            audit_record,
            approval_request: approval.approval_request.clone(),
            mode_behavior: evaluation.mode_behavior.label().to_owned(),
            mode_status: evaluation.mode_status.clone(),
            record_status: evaluation.record_status.clone(),
            failure_posture: mode_projection.failure_posture.label().to_owned(),
            coverage_support: mode_projection.coverage_support.label().to_owned(),
            coverage_display_rule: mode_projection.coverage_display_rule.label().to_owned(),
            coverage_summary: mode_projection.coverage_summary.to_owned(),
            coverage_gap: mode_projection.coverage_gap.to_owned(),
            realized_enforcement: enforcement,
            redaction_status: LIVE_PREVIEW_REDACTION_STATUS,
        }
    }

    pub fn persist_reflection<S: LivePreviewStore>(
        &self,
        store: &S,
        reflection: &LivePreviewAuditReflection,
    ) -> Result<(), LivePreviewPersistenceError> {
        store
            .append_audit_record(&reflection.audit_record)
            .map_err(|message| LivePreviewPersistenceError::AppendAudit {
                event_id: reflection.audit_record.event_id.clone(),
                message,
            })?;

        if let Some(approval_request) = &reflection.approval_request {
            store
                .append_approval_request(approval_request)
                .map_err(|message| LivePreviewPersistenceError::AppendApproval {
                    approval_id: approval_request.approval_id.clone(),
                    message,
                })?;
        }

        Ok(())
    }

    pub fn handoff(&self) -> AuditBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "modes={} record_fields={} stages={}",
            self.modes.join(","),
            self.record_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LivePreviewAuditReflection {
    pub live_request_summary: String,
    pub audit_record: EventEnvelope,
    pub approval_request: Option<ApprovalRequest>,
    pub mode_behavior: String,
    pub mode_status: String,
    pub record_status: String,
    pub failure_posture: String,
    pub coverage_support: String,
    pub coverage_display_rule: String,
    pub coverage_summary: String,
    pub coverage_gap: String,
    pub realized_enforcement: EnforcementInfo,
    pub redaction_status: &'static str,
}

impl LivePreviewAuditReflection {
    pub fn summary(&self) -> String {
        format!(
            "event_id={} approval_request={} mode_behavior={} mode_status={} record_status={} failure_posture={} coverage_support={} coverage_display_rule={} coverage_gap={} redaction_status={}",
            self.audit_record.event_id,
            self.approval_request
                .as_ref()
                .map(|request| request.approval_id.as_str())
                .unwrap_or("none"),
            self.mode_behavior,
            self.mode_status,
            self.record_status,
            self.failure_posture,
            self.coverage_support,
            self.coverage_display_rule,
            self.coverage_gap,
            self.redaction_status
        )
    }
}

pub trait LivePreviewStore {
    fn append_audit_record(&self, event: &EventEnvelope) -> Result<(), String>;
    fn append_approval_request(&self, request: &ApprovalRequest) -> Result<(), String>;
}

impl LivePreviewStore for GenericRestPocStore {
    fn append_audit_record(&self, event: &EventEnvelope) -> Result<(), String> {
        self.append_audit_record(event)
            .map_err(|error| error.to_string())
    }

    fn append_approval_request(&self, request: &ApprovalRequest) -> Result<(), String> {
        self.append_approval_request(request)
            .map_err(|error| error.to_string())
    }
}

impl LivePreviewStore for GwsPocStore {
    fn append_audit_record(&self, event: &EventEnvelope) -> Result<(), String> {
        self.append_audit_record(event)
            .map_err(|error| error.to_string())
    }

    fn append_approval_request(&self, request: &ApprovalRequest) -> Result<(), String> {
        self.append_approval_request(request)
            .map_err(|error| error.to_string())
    }
}

impl LivePreviewStore for GitHubPocStore {
    fn append_audit_record(&self, event: &EventEnvelope) -> Result<(), String> {
        self.append_audit_record(event)
            .map_err(|error| error.to_string())
    }

    fn append_approval_request(&self, request: &ApprovalRequest) -> Result<(), String> {
        self.append_approval_request(request)
            .map_err(|error| error.to_string())
    }
}

impl LivePreviewStore for MessagingPocStore {
    fn append_audit_record(&self, event: &EventEnvelope) -> Result<(), String> {
        self.append_audit_record(event)
            .map_err(|error| error.to_string())
    }

    fn append_approval_request(&self, request: &ApprovalRequest) -> Result<(), String> {
        self.append_approval_request(request)
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LivePreviewPersistenceError {
    #[error("failed to append live preview audit record for event `{event_id}`: {message}")]
    AppendAudit { event_id: String, message: String },
    #[error("failed to append live preview approval request `{approval_id}`: {message}")]
    AppendApproval {
        approval_id: String,
        message: String,
    },
}

fn preview_enforcement_info(
    evaluation: &LivePreviewPolicyEvaluation,
    approval: &LivePreviewApprovalProjection,
) -> EnforcementInfo {
    let mode_projection = evaluation
        .live_mode
        .project(evaluation.policy_decision.decision);

    EnforcementInfo {
        directive: directive_for_decision(evaluation.policy_decision.decision),
        status: EnforcementStatus::ObserveOnlyFallback,
        status_reason: Some(mode_projection.status_reason.to_owned()),
        enforced: false,
        coverage_gap: Some(mode_projection.coverage_gap.to_owned()),
        approval_id: approval
            .approval_request
            .as_ref()
            .map(|request| request.approval_id.clone()),
        expires_at: approval.expiry_hint,
    }
}

fn directive_for_decision(decision: agenta_core::PolicyDecisionKind) -> EnforcementDirective {
    match decision {
        agenta_core::PolicyDecisionKind::Allow => EnforcementDirective::Allow,
        agenta_core::PolicyDecisionKind::RequireApproval => EnforcementDirective::Hold,
        agenta_core::PolicyDecisionKind::Deny => EnforcementDirective::Deny,
    }
}

fn live_request_summary(event: &EventEnvelope) -> String {
    event
        .action
        .attributes
        .get("live_request_summary")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "class={:?} verb={} target={}",
                event.action.class,
                event.action.verb.as_deref().unwrap_or("unknown"),
                event.action.target.as_deref().unwrap_or("unknown")
            )
        })
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        EnforcementDirective, EnforcementStatus, ResultStatus, SessionRecord, SessionWorkspace,
    };

    use super::LIVE_PREVIEW_REDACTION_STATUS;
    use crate::poc::{
        github::{GitHubSemanticGovernancePocPlan, persist::GitHubPocStore},
        gws::{ApiNetworkGwsPocPlan, persist::GwsPocStore},
        live_proxy::{
            LiveProxyInterceptionPlan, generic_rest::GenericRestLivePreviewPlan,
            github::GitHubLivePreviewAdapterPlan, gws::GwsLivePreviewAdapterPlan,
            messaging::MessagingLivePreviewAdapterPlan, policy::LivePreviewConsumer,
        },
        messaging::{MessagingCollaborationGovernancePlan, persist::MessagingPocStore},
        rest::persist::GenericRestPocStore,
    };

    #[test]
    fn audit_plan_reflects_record_only_hold_records_for_enforce_preview_generic_rest() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let store = GenericRestPocStore::fresh(unique_store_dir("generic-rest-enforce-preview"))
            .expect("generic REST store should init");
        let event = GenericRestLivePreviewPlan::default().preview_hold_gmail_users_messages_send();
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("generic REST live preview should evaluate");
        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("approval projection should succeed");
        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);

        live_proxy
            .audit
            .persist_reflection(&store, &reflection)
            .expect("generic REST reflection should persist");

        let persisted_audit = store
            .latest_audit_record()
            .expect("audit record should load")
            .expect("audit record should exist");
        let persisted_request = store
            .latest_approval_request()
            .expect("approval request should load")
            .expect("approval request should exist");

        assert_eq!(persisted_audit.result.status, ResultStatus::Observed);
        assert_eq!(
            persisted_audit
                .enforcement
                .as_ref()
                .map(|info| info.directive),
            Some(EnforcementDirective::Hold)
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("mode_status")
                .and_then(|value| value.as_str()),
            Some("enforce_preview_record_only")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("record_status")
                .and_then(|value| value.as_str()),
            Some("enforce_preview_approval_request_recorded")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("failure_posture")
                .and_then(|value| value.as_str()),
            Some("fail_open")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_support")
                .and_then(|value| value.as_str()),
            Some("preview_supported")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_display_rule")
                .and_then(|value| value.as_str()),
            Some("show_preview_supported_and_fail_open")
        );
        assert!(
            persisted_audit
                .action
                .attributes
                .get("coverage_summary")
                .and_then(|value| value.as_str())
                .expect("coverage_summary should exist")
                .contains("record-only path")
        );
        assert_eq!(
            persisted_request
                .enforcement
                .as_ref()
                .and_then(|info| info.coverage_gap.as_deref()),
            Some("enforce_preview_has_no_inline_hold_deny_or_resume")
        );
    }

    #[test]
    fn audit_plan_reflects_shadow_mode_as_observe_only_without_approval_records() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let store = GenericRestPocStore::fresh(unique_store_dir("generic-rest-shadow"))
            .expect("generic REST store should init");
        let event = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::GenericRest,
            &GenericRestLivePreviewPlan::default().preview_hold_gmail_users_messages_send(),
            "shadow",
            "consumer=generic_rest provider=gws action=gmail.users.messages.send target=gmail.users/me",
        );
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &event)
            .expect("shadow live preview should evaluate");
        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("shadow approval projection should succeed");
        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);

        live_proxy
            .audit
            .persist_reflection(&store, &reflection)
            .expect("shadow reflection should persist");

        let persisted_audit = store
            .latest_audit_record()
            .expect("audit record should load")
            .expect("audit record should exist");
        assert_eq!(persisted_audit.result.status, ResultStatus::Observed);
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("mode_behavior")
                .and_then(|value| value.as_str()),
            Some("observe_only")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("record_status")
                .and_then(|value| value.as_str()),
            Some("shadow_require_approval_recorded")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("failure_posture")
                .and_then(|value| value.as_str()),
            Some("fail_open")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_support")
                .and_then(|value| value.as_str()),
            Some("preview_supported")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_display_rule")
                .and_then(|value| value.as_str()),
            Some("show_preview_supported_and_fail_open")
        );
        assert!(
            persisted_audit
                .action
                .attributes
                .get("coverage_summary")
                .and_then(|value| value.as_str())
                .expect("coverage_summary should exist")
                .contains("observe-only path")
        );
        assert!(
            store
                .latest_approval_request()
                .expect("approval log should load")
                .is_none()
        );
    }

    #[test]
    fn audit_plan_reflects_gws_allow_preview_and_preserves_redaction_status() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let gws_live = GwsLivePreviewAdapterPlan::default();
        let gws_plan = ApiNetworkGwsPocPlan::bootstrap();
        let store = GwsPocStore::fresh(unique_store_dir("gws-shadow-allow"))
            .expect("GWS store should init");
        let normalized = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::Gws,
            &gws_plan.evaluate.normalize_classified_action(
                &gws_live.preview_admin_reports_activities_list(),
                &placeholder_session(
                    "openclaw-main",
                    "sess_live_proxy_admin_reports_activities_list_preview",
                ),
            ),
            "shadow",
            "consumer=gws action=admin.reports.activities.list target=admin.reports/users/all/applications/drive",
        );
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::Gws, &normalized)
            .expect("GWS live preview should evaluate");
        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("allow preview should not need approval");
        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);

        live_proxy
            .audit
            .persist_reflection(&store, &reflection)
            .expect("GWS reflection should persist");

        let persisted_audit = store
            .latest_audit_record()
            .expect("audit record should load")
            .expect("audit record should exist");
        assert_eq!(persisted_audit.result.status, ResultStatus::Observed);
        assert_eq!(
            persisted_audit
                .enforcement
                .as_ref()
                .map(|info| info.directive),
            Some(EnforcementDirective::Allow)
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("redaction_status")
                .and_then(|value| value.as_str()),
            Some(LIVE_PREVIEW_REDACTION_STATUS)
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("observation_provenance")
                .and_then(|value| value.as_str()),
            Some("fixture_preview")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("validation_status")
                .and_then(|value| value.as_str()),
            Some("fixture_preview")
        );
    }

    #[test]
    fn audit_plan_reflects_unsupported_mode_for_github_deny_records() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let github_live = GitHubLivePreviewAdapterPlan::default();
        let github_plan = GitHubSemanticGovernancePocPlan::bootstrap();
        let store = GitHubPocStore::fresh(unique_store_dir("github-unsupported-deny"))
            .expect("GitHub store should init");
        let normalized = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::GitHub,
            &github_plan.policy.normalize_classified_action(
                &github_live.preview_actions_secrets_create_or_update(),
                &placeholder_session(
                    "openclaw-main",
                    "sess_live_proxy_github_actions_secrets_create_or_update_preview",
                ),
            ),
            "unsupported",
            "consumer=github action=actions.secrets.create_or_update target=repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
        );
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GitHub, &normalized)
            .expect("GitHub live preview should evaluate");
        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("deny preview should not need approval");
        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);

        live_proxy
            .audit
            .persist_reflection(&store, &reflection)
            .expect("GitHub reflection should persist");

        let persisted_audit = store
            .latest_audit_record()
            .expect("audit record should load")
            .expect("audit record should exist");
        assert_eq!(persisted_audit.result.status, ResultStatus::Observed);
        assert_eq!(
            persisted_audit
                .enforcement
                .as_ref()
                .map(|info| info.directive),
            Some(EnforcementDirective::Deny)
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("mode_status")
                .and_then(|value| value.as_str()),
            Some("unsupported_preview_only")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("failure_posture")
                .and_then(|value| value.as_str()),
            Some("fail_open")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_support")
                .and_then(|value| value.as_str()),
            Some("unsupported")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_display_rule")
                .and_then(|value| value.as_str()),
            Some("show_unsupported_and_fail_open")
        );
        assert!(
            persisted_audit
                .action
                .attributes
                .get("coverage_summary")
                .and_then(|value| value.as_str())
                .expect("coverage_summary should exist")
                .contains("unsupported live preview path")
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_gap")
                .and_then(|value| value.as_str()),
            Some("unsupported_mode_has_no_supported_live_preview_contract")
        );
    }

    #[test]
    fn audit_plan_reflects_record_only_hold_records_for_messaging() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let messaging_live = MessagingLivePreviewAdapterPlan::default();
        let messaging_plan = MessagingCollaborationGovernancePlan::bootstrap();
        let store = MessagingPocStore::fresh(unique_store_dir("messaging-enforce-preview"))
            .expect("messaging store should init");
        let normalized = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::Messaging,
            &messaging_plan.policy.normalize_classified_action(
                &messaging_live.preview_slack_conversations_invite(),
                &placeholder_session(
                    "openclaw-main",
                    "sess_live_proxy_slack_conversations_invite_preview",
                ),
            ),
            "enforce_preview",
            "consumer=messaging action=conversations.invite target=slack.channels/C12345678/members/U23456789",
        );
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::Messaging, &normalized)
            .expect("messaging live preview should evaluate");
        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("messaging hold preview should create approval state");
        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);

        live_proxy
            .audit
            .persist_reflection(&store, &reflection)
            .expect("messaging reflection should persist");

        let persisted_request = store
            .latest_approval_request()
            .expect("approval request should load")
            .expect("approval request should exist");

        assert_eq!(reflection.mode_status, "enforce_preview_record_only");
        assert_eq!(
            reflection.record_status,
            "enforce_preview_approval_request_recorded"
        );
        assert_eq!(reflection.failure_posture, "fail_open");
        assert_eq!(reflection.coverage_support, "preview_supported");
        assert_eq!(
            reflection.coverage_display_rule,
            "show_preview_supported_and_fail_open"
        );
        assert!(reflection.coverage_summary.contains("record-only path"));
        assert_eq!(
            persisted_request
                .enforcement
                .as_ref()
                .map(|info| info.status),
            Some(EnforcementStatus::ObserveOnlyFallback)
        );
        assert_eq!(
            persisted_request
                .request
                .attributes
                .get("observation_provenance")
                .and_then(|value| value.as_str()),
            Some("fixture_preview")
        );
        assert_eq!(
            persisted_request
                .request
                .attributes
                .get("validation_status")
                .and_then(|value| value.as_str()),
            Some("fixture_preview")
        );
    }

    #[test]
    fn audit_plan_summary_advertises_failure_posture_and_coverage_visibility_fields() {
        let summary = LiveProxyInterceptionPlan::bootstrap().audit.summary();

        assert!(summary.contains("failure_posture"));
        assert!(summary.contains("coverage_support"));
        assert!(summary.contains("coverage_display_rule"));
        assert!(summary.contains("coverage_summary"));
        assert!(summary.contains("coverage_gap"));
    }

    #[test]
    fn reflection_summary_keeps_fail_open_and_unsupported_visibility_explicit() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let github_live = GitHubLivePreviewAdapterPlan::default();
        let github_plan = GitHubSemanticGovernancePocPlan::bootstrap();
        let normalized = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::GitHub,
            &github_plan.policy.normalize_classified_action(
                &github_live.preview_actions_secrets_create_or_update(),
                &placeholder_session(
                    "openclaw-main",
                    "sess_live_proxy_summary_github_actions_secrets_create_or_update_preview",
                ),
            ),
            "unsupported",
            "consumer=github action=actions.secrets.create_or_update target=repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
        );
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GitHub, &normalized)
            .expect("GitHub live preview should evaluate");
        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .expect("deny preview should not need approval");
        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);
        let summary = reflection.summary();

        assert!(summary.contains("failure_posture=fail_open"));
        assert!(summary.contains("coverage_support=unsupported"));
        assert!(summary.contains("coverage_display_rule=show_unsupported_and_fail_open"));
        assert!(
            summary
                .contains("coverage_gap=unsupported_mode_has_no_supported_live_preview_contract")
        );
        assert!(!summary.contains("fail_closed"));
    }

    fn unique_store_dir(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "agent-auditor-hostd-live-preview-{}-{}",
                name,
                std::process::id()
            ))
    }

    fn placeholder_session(agent_id: &str, session_id: &str) -> SessionRecord {
        let mut session = SessionRecord::placeholder(agent_id, session_id);
        session.workspace = Some(SessionWorkspace {
            workspace_id: Some("agent-auditor".to_owned()),
            path: Some("/home/shioriko/src/github.com/n01e0/agent-auditor".to_owned()),
            repo: Some("n01e0/agent-auditor".to_owned()),
            branch: Some("main".to_owned()),
        });
        session
    }
}
