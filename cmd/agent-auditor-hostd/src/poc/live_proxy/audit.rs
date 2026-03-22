use agenta_core::{
    ApprovalRequest, EnforcementDirective, EnforcementInfo, EnforcementStatus, EventEnvelope,
    PolicyDecisionKind,
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

const LIVE_PREVIEW_COVERAGE_GAP: &str = "live_preview_path_has_no_inline_hold_deny_or_resume";
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
            "mode_status",
            "approval_eligibility",
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
            "mode_status",
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
                "record the exact realized interception status, coverage gap, and approval linkage so operators can tell modeled intent from real runtime effect",
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
        let enforcement = preview_enforcement_info(evaluation, approval);
        let mut audit_record = apply_enforcement_to_event(&decision_applied, &enforcement);
        let live_request_summary = live_request_summary(&audit_record);

        audit_record.action.attributes.insert(
            "coverage_posture".to_owned(),
            json!(evaluation.coverage_posture.label()),
        );
        audit_record.action.attributes.insert(
            "mode_status".to_owned(),
            json!(evaluation.mode_status.clone()),
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
        audit_record
            .action
            .attributes
            .insert("coverage_gap".to_owned(), json!(LIVE_PREVIEW_COVERAGE_GAP));
        audit_record.action.attributes.insert(
            "redaction_status".to_owned(),
            json!(LIVE_PREVIEW_REDACTION_STATUS),
        );

        LivePreviewAuditReflection {
            live_request_summary,
            audit_record,
            approval_request: approval.approval_request.clone(),
            mode_status: evaluation.mode_status.clone(),
            coverage_gap: LIVE_PREVIEW_COVERAGE_GAP.to_owned(),
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
    pub mode_status: String,
    pub coverage_gap: String,
    pub realized_enforcement: EnforcementInfo,
    pub redaction_status: &'static str,
}

impl LivePreviewAuditReflection {
    pub fn summary(&self) -> String {
        format!(
            "event_id={} approval_request={} mode_status={} coverage_gap={} redaction_status={}",
            self.audit_record.event_id,
            self.approval_request
                .as_ref()
                .map(|request| request.approval_id.as_str())
                .unwrap_or("none"),
            self.mode_status,
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
    EnforcementInfo {
        directive: directive_for_decision(evaluation.policy_decision.decision),
        status: EnforcementStatus::ObserveOnlyFallback,
        status_reason: Some(preview_status_reason(evaluation.policy_decision.decision)),
        enforced: false,
        coverage_gap: Some(LIVE_PREVIEW_COVERAGE_GAP.to_owned()),
        approval_id: approval
            .approval_request
            .as_ref()
            .map(|request| request.approval_id.clone()),
        expires_at: approval.expiry_hint,
    }
}

fn directive_for_decision(decision: PolicyDecisionKind) -> EnforcementDirective {
    match decision {
        PolicyDecisionKind::Allow => EnforcementDirective::Allow,
        PolicyDecisionKind::RequireApproval => EnforcementDirective::Hold,
        PolicyDecisionKind::Deny => EnforcementDirective::Deny,
    }
}

fn preview_status_reason(decision: PolicyDecisionKind) -> String {
    match decision {
        PolicyDecisionKind::Allow => {
            "live preview path observed an allow decision without requiring inline runtime intervention"
                .to_owned()
        }
        PolicyDecisionKind::RequireApproval => {
            "live preview path recorded approval intent but cannot pause the in-flight provider request yet"
                .to_owned()
        }
        PolicyDecisionKind::Deny => {
            "live preview path recorded a deny result but cannot block the in-flight provider request yet"
                .to_owned()
        }
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

    use super::{LIVE_PREVIEW_COVERAGE_GAP, LIVE_PREVIEW_REDACTION_STATUS};
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
    fn audit_plan_reflects_preview_only_hold_records_for_generic_rest_and_persists_them() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let store = GenericRestPocStore::bootstrap().expect("generic REST store should init");
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
            persisted_audit.enforcement.as_ref().map(|info| info.status),
            Some(EnforcementStatus::ObserveOnlyFallback)
        );
        assert_eq!(
            persisted_audit
                .action
                .attributes
                .get("coverage_gap")
                .and_then(|value| value.as_str()),
            Some(LIVE_PREVIEW_COVERAGE_GAP)
        );
        assert_eq!(
            persisted_request
                .enforcement
                .as_ref()
                .and_then(|info| info.coverage_gap.as_deref()),
            Some(LIVE_PREVIEW_COVERAGE_GAP)
        );
    }

    #[test]
    fn audit_plan_reflects_preview_only_allow_records_for_gws() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let gws_live = GwsLivePreviewAdapterPlan::default();
        let gws_plan = ApiNetworkGwsPocPlan::bootstrap();
        let store = GwsPocStore::bootstrap().expect("GWS store should init");
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
        assert!(
            store
                .latest_approval_request()
                .expect("approval log should load")
                .is_none()
        );
    }

    #[test]
    fn audit_plan_reflects_preview_only_deny_records_for_github() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let github_live = GitHubLivePreviewAdapterPlan::default();
        let github_plan = GitHubSemanticGovernancePocPlan::bootstrap();
        let store = GitHubPocStore::bootstrap().expect("GitHub store should init");
        let normalized = live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::GitHub,
            &github_plan.policy.normalize_classified_action(
                &github_live.preview_actions_secrets_create_or_update(),
                &placeholder_session(
                    "openclaw-main",
                    "sess_live_proxy_github_actions_secrets_create_or_update_preview",
                ),
            ),
            "enforce_preview",
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
                .enforcement
                .as_ref()
                .map(|info| info.enforced),
            Some(false)
        );
    }

    #[test]
    fn audit_plan_reflects_preview_only_hold_records_for_messaging() {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let messaging_live = MessagingLivePreviewAdapterPlan::default();
        let messaging_plan = MessagingCollaborationGovernancePlan::bootstrap();
        let store = MessagingPocStore::bootstrap().expect("messaging store should init");
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
            persisted_request
                .enforcement
                .as_ref()
                .map(|info| info.status),
            Some(EnforcementStatus::ObserveOnlyFallback)
        );
        assert_eq!(reflection.mode_status, "enforce_preview_record_only");
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
