use agenta_core::{EventEnvelope, PolicyDecisionKind, SessionRecord, SessionWorkspace};

use crate::poc::{
    github::GitHubSemanticGovernancePocPlan,
    gws::ApiNetworkGwsPocPlan,
    live_proxy::{
        LiveProxyInterceptionPlan, generic_rest::GenericRestLivePreviewPlan,
        github::GitHubLivePreviewAdapterPlan, gws::GwsLivePreviewAdapterPlan,
        messaging::MessagingLivePreviewAdapterPlan, mode::LiveMode, policy::LivePreviewConsumer,
    },
    messaging::MessagingCollaborationGovernancePlan,
};

#[derive(Debug, Clone, PartialEq)]
pub struct LiveProxyFixtureCase {
    pub name: &'static str,
    pub consumer: LivePreviewConsumer,
    pub mode: LiveMode,
    pub event: EventEnvelope,
    pub expected_decision: PolicyDecisionKind,
    pub expected_coverage_posture: &'static str,
    pub expected_mode_behavior: &'static str,
    pub expected_mode_status: &'static str,
    pub expected_record_status: &'static str,
    pub expected_failure_posture: &'static str,
    pub expected_coverage_support: &'static str,
    pub expected_coverage_display_rule: &'static str,
    pub expected_coverage_summary: &'static str,
    pub expected_coverage_gap: &'static str,
    pub expect_approval_request: bool,
    pub expected_wait_state: Option<&'static str>,
}

impl LiveProxyFixtureCase {
    pub fn summary(&self) -> String {
        format!(
            "name={} consumer={} mode={} decision={:?} approval_request={}",
            self.name,
            self.consumer.label(),
            self.mode.label(),
            self.expected_decision,
            self.expect_approval_request
        )
    }
}

pub fn seam_fixture_catalog() -> Vec<LiveProxyFixtureCase> {
    let live_proxy = LiveProxyInterceptionPlan::bootstrap();
    let generic_rest = GenericRestLivePreviewPlan::default();
    let gws_live = GwsLivePreviewAdapterPlan::default();
    let github_live = GitHubLivePreviewAdapterPlan::default();
    let messaging_live = MessagingLivePreviewAdapterPlan::default();
    let gws_plan = ApiNetworkGwsPocPlan::bootstrap();
    let github_plan = GitHubSemanticGovernancePocPlan::bootstrap();
    let messaging_plan = MessagingCollaborationGovernancePlan::bootstrap();

    vec![
        LiveProxyFixtureCase {
            name: "generic_rest_enforce_preview_hold",
            consumer: LivePreviewConsumer::GenericRest,
            mode: LiveMode::EnforcePreview,
            event: live_proxy.policy.annotate_preview_event(
                LivePreviewConsumer::GenericRest,
                &generic_rest.preview_hold_gmail_users_messages_send(),
                LiveMode::EnforcePreview.label(),
                "consumer=generic_rest provider=gws action=gmail.users.messages.send target=gmail.users/me",
            ),
            expected_decision: PolicyDecisionKind::RequireApproval,
            expected_coverage_posture: "record_only_preview",
            expected_mode_behavior: "record_only",
            expected_mode_status: "enforce_preview_record_only",
            expected_record_status: "enforce_preview_approval_request_recorded",
            expected_failure_posture: "fail_open",
            expected_coverage_support: "preview_supported",
            expected_coverage_display_rule: "show_preview_supported_and_fail_open",
            expected_coverage_summary: "preview-supported record-only path; approval or deny intent is reflected locally but the live request remains fail-open",
            expected_coverage_gap: "enforce_preview_has_no_inline_hold_deny_or_resume",
            expect_approval_request: true,
            expected_wait_state: Some("pending_approval_record_only"),
        },
        LiveProxyFixtureCase {
            name: "generic_rest_shadow_hold_advisory_only",
            consumer: LivePreviewConsumer::GenericRest,
            mode: LiveMode::Shadow,
            event: live_proxy.policy.annotate_preview_event(
                LivePreviewConsumer::GenericRest,
                &generic_rest.preview_hold_gmail_users_messages_send(),
                LiveMode::Shadow.label(),
                "consumer=generic_rest provider=gws action=gmail.users.messages.send target=gmail.users/me",
            ),
            expected_decision: PolicyDecisionKind::RequireApproval,
            expected_coverage_posture: "observe_only_preview",
            expected_mode_behavior: "observe_only",
            expected_mode_status: "shadow_observe_only",
            expected_record_status: "shadow_require_approval_recorded",
            expected_failure_posture: "fail_open",
            expected_coverage_support: "preview_supported",
            expected_coverage_display_rule: "show_preview_supported_and_fail_open",
            expected_coverage_summary: "preview-supported observe-only path; policy intent is recorded but the live request remains fail-open",
            expected_coverage_gap: "shadow_mode_has_no_inline_hold_deny_or_resume",
            expect_approval_request: false,
            expected_wait_state: Some("shadow_observe_only"),
        },
        LiveProxyFixtureCase {
            name: "gws_shadow_allow",
            consumer: LivePreviewConsumer::Gws,
            mode: LiveMode::Shadow,
            event: live_proxy.policy.annotate_preview_event(
                LivePreviewConsumer::Gws,
                &gws_plan.evaluate.normalize_classified_action(
                    &gws_live.preview_admin_reports_activities_list(),
                    &placeholder_session(
                        "openclaw-main",
                        "sess_fixture_gws_shadow_allow",
                    ),
                ),
                LiveMode::Shadow.label(),
                "consumer=gws action=admin.reports.activities.list target=admin.reports/users/all/applications/drive",
            ),
            expected_decision: PolicyDecisionKind::Allow,
            expected_coverage_posture: "observe_only_preview",
            expected_mode_behavior: "observe_only",
            expected_mode_status: "shadow_observe_only",
            expected_record_status: "shadow_allow_recorded",
            expected_failure_posture: "fail_open",
            expected_coverage_support: "preview_supported",
            expected_coverage_display_rule: "show_preview_supported_and_fail_open",
            expected_coverage_summary: "preview-supported observe-only path; policy intent is recorded but the live request remains fail-open",
            expected_coverage_gap: "shadow_mode_has_no_inline_hold_deny_or_resume",
            expect_approval_request: false,
            expected_wait_state: None,
        },
        LiveProxyFixtureCase {
            name: "github_unsupported_deny",
            consumer: LivePreviewConsumer::GitHub,
            mode: LiveMode::Unsupported,
            event: live_proxy.policy.annotate_preview_event(
                LivePreviewConsumer::GitHub,
                &github_plan.policy.normalize_classified_action(
                    &github_live.preview_actions_secrets_create_or_update(),
                    &placeholder_session(
                        "openclaw-main",
                        "sess_fixture_github_unsupported_deny",
                    ),
                ),
                LiveMode::Unsupported.label(),
                "consumer=github action=actions.secrets.create_or_update target=repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
            ),
            expected_decision: PolicyDecisionKind::Deny,
            expected_coverage_posture: "unsupported_preview",
            expected_mode_behavior: "unsupported",
            expected_mode_status: "unsupported_preview_only",
            expected_record_status: "unsupported_deny_recorded",
            expected_failure_posture: "fail_open",
            expected_coverage_support: "unsupported",
            expected_coverage_display_rule: "show_unsupported_and_fail_open",
            expected_coverage_summary: "unsupported live preview path; policy signals are diagnostic only and the live request remains fail-open",
            expected_coverage_gap: "unsupported_mode_has_no_supported_live_preview_contract",
            expect_approval_request: false,
            expected_wait_state: None,
        },
        LiveProxyFixtureCase {
            name: "messaging_enforce_preview_hold",
            consumer: LivePreviewConsumer::Messaging,
            mode: LiveMode::EnforcePreview,
            event: live_proxy.policy.annotate_preview_event(
                LivePreviewConsumer::Messaging,
                &messaging_plan.policy.normalize_classified_action(
                    &messaging_live.preview_slack_conversations_invite(),
                    &placeholder_session(
                        "openclaw-main",
                        "sess_fixture_messaging_enforce_preview_hold",
                    ),
                ),
                LiveMode::EnforcePreview.label(),
                "consumer=messaging action=conversations.invite target=slack.channels/C12345678/members/U23456789",
            ),
            expected_decision: PolicyDecisionKind::RequireApproval,
            expected_coverage_posture: "record_only_preview",
            expected_mode_behavior: "record_only",
            expected_mode_status: "enforce_preview_record_only",
            expected_record_status: "enforce_preview_approval_request_recorded",
            expected_failure_posture: "fail_open",
            expected_coverage_support: "preview_supported",
            expected_coverage_display_rule: "show_preview_supported_and_fail_open",
            expected_coverage_summary: "preview-supported record-only path; approval or deny intent is reflected locally but the live request remains fail-open",
            expected_coverage_gap: "enforce_preview_has_no_inline_hold_deny_or_resume",
            expect_approval_request: true,
            expected_wait_state: Some("pending_approval_record_only"),
        },
    ]
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

#[cfg(test)]
mod tests {
    use super::seam_fixture_catalog;

    #[test]
    fn seam_fixture_catalog_covers_modes_consumers_and_policy_shapes() {
        let fixtures = seam_fixture_catalog();

        assert_eq!(fixtures.len(), 5);
        assert!(
            fixtures
                .iter()
                .any(|fixture| fixture.mode.label() == "shadow")
        );
        assert!(
            fixtures
                .iter()
                .any(|fixture| fixture.mode.label() == "enforce_preview")
        );
        assert!(
            fixtures
                .iter()
                .any(|fixture| fixture.mode.label() == "unsupported")
        );
        assert!(
            fixtures
                .iter()
                .any(|fixture| fixture.consumer.label() == "generic_rest")
        );
        assert!(
            fixtures
                .iter()
                .any(|fixture| fixture.consumer.label() == "gws")
        );
        assert!(
            fixtures
                .iter()
                .any(|fixture| fixture.consumer.label() == "github")
        );
        assert!(
            fixtures
                .iter()
                .any(|fixture| fixture.consumer.label() == "messaging")
        );
    }

    #[test]
    fn seam_fixture_events_are_annotated_with_mode_and_live_request_summary() {
        for fixture in seam_fixture_catalog() {
            assert_eq!(
                fixture
                    .event
                    .action
                    .attributes
                    .get("mode")
                    .and_then(|value| value.as_str()),
                Some(fixture.mode.label())
            );
            assert_eq!(
                fixture
                    .event
                    .action
                    .attributes
                    .get("live_preview_consumer")
                    .and_then(|value| value.as_str()),
                Some(fixture.consumer.label())
            );
            assert!(
                fixture
                    .event
                    .action
                    .attributes
                    .get("live_request_summary")
                    .and_then(|value| value.as_str())
                    .is_some()
            );
        }
    }
}
