use agenta_core::{ApprovalRequest, EventEnvelope, PolicyDecision, PolicyDecisionKind};
use serde_json::Value;
use thiserror::Error;

use super::{
    contract::GwsActionKind,
    posture::{GwsEnforcementPosture, approval_hold_actions, posture_for_action},
};
use crate::poc::enforcement::contract::{
    EnforcementDirective, EnforcementOutcome, EnforcementScope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPathPlan {
    pub semantic_actions: Vec<GwsActionKind>,
    pub input_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub directive: EnforcementDirective,
}

impl Default for ApprovalPathPlan {
    fn default() -> Self {
        Self {
            semantic_actions: approval_hold_actions(),
            input_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "semantic_action_label",
                "posture",
            ],
            responsibilities: vec![
                "own the minimal require_approval path for normalized GWS semantic actions after policy evaluation",
                "limit the preview path to actions whose posture is approval_hold_preview",
                "require an approval request before projecting a held GWS enforcement outcome",
                "handoff a GWS-scoped hold outcome for later event and record reflection without mutating persistence itself",
            ],
            stages: vec!["accept", "verify_posture", "hold_projection"],
            directive: EnforcementDirective::Hold,
        }
    }
}

impl ApprovalPathPlan {
    pub fn apply(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        approval_request: Option<&ApprovalRequest>,
    ) -> Result<EnforcementOutcome, ApprovalPathError> {
        let action = semantic_action_from_event(event).ok_or_else(|| {
            ApprovalPathError::MissingSemanticAction {
                event_id: event.event_id.clone(),
            }
        })?;
        let posture = posture_for_action(action);

        if posture.posture != GwsEnforcementPosture::ApprovalHoldPreview {
            return Err(ApprovalPathError::UnsupportedPosture {
                event_id: event.event_id.clone(),
                action,
                posture: posture.posture,
            });
        }

        if decision.decision != PolicyDecisionKind::RequireApproval {
            return Err(ApprovalPathError::UnexpectedPolicyDecision {
                event_id: event.event_id.clone(),
                action,
                decision: decision.decision,
            });
        }

        let approval_request =
            approval_request.ok_or_else(|| ApprovalPathError::MissingApprovalRequest {
                event_id: event.event_id.clone(),
            })?;

        Ok(EnforcementOutcome::held_for_approval(
            EnforcementScope::Gws,
            event,
            decision,
            approval_request,
        ))
    }

    pub fn summary(&self) -> String {
        let semantic_actions = self
            .semantic_actions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "semantic_actions={} input_fields={} stages={} directive={}",
            semantic_actions,
            self.input_fields.join(","),
            self.stages.join("->"),
            self.directive,
        )
    }
}

fn semantic_action_from_event(event: &EventEnvelope) -> Option<GwsActionKind> {
    event
        .action
        .attributes
        .get("semantic_action_label")
        .and_then(Value::as_str)
        .and_then(GwsActionKind::from_label)
        .or_else(|| {
            event
                .action
                .verb
                .as_deref()
                .and_then(GwsActionKind::from_label)
        })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApprovalPathError {
    #[error("gws approval path requires semantic_action_label for event `{event_id}`")]
    MissingSemanticAction { event_id: String },
    #[error(
        "gws approval path only supports approval_hold_preview actions; event `{event_id}` action `{action}` had posture `{posture}`"
    )]
    UnsupportedPosture {
        event_id: String,
        action: GwsActionKind,
        posture: GwsEnforcementPosture,
    },
    #[error(
        "gws approval path expected require_approval for event `{event_id}` action `{action}`, got `{decision:?}`"
    )]
    UnexpectedPolicyDecision {
        event_id: String,
        action: GwsActionKind,
        decision: PolicyDecisionKind,
    },
    #[error("gws approval path requires an approval request for event `{event_id}`")]
    MissingApprovalRequest { event_id: String },
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        ApprovalRequest, ApprovalStatus, EventEnvelope, PolicyDecision, PolicyDecisionKind,
        ResultStatus, SessionRecord,
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, apply_decision_to_event,
        approval_request_from_decision,
    };

    use super::{ApprovalPathError, ApprovalPathPlan};
    use crate::poc::{
        enforcement::contract::{EnforcementDirective, EnforcementScope, EnforcementStatus},
        gws::{
            ApiNetworkGwsPocPlan,
            contract::{ApiRequestObservation, GwsActionKind, NetworkRequestObservation},
            posture::approval_hold_actions,
        },
    };

    #[test]
    fn approval_path_plan_tracks_only_approval_hold_actions() {
        let plan = ApprovalPathPlan::default();

        assert_eq!(plan.semantic_actions, approval_hold_actions());
        assert_eq!(
            plan.semantic_actions,
            vec![
                GwsActionKind::DrivePermissionsUpdate,
                GwsActionKind::GmailUsersMessagesSend,
                GwsActionKind::DriveFilesGetMedia,
            ]
        );
        assert_eq!(plan.directive, EnforcementDirective::Hold);
        assert_eq!(
            plan.input_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "semantic_action_label",
                "posture",
            ]
        );
    }

    #[test]
    fn approval_path_plan_holds_high_risk_gws_actions_until_approval() {
        let plan = ApprovalPathPlan::default();

        for action in approval_hold_actions() {
            let (event, decision, request) = require_approval_preview(action);
            let outcome = plan
                .apply(&event, &decision, Some(&request))
                .expect("approval path should create held outcome");

            assert_eq!(outcome.scope, EnforcementScope::Gws);
            assert_eq!(outcome.directive, EnforcementDirective::Hold);
            assert_eq!(outcome.status, EnforcementStatus::Held);
            assert_eq!(outcome.policy_decision, PolicyDecisionKind::RequireApproval);
            assert_eq!(outcome.action_verb.as_deref(), Some(action.label()));
            assert!(outcome.enforced);
            assert_eq!(
                outcome.approval_id.as_deref(),
                Some(request.approval_id.as_str())
            );
            assert_eq!(outcome.expires_at, request.expires_at);
        }
    }

    #[test]
    fn approval_path_plan_rejects_observe_only_admin_activity_listing() {
        let plan = ApprovalPathPlan::default();
        let (event, decision) = allow_preview(GwsActionKind::AdminReportsActivitiesList);

        let error = plan
            .apply(&event, &decision, None)
            .expect_err("admin listing should not enter approval-hold path");

        assert_eq!(
            error,
            ApprovalPathError::UnsupportedPosture {
                event_id: event.event_id.clone(),
                action: GwsActionKind::AdminReportsActivitiesList,
                posture: crate::poc::gws::posture::GwsEnforcementPosture::ObserveOnlyAllowPreview,
            }
        );
    }

    #[test]
    fn approval_path_plan_requires_approval_request() {
        let plan = ApprovalPathPlan::default();
        let (event, decision, _) = require_approval_preview(GwsActionKind::DrivePermissionsUpdate);

        let error = plan
            .apply(&event, &decision, None)
            .expect_err("approval path should require approval request");

        assert_eq!(
            error,
            ApprovalPathError::MissingApprovalRequest {
                event_id: event.event_id.clone(),
            }
        );
    }

    #[test]
    fn approval_path_plan_rejects_non_require_approval_decisions_for_hold_preview_actions() {
        let plan = ApprovalPathPlan::default();
        let (event, _, request) = require_approval_preview(GwsActionKind::DriveFilesGetMedia);
        let allow_decision = PolicyDecision {
            decision: PolicyDecisionKind::Allow,
            rule_id: Some("gws.drive.files_get_media.allowed".to_owned()),
            severity: None,
            reason: Some("drive file media download unexpectedly allowed".to_owned()),
            approval: None,
            tags: vec!["gws".to_owned(), "drive".to_owned(), "allow".to_owned()],
        };

        let error = plan
            .apply(&event, &allow_decision, Some(&request))
            .expect_err("hold preview should reject non-require_approval decisions");

        assert_eq!(
            error,
            ApprovalPathError::UnexpectedPolicyDecision {
                event_id: event.event_id.clone(),
                action: GwsActionKind::DriveFilesGetMedia,
                decision: PolicyDecisionKind::Allow,
            }
        );
    }

    #[test]
    fn approval_path_plan_requires_semantic_action_label_when_gws_identity_is_missing() {
        let plan = ApprovalPathPlan::default();
        let (mut event, decision, request) =
            require_approval_preview(GwsActionKind::GmailUsersMessagesSend);
        event.action.verb = None;
        event.action.attributes.remove("semantic_action_label");

        let error = plan
            .apply(&event, &decision, Some(&request))
            .expect_err("approval path should reject events without a semantic action label");

        assert_eq!(
            error,
            ApprovalPathError::MissingSemanticAction {
                event_id: event.event_id.clone(),
            }
        );
    }

    #[test]
    fn approval_path_summary_mentions_all_enforcement_path_stages() {
        let summary = ApprovalPathPlan::default().summary();

        assert!(summary.contains(
            "semantic_actions=drive.permissions.update,gmail.users.messages.send,drive.files.get_media"
        ));
        assert!(summary.contains("input_fields=normalized_event,policy_decision,approval_request,semantic_action_label,posture"));
        assert!(summary.contains("stages=accept->verify_posture->hold_projection"));
        assert!(summary.contains("directive=hold"));
    }

    fn require_approval_preview(
        action: GwsActionKind,
    ) -> (EventEnvelope, PolicyDecision, ApprovalRequest) {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_approval_path");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let classified = match action {
            GwsActionKind::DrivePermissionsUpdate => plan
                .classify
                .classify_action(&plan.session_linkage.link_api_observation(
                    &ApiRequestObservation::preview_drive_permissions_update(),
                    &session,
                ))
                .expect("drive permissions update should classify"),
            GwsActionKind::DriveFilesGetMedia => plan
                .classify
                .classify_action(&plan.session_linkage.link_network_observation(
                    &NetworkRequestObservation::preview_drive_files_get_media(),
                    &session,
                ))
                .expect("drive files get_media should classify"),
            GwsActionKind::GmailUsersMessagesSend => plan
                .classify
                .classify_action(&plan.session_linkage.link_api_observation(
                    &ApiRequestObservation::preview_gmail_users_messages_send(),
                    &session,
                ))
                .expect("gmail send should classify"),
            GwsActionKind::AdminReportsActivitiesList => {
                panic!("admin reports activities list is not approval-gated")
            }
        };
        let event = plan
            .evaluate
            .normalize_classified_action(&classified, &session);
        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(&event))
            .expect("gws preview policy should evaluate");
        let enriched = apply_decision_to_event(&event, &decision);
        let request = approval_request_from_decision(&enriched, &decision)
            .expect("require_approval should create approval request");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(event.result.status, ResultStatus::Observed);

        (event, decision, request)
    }

    fn allow_preview(action: GwsActionKind) -> (EventEnvelope, PolicyDecision) {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_approval_path_allow");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let classified = match action {
            GwsActionKind::AdminReportsActivitiesList => plan
                .classify
                .classify_action(&plan.session_linkage.link_api_observation(
                    &ApiRequestObservation::preview_admin_reports_activities_list(),
                    &session,
                ))
                .expect("admin reports activities list should classify"),
            _ => panic!("allow_preview only supports admin reports activities list"),
        };
        let event = plan
            .evaluate
            .normalize_classified_action(&classified, &session);
        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(&event))
            .expect("gws preview policy should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);

        (event, decision)
    }
}
