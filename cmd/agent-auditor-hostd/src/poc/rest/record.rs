use agenta_core::{
    ApprovalRequest, EnforcementDirective, EnforcementInfo, EnforcementStatus, EventEnvelope,
    PolicyDecision, PolicyDecisionKind,
};
use agenta_policy::{
    apply_decision_to_event, apply_enforcement_to_approval_request, apply_enforcement_to_event,
};
use thiserror::Error;

use super::contract::{PolicyBoundary, RecordBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl RecordPlan {
    pub fn from_policy_boundary(policy: PolicyBoundary) -> Self {
        Self {
            providers: policy.providers,
            input_fields: policy.decision_fields,
            record_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ],
            responsibilities: vec![
                "append redaction-safe generic REST audit records and approval requests without replaying provider-specific taxonomy or metadata joins",
                "reflect allow, hold, and deny outcomes into append-only storage and later publish fanout using the checked-in generic REST contract",
                "avoid storing raw request or response payloads, token values, signed URLs, full query strings, message bodies, or file bytes",
            ],
            stages: vec!["persist", "publish"],
            sinks: vec!["structured_log", "audit_store", "approval_store"],
            redaction_contract: policy.redaction_contract,
        }
    }

    pub fn reflect_allow(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Result<EventEnvelope, RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::Allow {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::Allow,
                actual: decision.decision,
            });
        }

        Ok(apply_decision_to_event(event, decision))
    }

    pub fn reflect_hold(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        approval_request: &ApprovalRequest,
    ) -> Result<(EventEnvelope, ApprovalRequest), RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::RequireApproval {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::RequireApproval,
                actual: decision.decision,
            });
        }

        let decision_applied = apply_decision_to_event(event, decision);
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Hold,
            status: EnforcementStatus::Held,
            status_reason: decision.reason.clone(),
            enforced: true,
            coverage_gap: None,
            approval_id: Some(approval_request.approval_id.clone()),
            expires_at: approval_request.expires_at,
        };

        Ok((
            apply_enforcement_to_event(&decision_applied, &enforcement),
            apply_enforcement_to_approval_request(approval_request, &enforcement),
        ))
    }

    pub fn reflect_deny(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Result<EventEnvelope, RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::Deny {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::Deny,
                actual: decision.decision,
            });
        }

        let decision_applied = apply_decision_to_event(event, decision);
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Deny,
            status: EnforcementStatus::Denied,
            status_reason: decision.reason.clone(),
            enforced: true,
            coverage_gap: None,
            approval_id: None,
            expires_at: None,
        };

        Ok(apply_enforcement_to_event(&decision_applied, &enforcement))
    }

    pub fn handoff(&self) -> RecordBoundary {
        RecordBoundary {
            providers: self.providers.clone(),
            input_fields: self.input_fields.clone(),
            record_fields: self.record_fields.clone(),
            redaction_contract: self.redaction_contract,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} input_fields={} record_fields={} stages={} sinks={}",
            self.providers.join(","),
            self.input_fields.join(","),
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordReflectionError {
    #[error(
        "generic REST record reflection expected `{expected:?}` for event `{event_id}`, got `{actual:?}`"
    )]
    UnexpectedDecision {
        event_id: String,
        expected: PolicyDecisionKind,
        actual: PolicyDecisionKind,
    },
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, ApprovalStatus, CollectorKind, EventEnvelope,
        EventType, JsonMap, PolicyDecisionKind, ResultInfo, ResultStatus, SessionRef, SourceInfo,
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, approval_request_from_decision,
    };
    use serde_json::json;

    use super::{RecordPlan, RecordReflectionError};
    use crate::poc::rest::{normalize::NormalizePlan, policy::PolicyPlan};

    #[test]
    fn record_plan_preserves_redaction_contract_and_storage_sinks() {
        let normalize = NormalizePlan::default();
        let policy = PolicyPlan::from_contract_boundary(normalize.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());

        assert_eq!(plan.stages, vec!["persist", "publish"]);
        assert_eq!(
            plan.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
        assert_eq!(
            plan.redaction_contract,
            "generic REST / OAuth seams carry route templates, authority labels, query classes, shared action identity, target hints, and docs-backed auth/risk descriptors only; raw request bodies, response bodies, message text, file bytes, token values, signed URLs, and full query strings must not cross the seam"
        );
    }

    #[test]
    fn record_plan_reflects_allow_hold_and_deny_without_re_evaluating_policy() {
        let normalize = NormalizePlan::default();
        let policy = PolicyPlan::from_contract_boundary(normalize.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());

        let allow_observed = fixture_event(GenericRestFixture {
            event_id: "evt_rest_admin_reports_allow",
            provider_id: "gws",
            action_key: "admin.reports.activities.list",
            target: "admin.reports/users/all/applications/drive",
            event_type: EventType::GwsAction,
            action_class: ActionClass::Gws,
            semantic_surface: "gws.admin",
            method: "GET",
            host: "admin.googleapis.com",
            path_template: "/admin/reports/v1/activity/users/all/applications/{applicationName}",
            query_class: "filter",
            primary_scope: "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            documented_scopes: &["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
            side_effect: "lists admin activity reports without mutating tenant state",
            privilege_class: "admin_read",
        });
        let allow_decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&PolicyInput::from_event(&allow_observed))
            .expect("allow decision should evaluate");
        let allow_enriched = plan
            .reflect_allow(&allow_observed, &allow_decision)
            .expect("allow reflection should succeed");

        let hold_observed = fixture_event(GenericRestFixture {
            event_id: "evt_rest_gmail_send_hold",
            provider_id: "gws",
            action_key: "gmail.users.messages.send",
            target: "gmail.users/me",
            event_type: EventType::GwsAction,
            action_class: ActionClass::Gws,
            semantic_surface: "gws.gmail",
            method: "POST",
            host: "gmail.googleapis.com",
            path_template: "/gmail/v1/users/{userId}/messages/send",
            query_class: "action_arguments",
            primary_scope: "https://www.googleapis.com/auth/gmail.send",
            documented_scopes: &["https://www.googleapis.com/auth/gmail.send"],
            side_effect: "sends a Gmail message to one or more recipients",
            privilege_class: "outbound_send",
        });
        let hold_decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&PolicyInput::from_event(&hold_observed))
            .expect("hold decision should evaluate");
        let hold_request = approval_request_from_decision(
            &agenta_policy::apply_decision_to_event(&hold_observed, &hold_decision),
            &hold_decision,
        )
        .expect("hold decision should yield approval request");
        let (hold_enriched, hold_request) = plan
            .reflect_hold(&hold_observed, &hold_decision, &hold_request)
            .expect("hold reflection should succeed");

        let deny_observed = fixture_event(GenericRestFixture {
            event_id: "evt_rest_github_secret_deny",
            provider_id: "github",
            action_key: "actions.secrets.create_or_update",
            target: "repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
            event_type: EventType::GithubAction,
            action_class: ActionClass::Github,
            semantic_surface: "github.actions",
            method: "PUT",
            host: "api.github.com",
            path_template: "/repos/{owner}/{repo}/actions/secrets/{secret_name}",
            query_class: "none",
            primary_scope: "github.permission:secrets:write",
            documented_scopes: &["github.permission:secrets:write", "github.oauth:repo"],
            side_effect: "creates or updates an encrypted repository Actions secret",
            privilege_class: "admin_write",
        });
        let deny_decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&PolicyInput::from_event(&deny_observed))
            .expect("deny decision should evaluate");
        let deny_enriched = plan
            .reflect_deny(&deny_observed, &deny_decision)
            .expect("deny reflection should succeed");

        assert_eq!(allow_enriched.result.status, ResultStatus::Allowed);
        assert!(allow_enriched.enforcement.is_none());
        assert_eq!(hold_enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            hold_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Held)
        );
        assert_eq!(hold_request.status, ApprovalStatus::Pending);
        assert_eq!(
            hold_request.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Held)
        );
        assert_eq!(deny_enriched.result.status, ResultStatus::Denied);
        assert_eq!(
            deny_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Denied)
        );
    }

    #[test]
    fn record_plan_rejects_unexpected_decision_kind() {
        let normalize = NormalizePlan::default();
        let policy = PolicyPlan::from_contract_boundary(normalize.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());
        let event = fixture_event(GenericRestFixture {
            event_id: "evt_rest_reject_wrong_decision",
            provider_id: "gws",
            action_key: "admin.reports.activities.list",
            target: "admin.reports/users/all/applications/drive",
            event_type: EventType::GwsAction,
            action_class: ActionClass::Gws,
            semantic_surface: "gws.admin",
            method: "GET",
            host: "admin.googleapis.com",
            path_template: "/admin/reports/v1/activity/users/all/applications/{applicationName}",
            query_class: "filter",
            primary_scope: "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            documented_scopes: &["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
            side_effect: "lists admin activity reports without mutating tenant state",
            privilege_class: "admin_read",
        });
        let deny_decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&PolicyInput::from_event(&fixture_event(
                GenericRestFixture {
                    event_id: "evt_rest_github_secret_deny_for_reject",
                    provider_id: "github",
                    action_key: "actions.secrets.create_or_update",
                    target: "repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
                    event_type: EventType::GithubAction,
                    action_class: ActionClass::Github,
                    semantic_surface: "github.actions",
                    method: "PUT",
                    host: "api.github.com",
                    path_template: "/repos/{owner}/{repo}/actions/secrets/{secret_name}",
                    query_class: "none",
                    primary_scope: "github.permission:secrets:write",
                    documented_scopes: &["github.permission:secrets:write", "github.oauth:repo"],
                    side_effect: "creates or updates an encrypted repository Actions secret",
                    privilege_class: "admin_write",
                },
            )))
            .expect("deny decision should evaluate");

        assert_eq!(
            plan.reflect_allow(&event, &deny_decision),
            Err(RecordReflectionError::UnexpectedDecision {
                event_id: "evt_rest_reject_wrong_decision".to_owned(),
                expected: PolicyDecisionKind::Allow,
                actual: PolicyDecisionKind::Deny,
            })
        );
    }

    struct GenericRestFixture<'a> {
        event_id: &'a str,
        provider_id: &'a str,
        action_key: &'a str,
        target: &'a str,
        event_type: EventType,
        action_class: ActionClass,
        semantic_surface: &'a str,
        method: &'a str,
        host: &'a str,
        path_template: &'a str,
        query_class: &'a str,
        primary_scope: &'a str,
        documented_scopes: &'a [&'a str],
        side_effect: &'a str,
        privilege_class: &'a str,
    }

    fn fixture_event(fixture: GenericRestFixture<'_>) -> EventEnvelope {
        let GenericRestFixture {
            event_id,
            provider_id,
            action_key,
            target,
            event_type,
            action_class,
            semantic_surface,
            method,
            host,
            path_template,
            query_class,
            primary_scope,
            documented_scopes,
            side_effect,
            privilege_class,
        } = fixture;

        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!("api_observation"));
        attributes.insert("request_id".to_owned(), json!(format!("req_{event_id}")));
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("semantic_surface".to_owned(), json!(semantic_surface));
        attributes.insert("provider_id".to_owned(), json!(provider_id));
        attributes.insert("action_key".to_owned(), json!(action_key));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!(format!("{provider_id}:{action_key}")),
        );
        attributes.insert("target_hint".to_owned(), json!(target));
        attributes.insert("method".to_owned(), json!(method));
        attributes.insert("host".to_owned(), json!(host));
        attributes.insert("path_template".to_owned(), json!(path_template));
        attributes.insert("query_class".to_owned(), json!(query_class));
        attributes.insert(
            "oauth_scope_labels".to_owned(),
            json!({
                "primary": primary_scope,
                "documented": documented_scopes,
            }),
        );
        attributes.insert("side_effect".to_owned(), json!(side_effect));
        attributes.insert("privilege_class".to_owned(), json!(privilege_class));
        attributes.insert("content_retained".to_owned(), json!(false));

        EventEnvelope::new(
            event_id,
            event_type,
            SessionRef {
                session_id: "sess_generic_rest_record".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("ws_generic_rest_record".to_owned()),
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            Action {
                class: action_class,
                verb: Some(action_key.to_owned()),
                target: Some(target.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd generic REST record fixture".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        )
    }
}
