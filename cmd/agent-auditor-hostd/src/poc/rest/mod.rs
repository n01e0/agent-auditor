pub mod contract;
pub mod normalize;
pub mod persist;
pub mod policy;
pub mod record;

use self::{normalize::NormalizePlan, policy::PolicyPlan, record::RecordPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericRestOAuthGovernancePlan {
    pub normalize: NormalizePlan,
    pub policy: PolicyPlan,
    pub record: RecordPlan,
}

impl GenericRestOAuthGovernancePlan {
    pub fn bootstrap() -> Self {
        let normalize = NormalizePlan::default();
        let policy = PolicyPlan::from_contract_boundary(normalize.handoff());
        let record = RecordPlan::from_policy_boundary(policy.handoff());

        Self {
            normalize,
            policy,
            record,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, ApprovalStatus, CollectorKind, EventEnvelope,
        EventType, JsonMap, ResultInfo, ResultStatus, SessionRef, SourceInfo,
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, approval_request_from_decision,
    };
    use serde_json::json;

    use super::GenericRestOAuthGovernancePlan;
    use crate::poc::rest::persist::GenericRestPocStore;

    #[test]
    fn bootstrap_plan_keeps_normalize_policy_and_record_responsibilities_separate() {
        let plan = GenericRestOAuthGovernancePlan::bootstrap();

        assert!(
            plan.normalize
                .responsibilities
                .iter()
                .any(|item| item.contains("provider-neutral REST / OAuth governance contract"))
        );
        assert!(
            plan.normalize
                .responsibilities
                .iter()
                .all(|item| !item.contains("append redaction-safe generic REST audit records"))
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
                .all(|item| !item.contains("append-only storage"))
        );

        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("append redaction-safe generic REST audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_provider_contract_and_metadata_fields_into_generic_rest() {
        let plan = GenericRestOAuthGovernancePlan::bootstrap();

        assert_eq!(plan.normalize.providers, vec!["gws", "github"]);
        assert_eq!(
            plan.normalize.upstream_contract_fields,
            vec!["provider_id", "action_key", "target_hint"]
        );
        assert_eq!(
            plan.normalize.upstream_metadata_fields,
            vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ]
        );
        assert_eq!(
            plan.normalize.generic_contract_fields,
            vec![
                "provider_id",
                "action_key",
                "target_hint",
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ]
        );
        assert_eq!(plan.normalize.providers, plan.policy.providers);
        assert_eq!(plan.policy.providers, plan.record.providers);
        assert_eq!(
            plan.policy.input_fields,
            plan.normalize.generic_contract_fields
        );
        assert_eq!(plan.policy.input_fields, plan.policy.handoff().input_fields);
        assert_eq!(plan.policy.decision_fields, plan.record.input_fields);
        assert_eq!(
            plan.record.record_fields,
            plan.record.handoff().record_fields
        );
    }

    #[test]
    fn bootstrap_plan_preserves_generic_rest_redaction_guardrails() {
        let plan = GenericRestOAuthGovernancePlan::bootstrap();

        assert_eq!(
            plan.normalize.provider_input().redaction_contract,
            "generic REST / OAuth seams carry route templates, authority labels, query classes, shared action identity, target hints, and docs-backed auth/risk descriptors only; raw request bodies, response bodies, message text, file bytes, token values, signed URLs, and full query strings must not cross the seam"
        );
        assert_eq!(
            plan.normalize.provider_input().redaction_contract,
            plan.normalize.handoff().redaction_contract
        );
        assert_eq!(
            plan.normalize.handoff().redaction_contract,
            plan.policy.handoff().redaction_contract
        );
        assert_eq!(
            plan.policy.handoff().redaction_contract,
            plan.record.redaction_contract
        );
    }

    #[test]
    fn generic_rest_pipeline_reflects_and_persists_allow_hold_and_deny_records() {
        let plan = GenericRestOAuthGovernancePlan::bootstrap();
        let store = GenericRestPocStore::fresh(unique_test_root()).expect("store should init");

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
            .record
            .reflect_allow(&allow_observed, &allow_decision)
            .expect("allow reflection should succeed");
        store
            .append_audit_record(&allow_enriched)
            .expect("allow audit record should append");
        assert_eq!(allow_enriched.result.status, ResultStatus::Allowed);
        assert!(allow_enriched.enforcement.is_none());

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
        .expect("hold decision should create approval request");
        let (hold_enriched, hold_request) = plan
            .record
            .reflect_hold(&hold_observed, &hold_decision, &hold_request)
            .expect("hold reflection should succeed");
        store
            .append_audit_record(&hold_enriched)
            .expect("hold audit record should append");
        store
            .append_approval_request(&hold_request)
            .expect("hold approval request should append");
        assert_eq!(hold_enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(hold_request.status, ApprovalStatus::Pending);
        assert_eq!(
            hold_enriched
                .enforcement
                .as_ref()
                .and_then(|info| info.approval_id.as_deref()),
            Some(hold_request.approval_id.as_str())
        );

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
            .record
            .reflect_deny(&deny_observed, &deny_decision)
            .expect("deny reflection should succeed");
        store
            .append_audit_record(&deny_enriched)
            .expect("deny audit record should append");
        assert_eq!(deny_enriched.result.status, ResultStatus::Denied);
        assert_eq!(
            deny_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Denied)
        );

        assert_eq!(
            store
                .latest_audit_record()
                .expect("latest audit record should read"),
            Some(deny_enriched)
        );
        assert_eq!(
            store
                .latest_approval_request()
                .expect("latest approval request should read"),
            Some(hold_request)
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
                session_id: "sess_generic_rest_mod".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("ws_generic_rest_mod".to_owned()),
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
                reason: Some("observed by hostd generic REST mod fixture".to_owned()),
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

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        std::env::temp_dir().join(format!("agent-auditor-hostd-generic-rest-mod-test-{nonce}"))
    }
}
