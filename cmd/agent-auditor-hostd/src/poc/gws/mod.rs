pub mod approval;
pub mod classify;
pub mod contract;
pub mod evaluate;
pub mod persist;
pub mod posture;
pub mod record;
pub mod session_linkage;

use agenta_core::provider::{
    CanonicalResource, OAuthScope, OAuthScopeSet, PrivilegeClass, ProviderActionMetadata,
    ProviderMetadataCatalog, ProviderMethod, SideEffect,
};

use self::{
    approval::ApprovalPathPlan, classify::ClassifyPlan, contract::GwsActionKind,
    evaluate::EvaluatePlan, record::RecordPlan, session_linkage::SessionLinkagePlan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiNetworkGwsPocPlan {
    pub session_linkage: SessionLinkagePlan,
    pub classify: ClassifyPlan,
    pub evaluate: EvaluatePlan,
    pub approval: ApprovalPathPlan,
    pub record: RecordPlan,
}

impl ApiNetworkGwsPocPlan {
    pub fn bootstrap() -> Self {
        let session_linkage = SessionLinkagePlan::default();
        let classify = ClassifyPlan::from_session_linkage_boundary(session_linkage.handoff());
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let approval = ApprovalPathPlan::default();
        let record = RecordPlan::from_evaluation_boundary(evaluate.handoff());

        Self {
            session_linkage,
            classify,
            evaluate,
            approval,
            record,
        }
    }
}

pub fn preview_provider_metadata_catalog() -> ProviderMetadataCatalog {
    ProviderMetadataCatalog::new(vec![
        ProviderActionMetadata::new(
            GwsActionKind::DrivePermissionsUpdate.provider_action_id(),
            ProviderMethod::Patch,
            CanonicalResource::new("drive.files/{fileId}/permissions/{permissionId}")
                .expect("preview canonical resource should be valid"),
            SideEffect::new(
                "updates a Drive permission and may transfer ownership when transferOwnership=true",
            )
            .expect("preview side effect should be valid"),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/drive.file")
                    .expect("preview scope should be valid"),
                vec![
                    OAuthScope::new("https://www.googleapis.com/auth/drive")
                        .expect("preview scope should be valid"),
                    OAuthScope::new("https://www.googleapis.com/auth/drive.file")
                        .expect("preview scope should be valid"),
                ],
            ),
            PrivilegeClass::SharingWrite,
        ),
        ProviderActionMetadata::new(
            GwsActionKind::DriveFilesGetMedia.provider_action_id(),
            ProviderMethod::Get,
            CanonicalResource::new("drive.files/{fileId}/content")
                .expect("preview canonical resource should be valid"),
            SideEffect::new("returns Drive file content bytes")
                .expect("preview side effect should be valid"),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/drive.readonly")
                    .expect("preview scope should be valid"),
                vec![
                    OAuthScope::new("https://www.googleapis.com/auth/drive")
                        .expect("preview scope should be valid"),
                    OAuthScope::new("https://www.googleapis.com/auth/drive.readonly")
                        .expect("preview scope should be valid"),
                ],
            ),
            PrivilegeClass::ContentRead,
        ),
        ProviderActionMetadata::new(
            GwsActionKind::GmailUsersMessagesSend.provider_action_id(),
            ProviderMethod::Post,
            CanonicalResource::new("gmail.users/{userId}/messages:send")
                .expect("preview canonical resource should be valid"),
            SideEffect::new("sends the specified message to the listed recipients")
                .expect("preview side effect should be valid"),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/gmail.send")
                    .expect("preview scope should be valid"),
                vec![
                    OAuthScope::new("https://www.googleapis.com/auth/gmail.send")
                        .expect("preview scope should be valid"),
                ],
            ),
            PrivilegeClass::OutboundSend,
        ),
        ProviderActionMetadata::new(
            GwsActionKind::AdminReportsActivitiesList.provider_action_id(),
            ProviderMethod::Get,
            CanonicalResource::new("admin.reports.activities/{applicationName}")
                .expect("preview canonical resource should be valid"),
            SideEffect::new("returns Admin Reports activity entries for the requested application")
                .expect("preview side effect should be valid"),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/admin.reports.audit.readonly")
                    .expect("preview scope should be valid"),
                vec![
                    OAuthScope::new("https://www.googleapis.com/auth/admin.reports.audit.readonly")
                        .expect("preview scope should be valid"),
                ],
            ),
            PrivilegeClass::AdminRead,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        ActionClass, ApprovalScope, ApprovalStatus, EventType, PolicyDecision, PolicyDecisionKind,
        ResultStatus, SessionRecord, Severity,
        provider::{PrivilegeClass, ProviderMethod},
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, apply_decision_to_event,
        apply_enforcement_to_approval_request, apply_enforcement_to_event,
        approval_request_from_decision,
    };

    use super::{ApiNetworkGwsPocPlan, preview_provider_metadata_catalog};
    use crate::poc::{
        enforcement::contract::{EnforcementDirective, EnforcementOutcome, EnforcementScope},
        gws::{
            contract::{
                ApiRequestObservation, GwsSemanticSurface, GwsSignalSource,
                NetworkRequestObservation,
            },
            persist::GwsPocStore,
        },
    };

    #[test]
    fn bootstrap_plan_keeps_gws_phase_responsibilities_separate() {
        let plan = ApiNetworkGwsPocPlan::bootstrap();

        assert!(
            plan.session_linkage
                .responsibilities
                .iter()
                .any(|item| item.contains("same session identity"))
        );
        assert!(
            plan.session_linkage
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .any(|item| item.contains("semantic action candidates"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .any(|item| item.contains("drive.permissions.update"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .all(|item| !item.contains("same session identity used by runtime hostd events"))
        );
        assert!(
            plan.evaluate
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-core"))
        );
        assert!(
            plan.evaluate
                .responsibilities
                .iter()
                .all(|item| !item.contains("request adapters and egress observation"))
        );
        assert!(
            plan.approval
                .responsibilities
                .iter()
                .any(|item| item.contains("minimal require_approval path"))
        );
        assert!(
            plan.approval
                .responsibilities
                .iter()
                .all(|item| !item.contains("structured_log"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_gws_contracts_across_the_pipeline() {
        let plan = ApiNetworkGwsPocPlan::bootstrap();

        assert_eq!(
            plan.session_linkage.sources,
            vec![
                GwsSignalSource::ApiObservation,
                GwsSignalSource::NetworkObservation,
            ]
        );
        assert_eq!(plan.session_linkage.sources, plan.classify.sources);
        assert_eq!(plan.classify.sources, plan.evaluate.sources);
        assert_eq!(plan.evaluate.sources, plan.record.sources);
        assert_eq!(
            plan.session_linkage.semantic_surfaces,
            vec![
                GwsSemanticSurface::GoogleWorkspace,
                GwsSemanticSurface::GoogleWorkspaceDrive,
                GwsSemanticSurface::GoogleWorkspaceGmail,
                GwsSemanticSurface::GoogleWorkspaceAdmin,
            ]
        );
        assert_eq!(
            plan.session_linkage.semantic_surfaces,
            plan.classify.semantic_surfaces
        );
        assert_eq!(
            plan.classify.semantic_surfaces,
            plan.evaluate.semantic_surfaces
        );
        assert_eq!(
            plan.evaluate.semantic_surfaces,
            plan.record.semantic_surfaces
        );
        assert_eq!(
            plan.classify.classification_fields,
            vec![
                "semantic_surface",
                "provider_id",
                "action_key",
                "semantic_action_label",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ]
        );
        assert_eq!(
            plan.classify.semantic_actions,
            vec![
                crate::poc::gws::contract::GwsActionKind::DrivePermissionsUpdate,
                crate::poc::gws::contract::GwsActionKind::DriveFilesGetMedia,
                crate::poc::gws::contract::GwsActionKind::GmailUsersMessagesSend,
                crate::poc::gws::contract::GwsActionKind::AdminReportsActivitiesList,
            ]
        );
        assert_eq!(
            plan.approval.semantic_actions,
            vec![
                crate::poc::gws::contract::GwsActionKind::DrivePermissionsUpdate,
                crate::poc::gws::contract::GwsActionKind::GmailUsersMessagesSend,
                crate::poc::gws::contract::GwsActionKind::DriveFilesGetMedia,
            ]
        );
        assert_eq!(
            plan.record.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
        assert_eq!(
            plan.record.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
        );
    }

    #[test]
    fn bootstrap_plan_normalizes_preview_gws_action_into_agenta_core() {
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_bootstrap");
        let classified = plan
            .classify
            .classify_action(
                &plan
                    .session_linkage
                    .preview_session_linked_api_action(&session),
            )
            .expect("preview api action should classify");

        let normalized = plan
            .evaluate
            .normalize_classified_action(&classified, &session);

        assert_eq!(normalized.event_type, EventType::GwsAction);
        assert_eq!(normalized.action.class, ActionClass::Gws);
        assert_eq!(
            normalized.action.verb.as_deref(),
            Some("drive.permissions.update")
        );
        assert_eq!(
            normalized.action.target.as_deref(),
            Some("drive.files/abc123/permissions/perm456")
        );
        assert_eq!(
            normalized.action.attributes.get("provider_id"),
            Some(&serde_json::json!("gws"))
        );
        assert_eq!(
            normalized.action.attributes.get("action_key"),
            Some(&serde_json::json!("drive.permissions.update"))
        );
    }

    #[test]
    fn gws_pipeline_can_evaluate_policy_for_admin_activity_listing() {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_policy_allow");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_admin_reports_activities_list(),
                &session,
            ))
            .expect("admin reports list should classify");
        let event = plan
            .evaluate
            .normalize_classified_action(&classified, &session);
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&input)
            .expect("gws rego should evaluate");
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("gws.admin.reports.activities_list.allow")
        );
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(event.result.status, ResultStatus::Observed);
        assert_eq!(enriched.result.status, ResultStatus::Allowed);
        assert!(approval_request_from_decision(&enriched, &decision).is_none());
    }

    #[test]
    fn gws_pipeline_can_require_approval_for_drive_permission_updates() {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_policy_drive");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_drive_permissions_update(),
                &session,
            ))
            .expect("drive permissions update should classify");
        let event = plan
            .evaluate
            .normalize_classified_action(&classified, &session);
        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(&event))
            .expect("gws rego should evaluate");
        let enriched = apply_decision_to_event(&event, &decision);
        let approval_request = approval_request_from_decision(&enriched, &decision)
            .expect("require_approval should yield approval request");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("gws.drive.permissions_update.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(approval_request.status, ApprovalStatus::Pending);
        assert_eq!(
            approval_request.policy.scope,
            Some(ApprovalScope::SingleAction)
        );
        assert_eq!(approval_request.policy.ttl_seconds, Some(1800));
        assert_eq!(
            approval_request.policy.reviewer_hint.as_deref(),
            Some("security-oncall")
        );
    }

    #[test]
    fn gws_pipeline_can_require_approval_for_network_drive_downloads_and_gmail_send() {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_policy_network");
        let plan = ApiNetworkGwsPocPlan::bootstrap();

        let drive_download = plan
            .classify
            .classify_action(&plan.session_linkage.link_network_observation(
                &NetworkRequestObservation::preview_drive_files_get_media(),
                &session,
            ))
            .expect("drive download should classify");
        let gmail_send = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_gmail_users_messages_send(),
                &session,
            ))
            .expect("gmail send should classify");

        let drive_decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan
                    .evaluate
                    .normalize_classified_action(&drive_download, &session),
            ))
            .expect("gws drive download rego should evaluate");
        let gmail_decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan
                    .evaluate
                    .normalize_classified_action(&gmail_send, &session),
            ))
            .expect("gws gmail send rego should evaluate");

        assert_eq!(drive_decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            drive_decision.rule_id.as_deref(),
            Some("gws.drive.files_get_media.requires_approval")
        );
        assert_eq!(drive_decision.severity, Some(Severity::Medium));
        assert_eq!(gmail_decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            gmail_decision.rule_id.as_deref(),
            Some("gws.gmail.users_messages_send.requires_approval")
        );
        assert_eq!(gmail_decision.severity, Some(Severity::High));
    }

    #[test]
    fn gws_hold_reflects_into_event_approval_and_audit_records() {
        let allow_preview = preview_gws_policy_for_admin_activity_listing();
        let hold_preview = preview_gws_hold_for_drive_permissions_update();
        let store = GwsPocStore::fresh(unique_test_root()).expect("store should init");

        store
            .append_audit_record(&allow_preview.1)
            .expect("allow audit record should append");
        assert_eq!(
            store
                .latest_audit_record()
                .expect("allow audit record should read"),
            Some(allow_preview.1.clone())
        );
        assert_eq!(allow_preview.2.decision, PolicyDecisionKind::Allow);
        assert_eq!(allow_preview.1.result.status, ResultStatus::Allowed);
        assert!(allow_preview.3.is_none());

        store
            .append_audit_record(&hold_preview.1)
            .expect("hold audit record should append");
        store
            .append_approval_request(&hold_preview.3)
            .expect("hold approval request should append");

        assert_eq!(
            store
                .latest_audit_record()
                .expect("hold audit record should read"),
            Some(hold_preview.1.clone())
        );
        assert_eq!(
            store
                .latest_approval_request()
                .expect("hold approval request should read"),
            Some(hold_preview.3.clone())
        );
        assert_eq!(hold_preview.2.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(hold_preview.1.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(hold_preview.3.status, ApprovalStatus::Pending);
        assert_eq!(hold_preview.4.scope, EnforcementScope::Gws);
        assert_eq!(hold_preview.4.directive, EnforcementDirective::Hold);
        assert_eq!(
            hold_preview.4.status_reason,
            "Drive permission updates require approval"
        );
        assert_eq!(
            hold_preview
                .1
                .enforcement
                .as_ref()
                .and_then(|enforcement| enforcement.approval_id.as_deref()),
            Some(hold_preview.3.approval_id.as_str())
        );
        assert_eq!(
            hold_preview
                .3
                .enforcement
                .as_ref()
                .map(|enforcement| enforcement.status),
            Some(agenta_core::EnforcementStatus::Held)
        );
    }

    #[test]
    fn gws_all_supported_actions_round_trip_through_policy_and_records() {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_round_trip");
        let plan = ApiNetworkGwsPocPlan::bootstrap();

        let drive_permissions_update = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_drive_permissions_update(),
                &session,
            ))
            .expect("drive permissions update should classify");
        let drive_files_get_media = plan
            .classify
            .classify_action(&plan.session_linkage.link_network_observation(
                &NetworkRequestObservation::preview_drive_files_get_media(),
                &session,
            ))
            .expect("drive get_media should classify");
        let gmail_users_messages_send = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_gmail_users_messages_send(),
                &session,
            ))
            .expect("gmail send should classify");
        let admin_reports_activities_list = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_admin_reports_activities_list(),
                &session,
            ))
            .expect("admin reports list should classify");

        let drive_permissions_update_decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan
                    .evaluate
                    .normalize_classified_action(&drive_permissions_update, &session),
            ))
            .expect("drive permissions update policy should evaluate");
        let drive_files_get_media_decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan
                    .evaluate
                    .normalize_classified_action(&drive_files_get_media, &session),
            ))
            .expect("drive get_media policy should evaluate");
        let gmail_users_messages_send_decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan
                    .evaluate
                    .normalize_classified_action(&gmail_users_messages_send, &session),
            ))
            .expect("gmail send policy should evaluate");
        let admin_reports_activities_list_decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan
                    .evaluate
                    .normalize_classified_action(&admin_reports_activities_list, &session),
            ))
            .expect("admin reports list policy should evaluate");

        assert_eq!(
            drive_permissions_update_decision.decision,
            PolicyDecisionKind::RequireApproval
        );
        assert_eq!(
            drive_files_get_media_decision.decision,
            PolicyDecisionKind::RequireApproval
        );
        assert_eq!(
            gmail_users_messages_send_decision.decision,
            PolicyDecisionKind::RequireApproval
        );
        assert_eq!(
            admin_reports_activities_list_decision.decision,
            PolicyDecisionKind::Allow
        );
    }

    #[test]
    fn gws_provider_metadata_catalog_covers_all_preview_actions_for_policy_input() {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_provider_catalog");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let catalog = preview_provider_metadata_catalog();

        let previews = [
            (
                plan.classify
                    .classify_action(&plan.session_linkage.link_api_observation(
                        &ApiRequestObservation::preview_drive_permissions_update(),
                        &session,
                    ))
                    .expect("drive permissions update should classify"),
                ProviderMethod::Patch,
                PrivilegeClass::SharingWrite,
            ),
            (
                plan.classify
                    .classify_action(&plan.session_linkage.link_network_observation(
                        &NetworkRequestObservation::preview_drive_files_get_media(),
                        &session,
                    ))
                    .expect("drive files get_media should classify"),
                ProviderMethod::Get,
                PrivilegeClass::ContentRead,
            ),
            (
                plan.classify
                    .classify_action(&plan.session_linkage.link_api_observation(
                        &ApiRequestObservation::preview_gmail_users_messages_send(),
                        &session,
                    ))
                    .expect("gmail send should classify"),
                ProviderMethod::Post,
                PrivilegeClass::OutboundSend,
            ),
            (
                plan.classify
                    .classify_action(&plan.session_linkage.link_api_observation(
                        &ApiRequestObservation::preview_admin_reports_activities_list(),
                        &session,
                    ))
                    .expect("admin reports list should classify"),
                ProviderMethod::Get,
                PrivilegeClass::AdminRead,
            ),
        ];

        for (classified, expected_method, expected_privilege) in previews {
            let normalized = plan
                .evaluate
                .normalize_classified_action(&classified, &session);
            let provider_action = PolicyInput::from_event(&normalized)
                .provider_action
                .expect("normalized GWS event should derive shared provider action");
            let metadata = catalog
                .find(&provider_action.id())
                .expect("preview catalog should contain metadata for provider action");

            assert_eq!(metadata.provider_id(), &provider_action.provider_id);
            assert_eq!(metadata.action_key(), &provider_action.action_key);
            assert_eq!(metadata.method, expected_method);
            assert_eq!(metadata.privilege_class, expected_privilege);
        }
    }

    #[test]
    fn gws_deny_reflects_enforcement_into_event_and_audit_record() {
        let (observed, enriched, deny_decision, enforcement) = preview_gws_deny_for_gmail_send();
        let store = GwsPocStore::fresh(unique_test_root()).expect("store should init");

        store
            .append_audit_record(&enriched)
            .expect("deny audit record should append");

        assert_eq!(observed.result.status, ResultStatus::Observed);
        assert_eq!(enriched.result.status, ResultStatus::Denied);
        assert_eq!(enforcement.scope, EnforcementScope::Gws);
        assert_eq!(enforcement.directive, EnforcementDirective::Deny);
        assert_eq!(
            enforcement.status_reason,
            "Outbound Gmail send is denied by preview policy"
        );
        assert_eq!(
            enriched.result.reason.as_deref(),
            Some("Outbound Gmail send is denied by preview policy")
        );
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::Deny)
        );
        assert_eq!(
            enriched
                .policy
                .as_ref()
                .and_then(|policy| policy.rule_id.as_deref()),
            Some("gws.gmail.users_messages_send.denied")
        );
        assert_eq!(
            enriched
                .enforcement
                .as_ref()
                .map(|enforcement| enforcement.status),
            Some(agenta_core::EnforcementStatus::Denied)
        );
        assert!(approval_request_from_decision(&enriched, &deny_decision).is_none());
        assert_eq!(
            store
                .latest_audit_record()
                .expect("deny audit record should read"),
            Some(enriched)
        );
    }

    fn preview_gws_policy_for_admin_activity_listing() -> (
        agenta_core::EventEnvelope,
        agenta_core::EventEnvelope,
        PolicyDecision,
        Option<agenta_core::ApprovalRequest>,
    ) {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_policy_allow");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_admin_reports_activities_list(),
                &session,
            ))
            .expect("admin reports list should classify");
        let observed = plan
            .evaluate
            .normalize_classified_action(&classified, &session);
        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(&observed))
            .expect("gws rego should evaluate");
        let enriched = apply_decision_to_event(&observed, &decision);
        let approval_request = approval_request_from_decision(&enriched, &decision);

        (observed, enriched, decision, approval_request)
    }

    fn preview_gws_hold_for_drive_permissions_update() -> (
        agenta_core::EventEnvelope,
        agenta_core::EventEnvelope,
        PolicyDecision,
        agenta_core::ApprovalRequest,
        EnforcementOutcome,
    ) {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_policy_drive");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_drive_permissions_update(),
                &session,
            ))
            .expect("drive permissions update should classify");
        let observed = plan
            .evaluate
            .normalize_classified_action(&classified, &session);
        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(&observed))
            .expect("gws rego should evaluate");
        let decision_applied = apply_decision_to_event(&observed, &decision);
        let approval_request = approval_request_from_decision(&decision_applied, &decision)
            .expect("require approval should create approval request");
        let enforcement = plan
            .approval
            .apply(&decision_applied, &decision, Some(&approval_request))
            .expect("approval path should create held outcome");
        let enforcement_projection = enforcement.record_projection();
        let enriched = apply_enforcement_to_event(&decision_applied, &enforcement_projection);
        let approval_request =
            apply_enforcement_to_approval_request(&approval_request, &enforcement_projection);

        (observed, enriched, decision, approval_request, enforcement)
    }

    fn preview_gws_deny_for_gmail_send() -> (
        agenta_core::EventEnvelope,
        agenta_core::EventEnvelope,
        PolicyDecision,
        EnforcementOutcome,
    ) {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_policy_deny");
        let plan = ApiNetworkGwsPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_action(&plan.session_linkage.link_api_observation(
                &ApiRequestObservation::preview_gmail_users_messages_send(),
                &session,
            ))
            .expect("gmail send should classify");
        let observed = plan
            .evaluate
            .normalize_classified_action(&classified, &session);
        let deny_decision = PolicyDecision {
            decision: PolicyDecisionKind::Deny,
            rule_id: Some("gws.gmail.users_messages_send.denied".to_owned()),
            severity: Some(Severity::High),
            reason: Some("Outbound Gmail send is denied by preview policy".to_owned()),
            explanation: None,
            rationale: None,
            reviewer_hint: None,
            approval: None,
            tags: vec!["gws".to_owned(), "gmail".to_owned(), "deny".to_owned()],
        };
        let decision_applied = apply_decision_to_event(&observed, &deny_decision);
        let enforcement =
            EnforcementOutcome::denied(EnforcementScope::Gws, &decision_applied, &deny_decision);
        let enriched =
            apply_enforcement_to_event(&decision_applied, &enforcement.record_projection());

        (observed, enriched, deny_decision, enforcement)
    }

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        std::env::temp_dir().join(format!("agent-auditor-hostd-gws-mod-test-{nonce}"))
    }
}
