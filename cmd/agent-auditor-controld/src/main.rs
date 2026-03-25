use agenta_core::{
    Action, ActionClass, Actor, ActorKind, ApprovalDecisionRecord, ApprovalPolicy,
    ApprovalRecordPresentation, ApprovalRequest, ApprovalRequestAction, ApprovalScope,
    ApprovalStatus, RequesterContext, SessionRef, Severity,
    controlplane::{ApprovalControlPlaneProjection, ApprovalOpsSignals, ApprovalQueueItem},
};
use agenta_policy::PolicyInput;
use chrono::TimeZone;
use std::collections::BTreeMap;

fn print_json_line(key: &str, value: String) {
    println!("{}={}", key, value);
}

fn emit_projection_case(case_name: &str, projection: &ApprovalControlPlaneProjection) {
    print_json_line(
        &format!("approval_ops_hardening_status_{}", case_name),
        serde_json::to_string(&projection.ops_status)
            .expect("approval ops hardening status should serialize"),
    );
    print_json_line(
        &format!("approval_status_summary_{}", case_name),
        serde_json::to_string(&projection.status)
            .expect("approval status summary should serialize"),
    );
    print_json_line(
        &format!("approval_status_explanation_{}", case_name),
        serde_json::to_string(&projection.explanation)
            .expect("approval status explanation should serialize"),
    );
    print_json_line(
        &format!("approval_notification_summary_{}", case_name),
        serde_json::to_string(&projection.notification)
            .expect("approval notification summary should serialize"),
    );
    print_json_line(
        &format!("approval_reconciliation_summary_{}", case_name),
        serde_json::to_string(&projection.reconciliation)
            .expect("approval reconciliation summary should serialize"),
    );
    print_json_line(
        &format!("approval_audit_export_{}", case_name),
        serde_json::to_string(&projection.audit_export)
            .expect("approval audit export should serialize"),
    );
}

fn main() {
    let input = PolicyInput::new(
        "req_bootstrap_controld",
        SessionRef {
            session_id: "sess_bootstrap_controld".to_owned(),
            agent_id: Some("openclaw-main".to_owned()),
            initiator_id: Some("user:example".to_owned()),
            workspace_id: None,
            policy_bundle_version: Some("bundle-bootstrap".to_owned()),
            environment: Some("dev".to_owned()),
        },
        Actor {
            kind: ActorKind::Agent,
            id: Some("openclaw-main".to_owned()),
            display_name: Some("OpenClaw Main".to_owned()),
        },
        Action {
            class: ActionClass::Filesystem,
            verb: Some("read".to_owned()),
            target: Some("/var/run/secrets/demo".to_owned()),
            attributes: BTreeMap::new(),
        },
    );

    let mut attributes = BTreeMap::new();
    attributes.insert("provider_id".to_owned(), serde_json::json!("discord"));
    attributes.insert(
        "action_family".to_owned(),
        serde_json::json!("channel.invite"),
    );
    attributes.insert(
        "conversation_hint".to_owned(),
        serde_json::json!("incident-room"),
    );

    let approval_request = ApprovalRequest {
        approval_id: "apr_bootstrap_controld".to_owned(),
        status: ApprovalStatus::Pending,
        requested_at: chrono::Utc
            .with_ymd_and_hms(2026, 3, 21, 19, 30, 0)
            .single()
            .expect("fixed bootstrap timestamp should be valid"),
        resolved_at: None,
        expires_at: Some(
            chrono::Utc
                .with_ymd_and_hms(2026, 3, 21, 20, 0, 0)
                .single()
                .expect("fixed bootstrap timestamp should be valid"),
        ),
        session_id: "sess_bootstrap_controld".to_owned(),
        event_id: Some("evt_bootstrap_controld_invite".to_owned()),
        request: ApprovalRequestAction {
            action_class: ActionClass::Browser,
            action_verb: "channel.invite".to_owned(),
            target: Some("discord://server/ops/thread/incident-room".to_owned()),
            summary: Some("Invite a new member into the incident thread".to_owned()),
            attributes,
        },
        policy: ApprovalPolicy {
            rule_id: "messaging.channel_invite.requires_approval".to_owned(),
            severity: Some(Severity::High),
            reason: Some("Messaging membership expansion requires approval".to_owned()),
            scope: Some(ApprovalScope::SingleAction),
            ttl_seconds: Some(1800),
            reviewer_hint: Some("security-oncall".to_owned()),
        },
        presentation: Some(ApprovalRecordPresentation {
            reviewer_summary: Some(
                "Approval required before expanding incident-room membership".to_owned(),
            ),
            rationale: Some("Membership change affects incident communications".to_owned()),
        }),
        requester_context: Some(RequesterContext {
            agent_reason: Some("Need to add the incident commander to the thread".to_owned()),
            human_request: Some("please bring ops into the live incident room".to_owned()),
        }),
        decision: None,
        enforcement: None,
    };

    let queue_item = ApprovalQueueItem::from_request(&approval_request);
    let pending_review_projection = ApprovalControlPlaneProjection::derive(
        &queue_item,
        &ApprovalOpsSignals {
            stale: false,
            audit_record_present: true,
            decision_record_present: false,
            downstream_completion_recorded: false,
            requires_merge_follow_up: false,
        },
    );
    let stale_projection = ApprovalControlPlaneProjection::derive(
        &queue_item,
        &ApprovalOpsSignals {
            stale: true,
            audit_record_present: true,
            decision_record_present: false,
            downstream_completion_recorded: false,
            requires_merge_follow_up: false,
        },
    );
    let drift_missing_audit_projection = ApprovalControlPlaneProjection::derive(
        &queue_item,
        &ApprovalOpsSignals {
            stale: false,
            audit_record_present: false,
            decision_record_present: false,
            downstream_completion_recorded: false,
            requires_merge_follow_up: false,
        },
    );

    let mut approved_request = approval_request.clone();
    approved_request.status = ApprovalStatus::Approved;
    approved_request.decision = Some(ApprovalDecisionRecord {
        reviewer_id: Some("user:security-oncall".to_owned()),
        reviewer_note: Some("approved while the incident response continues".to_owned()),
        outcome: Some(ApprovalStatus::Approved),
    });
    let approved_queue_item = ApprovalQueueItem::from_request(&approved_request);

    let drift_missing_decision_projection = ApprovalControlPlaneProjection::derive(
        &approved_queue_item,
        &ApprovalOpsSignals {
            stale: false,
            audit_record_present: true,
            decision_record_present: false,
            downstream_completion_recorded: false,
            requires_merge_follow_up: false,
        },
    );
    let waiting_downstream_projection = ApprovalControlPlaneProjection::derive(
        &approved_queue_item,
        &ApprovalOpsSignals {
            stale: false,
            audit_record_present: true,
            decision_record_present: true,
            downstream_completion_recorded: false,
            requires_merge_follow_up: false,
        },
    );
    let waiting_merge_projection = ApprovalControlPlaneProjection::derive(
        &approved_queue_item,
        &ApprovalOpsSignals {
            stale: false,
            audit_record_present: true,
            decision_record_present: true,
            downstream_completion_recorded: false,
            requires_merge_follow_up: true,
        },
    );
    let stale_waiting_downstream_projection = ApprovalControlPlaneProjection::derive(
        &approved_queue_item,
        &ApprovalOpsSignals {
            stale: true,
            audit_record_present: true,
            decision_record_present: true,
            downstream_completion_recorded: false,
            requires_merge_follow_up: false,
        },
    );
    let stale_waiting_merge_projection = ApprovalControlPlaneProjection::derive(
        &approved_queue_item,
        &ApprovalOpsSignals {
            stale: true,
            audit_record_present: true,
            decision_record_present: true,
            downstream_completion_recorded: false,
            requires_merge_follow_up: true,
        },
    );
    let resolved_projection = ApprovalControlPlaneProjection::derive(
        &approved_queue_item,
        &ApprovalOpsSignals {
            stale: false,
            audit_record_present: true,
            decision_record_present: true,
            downstream_completion_recorded: true,
            requires_merge_follow_up: false,
        },
    );

    println!("agent-auditor-controld bootstrap");
    println!(
        "request_id={} action_class={:?}",
        input.request_id, input.action.class
    );
    println!(
        "approval_queue_model=components=approval_queue_item,approval_decision_summary,approval_rationale_capture input=approval_request reviewers=human_operator states=pending,approved,rejected,expired,cancelled"
    );
    print_json_line(
        "approval_queue_item",
        serde_json::to_string(&queue_item).expect("approval queue item should serialize"),
    );
    print_json_line(
        "approval_decision_summary",
        serde_json::to_string(&queue_item.decision_summary)
            .expect("approval decision summary should serialize"),
    );
    print_json_line(
        "approval_rationale_capture",
        serde_json::to_string(&queue_item.rationale_capture)
            .expect("approval rationale capture should serialize"),
    );
    println!(
        "approval_ops_hardening_model=components=approval_ops_signals,approval_ops_hardening_status facets=freshness,drift,recovery,waiting states=stale,missing_audit_record,missing_decision_record,missing_downstream_completion,waiting_merge recoveries=refresh_queue_projection,replay_from_audit,await_downstream_completion,recheck_downstream_state"
    );
    println!(
        "approval_ops_hardening_pattern_matrix=cases=pending_review,stale,drift_missing_audit,drift_missing_decision,waiting_downstream,waiting_merge,stale_waiting_downstream,stale_waiting_merge,resolved derived=status,explanation,notification,reconciliation,audit_export"
    );
    println!(
        "approval_control_plane_surface_model=components=approval_status_summary,approval_status_explanation,approval_notification_summary,approval_reconciliation_summary focuses=status,explanation,notification,reconciliation"
    );
    println!(
        "approval_audit_export_model=components=approval_audit_export_record linkage=approval_id,session_id,event_id,rule_id search=provider_id,action_family,status,status_kind,status_owner,severity consistency=reviewer_summary,persisted_rationale,agent_reason,human_request,reviewer_id reconciliation=state explanation=redaction_safe"
    );

    emit_projection_case("pending_review", &pending_review_projection);
    emit_projection_case("stale", &stale_projection);
    emit_projection_case("drift_missing_audit", &drift_missing_audit_projection);
    emit_projection_case("drift_missing_decision", &drift_missing_decision_projection);
    emit_projection_case("waiting_downstream", &waiting_downstream_projection);
    emit_projection_case("waiting_merge", &waiting_merge_projection);
    emit_projection_case(
        "stale_waiting_downstream",
        &stale_waiting_downstream_projection,
    );
    emit_projection_case("stale_waiting_merge", &stale_waiting_merge_projection);
    emit_projection_case("resolved", &resolved_projection);
}
