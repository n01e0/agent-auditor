use agenta_core::{
    Action, ActionClass, Actor, ActorKind, ApprovalDecisionRecord, ApprovalPolicy, ApprovalRequest,
    ApprovalRequestAction, ApprovalScope, ApprovalStatus, RequesterContext, SessionRef, Severity,
    controlplane::{
        ApprovalNotificationSummary, ApprovalOpsHardeningStatus, ApprovalOpsSignals,
        ApprovalQueueItem, ApprovalReconciliationSummary, ApprovalStatusSummary,
    },
};
use agenta_policy::PolicyInput;
use chrono::TimeZone;
use std::collections::BTreeMap;

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
        presentation: None,
        requester_context: Some(RequesterContext {
            agent_reason: Some("Need to add the incident commander to the thread".to_owned()),
            human_request: Some("please bring ops into the live incident room".to_owned()),
        }),
        decision: None,
        enforcement: None,
    };

    let queue_item = ApprovalQueueItem::from_request(&approval_request);
    let stale_ops_status = ApprovalOpsHardeningStatus::derive(
        &queue_item,
        &ApprovalOpsSignals {
            stale: true,
            audit_record_present: true,
            decision_record_present: false,
            downstream_completion_recorded: false,
            requires_merge_follow_up: false,
        },
    );
    let stale_status_summary = ApprovalStatusSummary::derive(&queue_item, &stale_ops_status);
    let stale_notification =
        ApprovalNotificationSummary::derive(&queue_item, &stale_status_summary);
    let stale_reconciliation =
        ApprovalReconciliationSummary::derive(&queue_item, &stale_ops_status);

    let mut approved_request = approval_request.clone();
    approved_request.status = ApprovalStatus::Approved;
    approved_request.decision = Some(ApprovalDecisionRecord {
        reviewer_id: Some("user:security-oncall".to_owned()),
        reviewer_note: Some("approved while the incident response continues".to_owned()),
        outcome: Some(ApprovalStatus::Approved),
    });
    let approved_queue_item = ApprovalQueueItem::from_request(&approved_request);
    let waiting_merge_ops_status = ApprovalOpsHardeningStatus::derive(
        &approved_queue_item,
        &ApprovalOpsSignals {
            stale: false,
            audit_record_present: true,
            decision_record_present: true,
            downstream_completion_recorded: false,
            requires_merge_follow_up: true,
        },
    );
    let waiting_merge_status_summary =
        ApprovalStatusSummary::derive(&approved_queue_item, &waiting_merge_ops_status);
    let waiting_merge_notification =
        ApprovalNotificationSummary::derive(&approved_queue_item, &waiting_merge_status_summary);
    let waiting_merge_reconciliation =
        ApprovalReconciliationSummary::derive(&approved_queue_item, &waiting_merge_ops_status);

    println!("agent-auditor-controld bootstrap");
    println!(
        "request_id={} action_class={:?}",
        input.request_id, input.action.class
    );
    println!(
        "approval_queue_model=components=approval_queue_item,approval_decision_summary,approval_rationale_capture input=approval_request reviewers=human_operator states=pending,approved,rejected,expired,cancelled"
    );
    println!(
        "approval_queue_item={}",
        serde_json::to_string(&queue_item).expect("approval queue item should serialize")
    );
    println!(
        "approval_decision_summary={}",
        serde_json::to_string(&queue_item.decision_summary)
            .expect("approval decision summary should serialize")
    );
    println!(
        "approval_rationale_capture={}",
        serde_json::to_string(&queue_item.rationale_capture)
            .expect("approval rationale capture should serialize")
    );
    println!(
        "approval_ops_hardening_model=components=approval_ops_signals,approval_ops_hardening_status facets=freshness,drift,recovery,waiting states=stale,missing_audit_record,missing_decision_record,missing_downstream_completion,waiting_merge"
    );
    println!(
        "approval_ops_hardening_status_stale={}",
        serde_json::to_string(&stale_ops_status)
            .expect("approval ops hardening stale status should serialize")
    );
    println!(
        "approval_ops_hardening_status_waiting_merge={}",
        serde_json::to_string(&waiting_merge_ops_status)
            .expect("approval ops hardening waiting-merge status should serialize")
    );
    println!(
        "approval_control_plane_surface_model=components=approval_status_summary,approval_notification_summary,approval_reconciliation_summary focuses=status,notification,reconciliation"
    );
    println!(
        "approval_status_summary_stale={}",
        serde_json::to_string(&stale_status_summary)
            .expect("approval status summary should serialize")
    );
    println!(
        "approval_notification_summary_stale={}",
        serde_json::to_string(&stale_notification)
            .expect("approval notification summary should serialize")
    );
    println!(
        "approval_reconciliation_summary_stale={}",
        serde_json::to_string(&stale_reconciliation)
            .expect("approval reconciliation summary should serialize")
    );
    println!(
        "approval_status_summary_waiting_merge={}",
        serde_json::to_string(&waiting_merge_status_summary)
            .expect("approval waiting-merge status summary should serialize")
    );
    println!(
        "approval_notification_summary_waiting_merge={}",
        serde_json::to_string(&waiting_merge_notification)
            .expect("approval waiting-merge notification should serialize")
    );
    println!(
        "approval_reconciliation_summary_waiting_merge={}",
        serde_json::to_string(&waiting_merge_reconciliation)
            .expect("approval waiting-merge reconciliation should serialize")
    );
}
