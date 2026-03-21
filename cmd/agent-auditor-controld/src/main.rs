use agenta_core::{
    Action, ActionClass, Actor, ActorKind, ApprovalPolicy, ApprovalRequest, ApprovalRequestAction,
    ApprovalScope, ApprovalStatus, RequesterContext, SessionRef, Severity,
    controlplane::ApprovalQueueItem,
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
        requester_context: Some(RequesterContext {
            agent_reason: Some("Need to add the incident commander to the thread".to_owned()),
            human_request: Some("please bring ops into the live incident room".to_owned()),
        }),
        decision: None,
        enforcement: None,
    };

    let queue_item = ApprovalQueueItem::from_request(&approval_request);

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
}
