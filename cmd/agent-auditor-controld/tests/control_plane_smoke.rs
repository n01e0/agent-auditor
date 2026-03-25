use std::{collections::BTreeMap, process::Command};

use serde_json::Value;

fn controld_lines() -> BTreeMap<String, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-auditor-controld"))
        .output()
        .expect("agent-auditor-controld should run");
    assert!(
        output.status.success(),
        "controld bootstrap failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            line.split_once('=')
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
        })
        .collect()
}

#[test]
fn controld_bootstrap_surfaces_control_plane_status_notification_and_reconciliation() {
    let lines = controld_lines();

    let queue_item: Value = serde_json::from_str(
        lines
            .get("approval_queue_item")
            .expect("approval queue item line should exist"),
    )
    .expect("approval queue item json should parse");
    assert_eq!(
        queue_item["decision_summary"]["action_summary"],
        "Approval required before expanding incident-room membership"
    );
    assert_eq!(
        queue_item["decision_summary"]["rule_id"],
        "messaging.channel_invite.requires_approval"
    );

    let rationale_capture: Value = serde_json::from_str(
        lines
            .get("approval_rationale_capture")
            .expect("approval rationale capture line should exist"),
    )
    .expect("approval rationale capture json should parse");
    assert_eq!(
        rationale_capture["policy_reason"],
        "Membership change affects incident communications"
    );

    assert!(lines
        .get("approval_ops_hardening_pattern_matrix")
        .expect("pattern matrix line should exist")
        .contains("drift_missing_audit,drift_missing_decision,waiting_downstream,waiting_merge,stale_waiting_downstream,stale_waiting_merge,resolved"));

    assert!(lines
        .get("approval_control_plane_surface_model")
        .expect("surface model line should exist")
        .contains("approval_status_summary,approval_status_explanation,approval_notification_summary,approval_reconciliation_summary"));

    let pending_review_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_pending_review")
            .expect("pending_review status summary line should exist"),
    )
    .expect("pending_review status summary json should parse");
    assert_eq!(pending_review_status["kind"], "pending_review");
    assert_eq!(pending_review_status["actionable"], true);

    let pending_review_explanation: Value = serde_json::from_str(
        lines
            .get("approval_status_explanation_pending_review")
            .expect("pending_review status explanation line should exist"),
    )
    .expect("pending_review status explanation json should parse");
    assert_eq!(pending_review_explanation["owner"], "reviewer");
    assert_eq!(
        pending_review_explanation["rule_id"],
        "messaging.channel_invite.requires_approval"
    );
    assert_eq!(
        pending_review_explanation["reviewer_hint"],
        "security-oncall"
    );

    assert!(
        lines
            .get("approval_audit_export_model")
            .expect("audit export model line should exist")
            .contains("approval_audit_export_record")
    );
    assert!(
        lines
            .get("approval_audit_export_model")
            .expect("audit export model line should exist")
            .contains("consistency=reviewer_summary,persisted_rationale,agent_reason,human_request,reviewer_id")
    );

    let pending_review_audit_export: Value = serde_json::from_str(
        lines
            .get("approval_audit_export_pending_review")
            .expect("pending_review audit export line should exist"),
    )
    .expect("pending_review audit export json should parse");
    assert_eq!(pending_review_audit_export["status_kind"], "pending_review");
    assert_eq!(pending_review_audit_export["status_owner"], "reviewer");
    assert_eq!(pending_review_audit_export["provider_id"], "discord");
    assert_eq!(
        pending_review_audit_export["action_family"],
        "channel.invite"
    );
    assert_eq!(
        pending_review_audit_export["rule_id"],
        "messaging.channel_invite.requires_approval"
    );
    assert_eq!(
        pending_review_audit_export["reviewer_summary"],
        "Approval required before expanding incident-room membership"
    );
    assert_eq!(
        pending_review_audit_export["persisted_rationale"],
        "Membership change affects incident communications"
    );
    assert_eq!(
        pending_review_audit_export["agent_reason"],
        "Need to add the incident commander to the thread"
    );
    assert_eq!(
        pending_review_audit_export["human_request"],
        "please bring ops into the live incident room"
    );
    assert_eq!(pending_review_audit_export["reviewer_id"], Value::Null);

    let stale_ops: Value = serde_json::from_str(
        lines
            .get("approval_ops_hardening_status_stale")
            .expect("stale ops hardening line should exist"),
    )
    .expect("stale ops hardening json should parse");
    assert_eq!(stale_ops["freshness"], "stale");
    assert_eq!(stale_ops["drift"], "in_sync");
    assert_eq!(stale_ops["recovery"], "refresh_queue_projection");
    assert_eq!(stale_ops["waiting"], "reviewer_decision");

    let stale_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_stale")
            .expect("stale status summary line should exist"),
    )
    .expect("stale status summary json should parse");
    assert_eq!(stale_status["kind"], "stale_queue");
    assert_eq!(stale_status["actionable"], false);

    let stale_explanation: Value = serde_json::from_str(
        lines
            .get("approval_status_explanation_stale")
            .expect("stale explanation line should exist"),
    )
    .expect("stale explanation json should parse");
    assert_eq!(stale_explanation["owner"], "ops");
    assert_eq!(
        stale_explanation["next_step"],
        "Refresh the queue projection from append-only approval inputs before asking a reviewer to act"
    );

    let stale_notification: Value = serde_json::from_str(
        lines
            .get("approval_notification_summary_stale")
            .expect("stale notification line should exist"),
    )
    .expect("stale notification json should parse");
    assert_eq!(stale_notification["class"], "stale_queue_alert");
    assert_eq!(stale_notification["audience"], "ops");

    let stale_reconciliation: Value = serde_json::from_str(
        lines
            .get("approval_reconciliation_summary_stale")
            .expect("stale reconciliation line should exist"),
    )
    .expect("stale reconciliation json should parse");
    assert_eq!(stale_reconciliation["state"], "needs_queue_refresh");

    let stale_audit_export: Value = serde_json::from_str(
        lines
            .get("approval_audit_export_stale")
            .expect("stale audit export line should exist"),
    )
    .expect("stale audit export json should parse");
    assert_eq!(stale_audit_export["status_kind"], "stale_queue");
    assert_eq!(stale_audit_export["status_owner"], "ops");
    assert_eq!(
        stale_audit_export["reconciliation_state"],
        "needs_queue_refresh"
    );
    assert!(stale_audit_export.get("reviewer_note").is_none());

    let drift_missing_audit_ops: Value = serde_json::from_str(
        lines
            .get("approval_ops_hardening_status_drift_missing_audit")
            .expect("drift_missing_audit ops hardening line should exist"),
    )
    .expect("drift_missing_audit ops hardening json should parse");
    assert_eq!(drift_missing_audit_ops["drift"], "missing_audit_record");
    assert_eq!(drift_missing_audit_ops["recovery"], "replay_from_audit");

    let drift_missing_audit_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_drift_missing_audit")
            .expect("drift_missing_audit status summary line should exist"),
    )
    .expect("drift_missing_audit status summary json should parse");
    assert_eq!(drift_missing_audit_status["kind"], "drifted");

    let drift_missing_audit_reconciliation: Value = serde_json::from_str(
        lines
            .get("approval_reconciliation_summary_drift_missing_audit")
            .expect("drift_missing_audit reconciliation line should exist"),
    )
    .expect("drift_missing_audit reconciliation json should parse");
    assert_eq!(
        drift_missing_audit_reconciliation["state"],
        "needs_audit_replay"
    );

    let drift_missing_audit_export: Value = serde_json::from_str(
        lines
            .get("approval_audit_export_drift_missing_audit")
            .expect("drift_missing_audit export line should exist"),
    )
    .expect("drift_missing_audit export json should parse");
    assert_eq!(drift_missing_audit_export["status_kind"], "drifted");
    assert_eq!(
        drift_missing_audit_export["reconciliation_state"],
        "needs_audit_replay"
    );

    let drift_missing_decision_ops: Value = serde_json::from_str(
        lines
            .get("approval_ops_hardening_status_drift_missing_decision")
            .expect("drift_missing_decision ops hardening line should exist"),
    )
    .expect("drift_missing_decision ops hardening json should parse");
    assert_eq!(
        drift_missing_decision_ops["drift"],
        "missing_decision_record"
    );
    assert_eq!(
        drift_missing_decision_ops["waiting"],
        "downstream_completion"
    );

    let drift_missing_decision_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_drift_missing_decision")
            .expect("drift_missing_decision status summary line should exist"),
    )
    .expect("drift_missing_decision status summary json should parse");
    assert_eq!(drift_missing_decision_status["kind"], "drifted");

    let waiting_merge_ops: Value = serde_json::from_str(
        lines
            .get("approval_ops_hardening_status_waiting_merge")
            .expect("waiting_merge ops hardening line should exist"),
    )
    .expect("waiting_merge ops hardening json should parse");
    assert_eq!(waiting_merge_ops["waiting"], "waiting_merge");
    assert_eq!(waiting_merge_ops["recovery"], "await_downstream_completion");

    let waiting_merge_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_waiting_merge")
            .expect("waiting_merge status summary line should exist"),
    )
    .expect("waiting_merge status summary json should parse");
    assert_eq!(waiting_merge_status["kind"], "waiting_merge");

    let waiting_merge_explanation: Value = serde_json::from_str(
        lines
            .get("approval_status_explanation_waiting_merge")
            .expect("waiting_merge explanation line should exist"),
    )
    .expect("waiting_merge explanation json should parse");
    assert_eq!(waiting_merge_explanation["owner"], "requester");
    assert_eq!(
        waiting_merge_explanation["reviewer_hint"],
        "security-oncall"
    );

    let waiting_merge_notification: Value = serde_json::from_str(
        lines
            .get("approval_notification_summary_waiting_merge")
            .expect("waiting_merge notification line should exist"),
    )
    .expect("waiting_merge notification json should parse");
    assert_eq!(
        waiting_merge_notification["class"],
        "waiting_merge_reminder"
    );
    assert_eq!(waiting_merge_notification["audience"], "requester");

    let waiting_merge_reconciliation: Value = serde_json::from_str(
        lines
            .get("approval_reconciliation_summary_waiting_merge")
            .expect("waiting_merge reconciliation line should exist"),
    )
    .expect("waiting_merge reconciliation json should parse");
    assert_eq!(waiting_merge_reconciliation["state"], "awaiting_completion");

    let waiting_merge_audit_export: Value = serde_json::from_str(
        lines
            .get("approval_audit_export_waiting_merge")
            .expect("waiting_merge audit export line should exist"),
    )
    .expect("waiting_merge audit export json should parse");
    assert_eq!(waiting_merge_audit_export["status_kind"], "waiting_merge");
    assert_eq!(waiting_merge_audit_export["status_owner"], "requester");
    assert_eq!(
        waiting_merge_audit_export["notification_class"],
        "waiting_merge_reminder"
    );
    assert_eq!(
        waiting_merge_audit_export["reviewer_summary"],
        "Approval required before expanding incident-room membership"
    );
    assert_eq!(
        waiting_merge_audit_export["persisted_rationale"],
        "Membership change affects incident communications"
    );
    assert_eq!(
        waiting_merge_audit_export["reviewer_id"],
        "user:security-oncall"
    );

    let waiting_downstream_ops: Value = serde_json::from_str(
        lines
            .get("approval_ops_hardening_status_waiting_downstream")
            .expect("waiting_downstream ops hardening line should exist"),
    )
    .expect("waiting_downstream ops hardening json should parse");
    assert_eq!(waiting_downstream_ops["waiting"], "downstream_completion");
    assert_eq!(
        waiting_downstream_ops["recovery"],
        "await_downstream_completion"
    );

    let waiting_downstream_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_waiting_downstream")
            .expect("waiting_downstream status summary line should exist"),
    )
    .expect("waiting_downstream status summary json should parse");
    assert_eq!(waiting_downstream_status["kind"], "waiting_downstream");

    let waiting_downstream_notification: Value = serde_json::from_str(
        lines
            .get("approval_notification_summary_waiting_downstream")
            .expect("waiting_downstream notification line should exist"),
    )
    .expect("waiting_downstream notification json should parse");
    assert_eq!(
        waiting_downstream_notification["class"],
        "waiting_downstream_reminder"
    );

    let stale_waiting_merge_ops: Value = serde_json::from_str(
        lines
            .get("approval_ops_hardening_status_stale_waiting_merge")
            .expect("stale waiting_merge ops hardening line should exist"),
    )
    .expect("stale waiting_merge ops hardening json should parse");
    assert_eq!(stale_waiting_merge_ops["freshness"], "stale");
    assert_eq!(
        stale_waiting_merge_ops["drift"],
        "missing_downstream_completion"
    );
    assert_eq!(
        stale_waiting_merge_ops["recovery"],
        "recheck_downstream_state"
    );
    assert_eq!(stale_waiting_merge_ops["waiting"], "waiting_merge");

    let stale_waiting_merge_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_stale_waiting_merge")
            .expect("stale waiting_merge status summary line should exist"),
    )
    .expect("stale waiting_merge status summary json should parse");
    assert_eq!(stale_waiting_merge_status["kind"], "stale_follow_up");
    assert_eq!(stale_waiting_merge_status["actionable"], false);

    let stale_waiting_merge_explanation: Value = serde_json::from_str(
        lines
            .get("approval_status_explanation_stale_waiting_merge")
            .expect("stale waiting_merge explanation line should exist"),
    )
    .expect("stale waiting_merge explanation json should parse");
    assert_eq!(stale_waiting_merge_explanation["owner"], "ops");
    assert!(
        stale_waiting_merge_explanation["next_step"]
            .as_str()
            .expect("stale waiting_merge next_step should be a string")
            .contains("Recheck downstream or merge state")
    );

    let stale_waiting_merge_notification: Value = serde_json::from_str(
        lines
            .get("approval_notification_summary_stale_waiting_merge")
            .expect("stale waiting_merge notification line should exist"),
    )
    .expect("stale waiting_merge notification json should parse");
    assert_eq!(
        stale_waiting_merge_notification["class"],
        "stale_follow_up_alert"
    );
    assert_eq!(stale_waiting_merge_notification["audience"], "ops");

    let stale_waiting_merge_reconciliation: Value = serde_json::from_str(
        lines
            .get("approval_reconciliation_summary_stale_waiting_merge")
            .expect("stale waiting_merge reconciliation line should exist"),
    )
    .expect("stale waiting_merge reconciliation json should parse");
    assert_eq!(
        stale_waiting_merge_reconciliation["state"],
        "needs_downstream_refresh"
    );

    let stale_waiting_merge_audit_export: Value = serde_json::from_str(
        lines
            .get("approval_audit_export_stale_waiting_merge")
            .expect("stale waiting_merge audit export line should exist"),
    )
    .expect("stale waiting_merge audit export json should parse");
    assert_eq!(
        stale_waiting_merge_audit_export["status_kind"],
        "stale_follow_up"
    );
    assert_eq!(stale_waiting_merge_audit_export["status_owner"], "ops");
    assert_eq!(
        stale_waiting_merge_audit_export["reconciliation_state"],
        "needs_downstream_refresh"
    );
    assert!(
        stale_waiting_merge_audit_export["explanation_next_step"]
            .as_str()
            .expect("stale waiting_merge export next_step should be a string")
            .contains("Recheck downstream or merge state")
    );

    let stale_waiting_downstream_ops: Value = serde_json::from_str(
        lines
            .get("approval_ops_hardening_status_stale_waiting_downstream")
            .expect("stale waiting_downstream ops hardening line should exist"),
    )
    .expect("stale waiting_downstream ops hardening json should parse");
    assert_eq!(
        stale_waiting_downstream_ops["waiting"],
        "downstream_completion"
    );
    assert_eq!(
        stale_waiting_downstream_ops["recovery"],
        "recheck_downstream_state"
    );

    let stale_waiting_downstream_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_stale_waiting_downstream")
            .expect("stale waiting_downstream status summary line should exist"),
    )
    .expect("stale waiting_downstream status summary json should parse");
    assert_eq!(stale_waiting_downstream_status["kind"], "stale_follow_up");

    let stale_waiting_downstream_reconciliation: Value = serde_json::from_str(
        lines
            .get("approval_reconciliation_summary_stale_waiting_downstream")
            .expect("stale waiting_downstream reconciliation line should exist"),
    )
    .expect("stale waiting_downstream reconciliation json should parse");
    assert_eq!(
        stale_waiting_downstream_reconciliation["state"],
        "needs_downstream_refresh"
    );

    let resolved_status: Value = serde_json::from_str(
        lines
            .get("approval_status_summary_resolved")
            .expect("resolved status summary line should exist"),
    )
    .expect("resolved status summary json should parse");
    assert_eq!(resolved_status["kind"], "resolved");
    assert_eq!(resolved_status["actionable"], false);

    let resolved_notification: Value = serde_json::from_str(
        lines
            .get("approval_notification_summary_resolved")
            .expect("resolved notification line should exist"),
    )
    .expect("resolved notification json should parse");
    assert_eq!(resolved_notification["class"], "resolution_update");
    assert_eq!(resolved_notification["audience"], "requester");

    let resolved_reconciliation: Value = serde_json::from_str(
        lines
            .get("approval_reconciliation_summary_resolved")
            .expect("resolved reconciliation line should exist"),
    )
    .expect("resolved reconciliation json should parse");
    assert_eq!(resolved_reconciliation["state"], "in_sync");

    let resolved_audit_export: Value = serde_json::from_str(
        lines
            .get("approval_audit_export_resolved")
            .expect("resolved audit export line should exist"),
    )
    .expect("resolved audit export json should parse");
    assert_eq!(resolved_audit_export["status_kind"], "resolved");
    assert_eq!(
        resolved_audit_export["reviewer_summary"],
        "Approval required before expanding incident-room membership"
    );
    assert_eq!(resolved_audit_export["reviewer_id"], "user:security-oncall");
}
