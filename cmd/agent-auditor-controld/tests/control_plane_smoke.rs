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

    assert!(lines
        .get("approval_control_plane_surface_model")
        .expect("surface model line should exist")
        .contains("approval_status_summary,approval_notification_summary,approval_reconciliation_summary"));

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
}
