mod common;

use serde_json::Value;

use self::common::{assert_json_subset, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-smoke-fixtures.json");

#[test]
fn hostd_bootstrap_smoke_matches_poc_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("event_log_exec").map(String::as_str),
        fixtures["event_log_exec"].as_str()
    );
    assert_eq!(
        lines.get("event_log_exit").map(String::as_str),
        fixtures["event_log_exit"].as_str()
    );
    assert_eq!(
        lines.get("lifecycle_log").map(String::as_str),
        fixtures["lifecycle_log"].as_str()
    );
    assert_eq!(
        lines.get("event_log_network").map(String::as_str),
        fixtures["event_log_network"].as_str()
    );
    assert_eq!(
        lines.get("event_log_filesystem").map(String::as_str),
        fixtures["event_log_filesystem"].as_str()
    );
    assert_eq!(
        lines.get("event_log_filesystem_allow").map(String::as_str),
        fixtures["event_log_filesystem_allow"].as_str()
    );
    assert_eq!(
        lines.get("event_log_filesystem_deny").map(String::as_str),
        fixtures["event_log_filesystem_deny"].as_str()
    );

    let normalized_network_observed: Value = serde_json::from_str(
        lines
            .get("normalized_network_observed")
            .expect("smoke output should include normalized_network_observed"),
    )
    .expect("normalized_network_observed should be valid json");
    assert_json_subset(
        &fixtures["normalized_network_observed"],
        &normalized_network_observed,
    );
    assert!(normalized_network_observed["timestamp"].is_string());

    let normalized_network: Value = serde_json::from_str(
        lines
            .get("normalized_network")
            .expect("smoke output should include normalized_network"),
    )
    .expect("normalized_network should be valid json");
    assert_json_subset(&fixtures["normalized_network"], &normalized_network);
    assert!(normalized_network["timestamp"].is_string());

    let network_policy_decision: Value = serde_json::from_str(
        lines
            .get("network_policy_decision")
            .expect("smoke output should include network_policy_decision"),
    )
    .expect("network_policy_decision should be valid json");
    assert_json_subset(
        &fixtures["network_policy_decision"],
        &network_policy_decision,
    );

    let network_approval_request: Value = serde_json::from_str(
        lines
            .get("network_approval_request")
            .expect("smoke output should include network_approval_request"),
    )
    .expect("network_approval_request should be valid json");
    assert_json_subset(
        &fixtures["network_approval_request"],
        &network_approval_request,
    );

    let normalized_network_require_approval: Value = serde_json::from_str(
        lines
            .get("normalized_network_require_approval")
            .expect("smoke output should include normalized_network_require_approval"),
    )
    .expect("normalized_network_require_approval should be valid json");
    assert_json_subset(
        &fixtures["normalized_network_require_approval"],
        &normalized_network_require_approval,
    );
    assert!(normalized_network_require_approval["timestamp"].is_string());

    let network_policy_decision_require_approval: Value = serde_json::from_str(
        lines
            .get("network_policy_decision_require_approval")
            .expect("smoke output should include network_policy_decision_require_approval"),
    )
    .expect("network_policy_decision_require_approval should be valid json");
    assert_json_subset(
        &fixtures["network_policy_decision_require_approval"],
        &network_policy_decision_require_approval,
    );

    let network_approval_request_require_approval: Value = serde_json::from_str(
        lines
            .get("network_approval_request_require_approval")
            .expect("smoke output should include network_approval_request_require_approval"),
    )
    .expect("network_approval_request_require_approval should be valid json");
    assert_json_subset(
        &fixtures["network_approval_request_require_approval"],
        &network_approval_request_require_approval,
    );
    assert!(network_approval_request_require_approval["requested_at"].is_string());
    assert!(network_approval_request_require_approval["expires_at"].is_string());

    let normalized_network_deny: Value = serde_json::from_str(
        lines
            .get("normalized_network_deny")
            .expect("smoke output should include normalized_network_deny"),
    )
    .expect("normalized_network_deny should be valid json");
    assert_json_subset(
        &fixtures["normalized_network_deny"],
        &normalized_network_deny,
    );
    assert!(normalized_network_deny["timestamp"].is_string());

    let network_policy_decision_deny: Value = serde_json::from_str(
        lines
            .get("network_policy_decision_deny")
            .expect("smoke output should include network_policy_decision_deny"),
    )
    .expect("network_policy_decision_deny should be valid json");
    assert_json_subset(
        &fixtures["network_policy_decision_deny"],
        &network_policy_decision_deny,
    );

    let network_approval_request_deny: Value = serde_json::from_str(
        lines
            .get("network_approval_request_deny")
            .expect("smoke output should include network_approval_request_deny"),
    )
    .expect("network_approval_request_deny should be valid json");
    assert_json_subset(
        &fixtures["network_approval_request_deny"],
        &network_approval_request_deny,
    );

    let persisted_network_audit_record_allow: Value = serde_json::from_str(
        lines
            .get("persisted_network_audit_record_allow")
            .expect("smoke output should include persisted_network_audit_record_allow"),
    )
    .expect("persisted_network_audit_record_allow should be valid json");
    assert_json_subset(
        &fixtures["persisted_network_audit_record_allow"],
        &persisted_network_audit_record_allow,
    );
    assert!(persisted_network_audit_record_allow["timestamp"].is_string());

    let persisted_network_audit_record_require_approval: Value = serde_json::from_str(
        lines
            .get("persisted_network_audit_record_require_approval")
            .expect("smoke output should include persisted_network_audit_record_require_approval"),
    )
    .expect("persisted_network_audit_record_require_approval should be valid json");
    assert_json_subset(
        &fixtures["persisted_network_audit_record_require_approval"],
        &persisted_network_audit_record_require_approval,
    );
    assert!(persisted_network_audit_record_require_approval["timestamp"].is_string());

    let persisted_network_audit_record_deny: Value = serde_json::from_str(
        lines
            .get("persisted_network_audit_record_deny")
            .expect("smoke output should include persisted_network_audit_record_deny"),
    )
    .expect("persisted_network_audit_record_deny should be valid json");
    assert_json_subset(
        &fixtures["persisted_network_audit_record_deny"],
        &persisted_network_audit_record_deny,
    );
    assert!(persisted_network_audit_record_deny["timestamp"].is_string());

    let normalized_exec: Value = serde_json::from_str(
        lines
            .get("normalized_exec")
            .expect("smoke output should include normalized_exec"),
    )
    .expect("normalized_exec should be valid json");
    assert_json_subset(&fixtures["normalized_exec"], &normalized_exec);
    assert!(normalized_exec["timestamp"].is_string());

    let normalized_process_allow: Value = serde_json::from_str(
        lines
            .get("normalized_process_allow")
            .expect("smoke output should include normalized_process_allow"),
    )
    .expect("normalized_process_allow should be valid json");
    assert_json_subset(
        &fixtures["normalized_process_allow"],
        &normalized_process_allow,
    );
    assert!(normalized_process_allow["timestamp"].is_string());
    assert!(normalized_process_allow["enforcement"]["expires_at"].is_null());

    let process_policy_decision_allow: Value = serde_json::from_str(
        lines
            .get("process_policy_decision_allow")
            .expect("smoke output should include process_policy_decision_allow"),
    )
    .expect("process_policy_decision_allow should be valid json");
    assert_json_subset(
        &fixtures["process_policy_decision_allow"],
        &process_policy_decision_allow,
    );

    let process_enforcement_allow: Value = serde_json::from_str(
        lines
            .get("process_enforcement_allow")
            .expect("smoke output should include process_enforcement_allow"),
    )
    .expect("process_enforcement_allow should be valid json");
    assert_json_subset(
        &fixtures["process_enforcement_allow"],
        &process_enforcement_allow,
    );

    let process_approval_request_allow: Value = serde_json::from_str(
        lines
            .get("process_approval_request_allow")
            .expect("smoke output should include process_approval_request_allow"),
    )
    .expect("process_approval_request_allow should be valid json");
    assert_json_subset(
        &fixtures["process_approval_request_allow"],
        &process_approval_request_allow,
    );

    let normalized_process_hold: Value = serde_json::from_str(
        lines
            .get("normalized_process_hold")
            .expect("smoke output should include normalized_process_hold"),
    )
    .expect("normalized_process_hold should be valid json");
    assert_json_subset(
        &fixtures["normalized_process_hold"],
        &normalized_process_hold,
    );
    assert!(normalized_process_hold["timestamp"].is_string());
    assert!(normalized_process_hold["enforcement"]["expires_at"].is_string());

    let process_policy_decision_hold: Value = serde_json::from_str(
        lines
            .get("process_policy_decision_hold")
            .expect("smoke output should include process_policy_decision_hold"),
    )
    .expect("process_policy_decision_hold should be valid json");
    assert_json_subset(
        &fixtures["process_policy_decision_hold"],
        &process_policy_decision_hold,
    );

    let process_enforcement_hold: Value = serde_json::from_str(
        lines
            .get("process_enforcement_hold")
            .expect("smoke output should include process_enforcement_hold"),
    )
    .expect("process_enforcement_hold should be valid json");
    assert_json_subset(
        &fixtures["process_enforcement_hold"],
        &process_enforcement_hold,
    );
    assert!(process_enforcement_hold["expires_at"].is_string());

    let process_approval_request_hold: Value = serde_json::from_str(
        lines
            .get("process_approval_request_hold")
            .expect("smoke output should include process_approval_request_hold"),
    )
    .expect("process_approval_request_hold should be valid json");
    assert_json_subset(
        &fixtures["process_approval_request_hold"],
        &process_approval_request_hold,
    );
    assert!(process_approval_request_hold["requested_at"].is_string());
    assert!(process_approval_request_hold["expires_at"].is_string());
    assert!(process_approval_request_hold["enforcement"]["expires_at"].is_string());

    let normalized_process_deny: Value = serde_json::from_str(
        lines
            .get("normalized_process_deny")
            .expect("smoke output should include normalized_process_deny"),
    )
    .expect("normalized_process_deny should be valid json");
    assert_json_subset(
        &fixtures["normalized_process_deny"],
        &normalized_process_deny,
    );
    assert!(normalized_process_deny["timestamp"].is_string());
    assert!(normalized_process_deny["enforcement"]["expires_at"].is_null());

    let process_policy_decision_deny: Value = serde_json::from_str(
        lines
            .get("process_policy_decision_deny")
            .expect("smoke output should include process_policy_decision_deny"),
    )
    .expect("process_policy_decision_deny should be valid json");
    assert_json_subset(
        &fixtures["process_policy_decision_deny"],
        &process_policy_decision_deny,
    );

    let process_enforcement_deny: Value = serde_json::from_str(
        lines
            .get("process_enforcement_deny")
            .expect("smoke output should include process_enforcement_deny"),
    )
    .expect("process_enforcement_deny should be valid json");
    assert_json_subset(
        &fixtures["process_enforcement_deny"],
        &process_enforcement_deny,
    );

    let process_approval_request_deny: Value = serde_json::from_str(
        lines
            .get("process_approval_request_deny")
            .expect("smoke output should include process_approval_request_deny"),
    )
    .expect("process_approval_request_deny should be valid json");
    assert_json_subset(
        &fixtures["process_approval_request_deny"],
        &process_approval_request_deny,
    );

    let normalized_exit: Value = serde_json::from_str(
        lines
            .get("normalized_exit")
            .expect("smoke output should include normalized_exit"),
    )
    .expect("normalized_exit should be valid json");
    assert_json_subset(&fixtures["normalized_exit"], &normalized_exit);
    assert!(normalized_exit["timestamp"].is_string());

    let normalized_filesystem: Value = serde_json::from_str(
        lines
            .get("normalized_filesystem")
            .expect("smoke output should include normalized_filesystem"),
    )
    .expect("normalized_filesystem should be valid json");
    assert_json_subset(&fixtures["normalized_filesystem"], &normalized_filesystem);
    assert!(normalized_filesystem["timestamp"].is_string());
    assert!(normalized_filesystem["enforcement"]["expires_at"].is_string());

    let filesystem_policy_decision: Value = serde_json::from_str(
        lines
            .get("filesystem_policy_decision")
            .expect("smoke output should include filesystem_policy_decision"),
    )
    .expect("filesystem_policy_decision should be valid json");
    assert_json_subset(
        &fixtures["filesystem_policy_decision"],
        &filesystem_policy_decision,
    );

    let filesystem_enforcement: Value = serde_json::from_str(
        lines
            .get("filesystem_enforcement")
            .expect("smoke output should include filesystem_enforcement"),
    )
    .expect("filesystem_enforcement should be valid json");
    assert_json_subset(&fixtures["filesystem_enforcement"], &filesystem_enforcement);
    assert!(filesystem_enforcement["expires_at"].is_string());

    let normalized_filesystem_allow: Value = serde_json::from_str(
        lines
            .get("normalized_filesystem_allow")
            .expect("smoke output should include normalized_filesystem_allow"),
    )
    .expect("normalized_filesystem_allow should be valid json");
    assert_json_subset(
        &fixtures["normalized_filesystem_allow"],
        &normalized_filesystem_allow,
    );
    assert!(normalized_filesystem_allow["timestamp"].is_string());
    assert!(normalized_filesystem_allow["enforcement"]["expires_at"].is_null());

    let filesystem_policy_decision_allow: Value = serde_json::from_str(
        lines
            .get("filesystem_policy_decision_allow")
            .expect("smoke output should include filesystem_policy_decision_allow"),
    )
    .expect("filesystem_policy_decision_allow should be valid json");
    assert_json_subset(
        &fixtures["filesystem_policy_decision_allow"],
        &filesystem_policy_decision_allow,
    );

    let filesystem_enforcement_allow: Value = serde_json::from_str(
        lines
            .get("filesystem_enforcement_allow")
            .expect("smoke output should include filesystem_enforcement_allow"),
    )
    .expect("filesystem_enforcement_allow should be valid json");
    assert_json_subset(
        &fixtures["filesystem_enforcement_allow"],
        &filesystem_enforcement_allow,
    );

    let filesystem_approval_request_allow: Value = serde_json::from_str(
        lines
            .get("filesystem_approval_request_allow")
            .expect("smoke output should include filesystem_approval_request_allow"),
    )
    .expect("filesystem_approval_request_allow should be valid json");
    assert_json_subset(
        &fixtures["filesystem_approval_request_allow"],
        &filesystem_approval_request_allow,
    );

    let normalized_filesystem_deny: Value = serde_json::from_str(
        lines
            .get("normalized_filesystem_deny")
            .expect("smoke output should include normalized_filesystem_deny"),
    )
    .expect("normalized_filesystem_deny should be valid json");
    assert_json_subset(
        &fixtures["normalized_filesystem_deny"],
        &normalized_filesystem_deny,
    );
    assert!(normalized_filesystem_deny["timestamp"].is_string());
    assert!(normalized_filesystem_deny["enforcement"]["expires_at"].is_null());

    let filesystem_policy_decision_deny: Value = serde_json::from_str(
        lines
            .get("filesystem_policy_decision_deny")
            .expect("smoke output should include filesystem_policy_decision_deny"),
    )
    .expect("filesystem_policy_decision_deny should be valid json");
    assert_json_subset(
        &fixtures["filesystem_policy_decision_deny"],
        &filesystem_policy_decision_deny,
    );

    let filesystem_enforcement_deny: Value = serde_json::from_str(
        lines
            .get("filesystem_enforcement_deny")
            .expect("smoke output should include filesystem_enforcement_deny"),
    )
    .expect("filesystem_enforcement_deny should be valid json");
    assert_json_subset(
        &fixtures["filesystem_enforcement_deny"],
        &filesystem_enforcement_deny,
    );

    let filesystem_approval_request_deny: Value = serde_json::from_str(
        lines
            .get("filesystem_approval_request_deny")
            .expect("smoke output should include filesystem_approval_request_deny"),
    )
    .expect("filesystem_approval_request_deny should be valid json");
    assert_json_subset(
        &fixtures["filesystem_approval_request_deny"],
        &filesystem_approval_request_deny,
    );

    let persisted_audit_record: Value = serde_json::from_str(
        lines
            .get("persisted_audit_record")
            .expect("smoke output should include persisted_audit_record"),
    )
    .expect("persisted_audit_record should be valid json");
    assert_json_subset(&fixtures["persisted_audit_record"], &persisted_audit_record);
    assert!(persisted_audit_record["timestamp"].is_string());
    assert!(persisted_audit_record["enforcement"]["expires_at"].is_string());

    let persisted_approval_request: Value = serde_json::from_str(
        lines
            .get("persisted_approval_request")
            .expect("smoke output should include persisted_approval_request"),
    )
    .expect("persisted_approval_request should be valid json");
    assert_json_subset(
        &fixtures["persisted_approval_request"],
        &persisted_approval_request,
    );
    assert!(persisted_approval_request["requested_at"].is_string());
    assert!(persisted_approval_request["expires_at"].is_string());
    assert!(persisted_approval_request["enforcement"]["expires_at"].is_string());

    assert!(
        lines
            .get("approval_local_jsonl_inspection_model")
            .expect("smoke output should include approval_local_jsonl_inspection_model")
            .contains("consistency=reviewer_summary,persisted_rationale,agent_reason,human_request,reviewer_hint")
    );

    let persisted_messaging_local_jsonl_inspection_require_approval: Value =
        serde_json::from_str(
            lines
                .get("persisted_messaging_local_jsonl_inspection_require_approval")
                .expect(
                    "smoke output should include persisted_messaging_local_jsonl_inspection_require_approval"
                ),
        )
        .expect("persisted messaging local jsonl inspection should be valid json");
    assert_eq!(
        persisted_messaging_local_jsonl_inspection_require_approval["reviewer_summary"],
        "Messaging membership expansion requires approval"
    );
    assert_eq!(
        persisted_messaging_local_jsonl_inspection_require_approval["persisted_rationale"],
        "Messaging membership expansion requires approval"
    );
    assert_eq!(
        persisted_messaging_local_jsonl_inspection_require_approval["reviewer_hint"],
        "security-oncall"
    );
    assert_eq!(
        persisted_messaging_local_jsonl_inspection_require_approval["explanation_source"],
        "persisted_rationale"
    );
    assert_eq!(
        persisted_messaging_local_jsonl_inspection_require_approval["explanation_summary"],
        "Messaging membership expansion requires approval"
    );
}
