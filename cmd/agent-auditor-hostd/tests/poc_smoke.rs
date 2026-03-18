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

    let persisted_audit_record: Value = serde_json::from_str(
        lines
            .get("persisted_audit_record")
            .expect("smoke output should include persisted_audit_record"),
    )
    .expect("persisted_audit_record should be valid json");
    assert_json_subset(&fixtures["persisted_audit_record"], &persisted_audit_record);
    assert!(persisted_audit_record["timestamp"].is_string());

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
}
