mod common;

use serde_json::Value;

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-filesystem-enforcement-smoke-fixtures.json");

#[test]
fn hostd_filesystem_enforcement_smoke_matches_filesystem_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

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

    let normalized_filesystem = json_line(&lines, "normalized_filesystem");
    assert_json_subset(&fixtures["normalized_filesystem"], &normalized_filesystem);
    assert!(normalized_filesystem["timestamp"].is_string());
    assert!(normalized_filesystem["enforcement"]["expires_at"].is_string());

    let filesystem_policy_decision = json_line(&lines, "filesystem_policy_decision");
    assert_json_subset(
        &fixtures["filesystem_policy_decision"],
        &filesystem_policy_decision,
    );

    let filesystem_enforcement = json_line(&lines, "filesystem_enforcement");
    assert_json_subset(&fixtures["filesystem_enforcement"], &filesystem_enforcement);
    assert!(filesystem_enforcement["expires_at"].is_string());

    let normalized_filesystem_allow = json_line(&lines, "normalized_filesystem_allow");
    assert_json_subset(
        &fixtures["normalized_filesystem_allow"],
        &normalized_filesystem_allow,
    );
    assert!(normalized_filesystem_allow["timestamp"].is_string());
    assert!(normalized_filesystem_allow["enforcement"]["expires_at"].is_null());

    let filesystem_policy_decision_allow = json_line(&lines, "filesystem_policy_decision_allow");
    assert_json_subset(
        &fixtures["filesystem_policy_decision_allow"],
        &filesystem_policy_decision_allow,
    );

    let filesystem_enforcement_allow = json_line(&lines, "filesystem_enforcement_allow");
    assert_json_subset(
        &fixtures["filesystem_enforcement_allow"],
        &filesystem_enforcement_allow,
    );

    let filesystem_approval_request_allow = json_line(&lines, "filesystem_approval_request_allow");
    assert_json_subset(
        &fixtures["filesystem_approval_request_allow"],
        &filesystem_approval_request_allow,
    );

    let normalized_filesystem_deny = json_line(&lines, "normalized_filesystem_deny");
    assert_json_subset(
        &fixtures["normalized_filesystem_deny"],
        &normalized_filesystem_deny,
    );
    assert!(normalized_filesystem_deny["timestamp"].is_string());
    assert!(normalized_filesystem_deny["enforcement"]["expires_at"].is_null());

    let filesystem_policy_decision_deny = json_line(&lines, "filesystem_policy_decision_deny");
    assert_json_subset(
        &fixtures["filesystem_policy_decision_deny"],
        &filesystem_policy_decision_deny,
    );

    let filesystem_enforcement_deny = json_line(&lines, "filesystem_enforcement_deny");
    assert_json_subset(
        &fixtures["filesystem_enforcement_deny"],
        &filesystem_enforcement_deny,
    );

    let filesystem_approval_request_deny = json_line(&lines, "filesystem_approval_request_deny");
    assert_json_subset(
        &fixtures["filesystem_approval_request_deny"],
        &filesystem_approval_request_deny,
    );

    let persisted_audit_record = json_line(&lines, "persisted_audit_record");
    assert_json_subset(&fixtures["persisted_audit_record"], &persisted_audit_record);
    assert!(persisted_audit_record["timestamp"].is_string());
    assert!(persisted_audit_record["enforcement"]["expires_at"].is_string());

    let persisted_approval_request = json_line(&lines, "persisted_approval_request");
    assert_json_subset(
        &fixtures["persisted_approval_request"],
        &persisted_approval_request,
    );
    assert!(persisted_approval_request["requested_at"].is_string());
    assert!(persisted_approval_request["expires_at"].is_string());
    assert!(persisted_approval_request["enforcement"]["expires_at"].is_string());
}
