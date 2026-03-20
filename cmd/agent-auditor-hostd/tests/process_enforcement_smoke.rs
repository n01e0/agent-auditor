mod common;

use serde_json::Value;

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-process-enforcement-smoke-fixtures.json");

#[test]
fn hostd_process_enforcement_smoke_matches_process_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    let normalized_process_allow = json_line(&lines, "normalized_process_allow");
    assert_json_subset(
        &fixtures["normalized_process_allow"],
        &normalized_process_allow,
    );
    assert!(normalized_process_allow["timestamp"].is_string());
    assert!(normalized_process_allow["enforcement"]["expires_at"].is_null());

    let process_policy_decision_allow = json_line(&lines, "process_policy_decision_allow");
    assert_json_subset(
        &fixtures["process_policy_decision_allow"],
        &process_policy_decision_allow,
    );

    let process_enforcement_allow = json_line(&lines, "process_enforcement_allow");
    assert_json_subset(
        &fixtures["process_enforcement_allow"],
        &process_enforcement_allow,
    );

    let process_approval_request_allow = json_line(&lines, "process_approval_request_allow");
    assert_json_subset(
        &fixtures["process_approval_request_allow"],
        &process_approval_request_allow,
    );

    let normalized_process_hold = json_line(&lines, "normalized_process_hold");
    assert_json_subset(
        &fixtures["normalized_process_hold"],
        &normalized_process_hold,
    );
    assert!(normalized_process_hold["timestamp"].is_string());
    assert!(normalized_process_hold["enforcement"]["expires_at"].is_string());

    let process_policy_decision_hold = json_line(&lines, "process_policy_decision_hold");
    assert_json_subset(
        &fixtures["process_policy_decision_hold"],
        &process_policy_decision_hold,
    );

    let process_enforcement_hold = json_line(&lines, "process_enforcement_hold");
    assert_json_subset(
        &fixtures["process_enforcement_hold"],
        &process_enforcement_hold,
    );
    assert!(process_enforcement_hold["expires_at"].is_string());

    let process_approval_request_hold = json_line(&lines, "process_approval_request_hold");
    assert_json_subset(
        &fixtures["process_approval_request_hold"],
        &process_approval_request_hold,
    );
    assert!(process_approval_request_hold["requested_at"].is_string());
    assert!(process_approval_request_hold["expires_at"].is_string());
    assert!(process_approval_request_hold["enforcement"]["expires_at"].is_string());

    let normalized_process_deny = json_line(&lines, "normalized_process_deny");
    assert_json_subset(
        &fixtures["normalized_process_deny"],
        &normalized_process_deny,
    );
    assert!(normalized_process_deny["timestamp"].is_string());
    assert!(normalized_process_deny["enforcement"]["expires_at"].is_null());

    let process_policy_decision_deny = json_line(&lines, "process_policy_decision_deny");
    assert_json_subset(
        &fixtures["process_policy_decision_deny"],
        &process_policy_decision_deny,
    );

    let process_enforcement_deny = json_line(&lines, "process_enforcement_deny");
    assert_json_subset(
        &fixtures["process_enforcement_deny"],
        &process_enforcement_deny,
    );

    let process_approval_request_deny = json_line(&lines, "process_approval_request_deny");
    assert_json_subset(
        &fixtures["process_approval_request_deny"],
        &process_approval_request_deny,
    );
}
