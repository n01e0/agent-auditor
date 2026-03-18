mod common;

use std::collections::BTreeMap;

use serde_json::Value;

use self::common::{assert_json_subset, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-secret-smoke-fixtures.json");

#[test]
fn hostd_secret_poc_smoke_matches_secret_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("event_log_secret_allow").map(String::as_str),
        fixtures["event_log_secret_allow"].as_str()
    );
    assert_eq!(
        lines
            .get("event_log_secret_require_approval")
            .map(String::as_str),
        fixtures["event_log_secret_require_approval"].as_str()
    );
    assert_eq!(
        lines.get("event_log_secret_deny").map(String::as_str),
        fixtures["event_log_secret_deny"].as_str()
    );

    let normalized_secret_allow_observed = json_line(&lines, "normalized_secret_allow_observed");
    assert_json_subset(
        &fixtures["normalized_secret_allow_observed"],
        &normalized_secret_allow_observed,
    );
    assert!(normalized_secret_allow_observed["timestamp"].is_string());

    let normalized_secret_allow = json_line(&lines, "normalized_secret_allow");
    assert_json_subset(
        &fixtures["normalized_secret_allow"],
        &normalized_secret_allow,
    );
    assert!(normalized_secret_allow["timestamp"].is_string());

    let secret_policy_decision_allow = json_line(&lines, "secret_policy_decision_allow");
    assert_json_subset(
        &fixtures["secret_policy_decision_allow"],
        &secret_policy_decision_allow,
    );

    let secret_approval_request_allow = json_line(&lines, "secret_approval_request_allow");
    assert_json_subset(
        &fixtures["secret_approval_request_allow"],
        &secret_approval_request_allow,
    );

    let normalized_secret_require_approval_observed =
        json_line(&lines, "normalized_secret_require_approval_observed");
    assert_json_subset(
        &fixtures["normalized_secret_require_approval_observed"],
        &normalized_secret_require_approval_observed,
    );
    assert!(normalized_secret_require_approval_observed["timestamp"].is_string());

    let normalized_secret_require_approval =
        json_line(&lines, "normalized_secret_require_approval");
    assert_json_subset(
        &fixtures["normalized_secret_require_approval"],
        &normalized_secret_require_approval,
    );
    assert!(normalized_secret_require_approval["timestamp"].is_string());

    let secret_policy_decision_require_approval =
        json_line(&lines, "secret_policy_decision_require_approval");
    assert_json_subset(
        &fixtures["secret_policy_decision_require_approval"],
        &secret_policy_decision_require_approval,
    );

    let secret_approval_request_require_approval =
        json_line(&lines, "secret_approval_request_require_approval");
    assert_json_subset(
        &fixtures["secret_approval_request_require_approval"],
        &secret_approval_request_require_approval,
    );
    assert!(secret_approval_request_require_approval["requested_at"].is_string());
    assert!(secret_approval_request_require_approval["expires_at"].is_string());

    let normalized_secret_deny_observed = json_line(&lines, "normalized_secret_deny_observed");
    assert_json_subset(
        &fixtures["normalized_secret_deny_observed"],
        &normalized_secret_deny_observed,
    );
    assert!(normalized_secret_deny_observed["timestamp"].is_string());

    let normalized_secret_deny = json_line(&lines, "normalized_secret_deny");
    assert_json_subset(&fixtures["normalized_secret_deny"], &normalized_secret_deny);
    assert!(normalized_secret_deny["timestamp"].is_string());

    let secret_policy_decision_deny = json_line(&lines, "secret_policy_decision_deny");
    assert_json_subset(
        &fixtures["secret_policy_decision_deny"],
        &secret_policy_decision_deny,
    );

    let secret_approval_request_deny = json_line(&lines, "secret_approval_request_deny");
    assert_json_subset(
        &fixtures["secret_approval_request_deny"],
        &secret_approval_request_deny,
    );

    let persisted_secret_audit_record_allow =
        json_line(&lines, "persisted_secret_audit_record_allow");
    assert_json_subset(
        &fixtures["persisted_secret_audit_record_allow"],
        &persisted_secret_audit_record_allow,
    );
    assert!(persisted_secret_audit_record_allow["timestamp"].is_string());

    let persisted_secret_audit_record_require_approval =
        json_line(&lines, "persisted_secret_audit_record_require_approval");
    assert_json_subset(
        &fixtures["persisted_secret_audit_record_require_approval"],
        &persisted_secret_audit_record_require_approval,
    );
    assert!(persisted_secret_audit_record_require_approval["timestamp"].is_string());

    let persisted_secret_approval_request = json_line(&lines, "persisted_secret_approval_request");
    assert_json_subset(
        &fixtures["persisted_secret_approval_request"],
        &persisted_secret_approval_request,
    );
    assert!(persisted_secret_approval_request["requested_at"].is_string());
    assert!(persisted_secret_approval_request["expires_at"].is_string());

    let persisted_secret_audit_record_deny =
        json_line(&lines, "persisted_secret_audit_record_deny");
    assert_json_subset(
        &fixtures["persisted_secret_audit_record_deny"],
        &persisted_secret_audit_record_deny,
    );
    assert!(persisted_secret_audit_record_deny["timestamp"].is_string());
}

fn json_line(lines: &BTreeMap<String, String>, key: &str) -> Value {
    serde_json::from_str(
        lines
            .get(key)
            .unwrap_or_else(|| panic!("smoke output should include {key}")),
    )
    .unwrap_or_else(|_| panic!("{key} should be valid json"))
}
