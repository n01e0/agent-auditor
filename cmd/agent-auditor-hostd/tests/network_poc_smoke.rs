mod common;

use std::collections::BTreeMap;

use serde_json::Value;

use self::common::{assert_json_subset, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-network-smoke-fixtures.json");

#[test]
fn hostd_network_poc_smoke_matches_network_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("event_log_network").map(String::as_str),
        fixtures["event_log_network"].as_str()
    );

    let normalized_network_observed = json_line(&lines, "normalized_network_observed");
    assert_json_subset(
        &fixtures["normalized_network_observed"],
        &normalized_network_observed,
    );
    assert!(normalized_network_observed["timestamp"].is_string());

    let normalized_network = json_line(&lines, "normalized_network");
    assert_json_subset(&fixtures["normalized_network"], &normalized_network);
    assert!(normalized_network["timestamp"].is_string());

    let network_policy_decision = json_line(&lines, "network_policy_decision");
    assert_json_subset(
        &fixtures["network_policy_decision"],
        &network_policy_decision,
    );

    let network_approval_request = json_line(&lines, "network_approval_request");
    assert_json_subset(
        &fixtures["network_approval_request"],
        &network_approval_request,
    );

    let normalized_network_require_approval =
        json_line(&lines, "normalized_network_require_approval");
    assert_json_subset(
        &fixtures["normalized_network_require_approval"],
        &normalized_network_require_approval,
    );
    assert!(normalized_network_require_approval["timestamp"].is_string());

    let network_policy_decision_require_approval =
        json_line(&lines, "network_policy_decision_require_approval");
    assert_json_subset(
        &fixtures["network_policy_decision_require_approval"],
        &network_policy_decision_require_approval,
    );

    let network_approval_request_require_approval =
        json_line(&lines, "network_approval_request_require_approval");
    assert_json_subset(
        &fixtures["network_approval_request_require_approval"],
        &network_approval_request_require_approval,
    );
    assert!(network_approval_request_require_approval["requested_at"].is_string());
    assert!(network_approval_request_require_approval["expires_at"].is_string());

    let normalized_network_deny = json_line(&lines, "normalized_network_deny");
    assert_json_subset(
        &fixtures["normalized_network_deny"],
        &normalized_network_deny,
    );
    assert!(normalized_network_deny["timestamp"].is_string());

    let network_policy_decision_deny = json_line(&lines, "network_policy_decision_deny");
    assert_json_subset(
        &fixtures["network_policy_decision_deny"],
        &network_policy_decision_deny,
    );

    let network_approval_request_deny = json_line(&lines, "network_approval_request_deny");
    assert_json_subset(
        &fixtures["network_approval_request_deny"],
        &network_approval_request_deny,
    );

    let persisted_network_audit_record_allow =
        json_line(&lines, "persisted_network_audit_record_allow");
    assert_json_subset(
        &fixtures["persisted_network_audit_record_allow"],
        &persisted_network_audit_record_allow,
    );
    assert!(persisted_network_audit_record_allow["timestamp"].is_string());

    let persisted_network_audit_record_require_approval =
        json_line(&lines, "persisted_network_audit_record_require_approval");
    assert_json_subset(
        &fixtures["persisted_network_audit_record_require_approval"],
        &persisted_network_audit_record_require_approval,
    );
    assert!(persisted_network_audit_record_require_approval["timestamp"].is_string());

    let persisted_network_audit_record_deny =
        json_line(&lines, "persisted_network_audit_record_deny");
    assert_json_subset(
        &fixtures["persisted_network_audit_record_deny"],
        &persisted_network_audit_record_deny,
    );
    assert!(persisted_network_audit_record_deny["timestamp"].is_string());
}

fn json_line(lines: &BTreeMap<String, String>, key: &str) -> Value {
    serde_json::from_str(
        lines
            .get(key)
            .unwrap_or_else(|| panic!("smoke output should include {key}")),
    )
    .unwrap_or_else(|_| panic!("{key} should be valid json"))
}
