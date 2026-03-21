mod common;

use serde_json::Value;

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-generic-rest-governance-smoke-fixtures.json");

#[test]
fn hostd_generic_rest_governance_smoke_matches_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("generic_rest_normalize").map(String::as_str),
        fixtures["generic_rest_normalize"].as_str()
    );
    assert_eq!(
        lines.get("generic_rest_policy").map(String::as_str),
        fixtures["generic_rest_policy"].as_str()
    );
    assert_eq!(
        lines.get("generic_rest_record").map(String::as_str),
        fixtures["generic_rest_record"].as_str()
    );

    let generic_rest_normalized_require_approval =
        json_line(&lines, "generic_rest_normalized_require_approval");
    assert_json_subset(
        &fixtures["generic_rest_normalized_require_approval"],
        &generic_rest_normalized_require_approval,
    );
    assert!(generic_rest_normalized_require_approval["timestamp"].is_string());

    let generic_rest_policy_decision_require_approval =
        json_line(&lines, "generic_rest_policy_decision_require_approval");
    assert_json_subset(
        &fixtures["generic_rest_policy_decision_require_approval"],
        &generic_rest_policy_decision_require_approval,
    );

    let generic_rest_approval_request_require_approval =
        json_line(&lines, "generic_rest_approval_request_require_approval");
    assert_json_subset(
        &fixtures["generic_rest_approval_request_require_approval"],
        &generic_rest_approval_request_require_approval,
    );
    assert!(generic_rest_approval_request_require_approval["requested_at"].is_string());
    assert!(generic_rest_approval_request_require_approval["expires_at"].is_string());

    let generic_rest_enriched_require_approval =
        json_line(&lines, "generic_rest_enriched_require_approval");
    assert_json_subset(
        &fixtures["generic_rest_enriched_require_approval"],
        &generic_rest_enriched_require_approval,
    );
    assert!(generic_rest_enriched_require_approval["timestamp"].is_string());
    assert!(generic_rest_enriched_require_approval["enforcement"]["expires_at"].is_string());

    let generic_rest_normalized_allow = json_line(&lines, "generic_rest_normalized_allow");
    assert_json_subset(
        &fixtures["generic_rest_normalized_allow"],
        &generic_rest_normalized_allow,
    );
    assert!(generic_rest_normalized_allow["timestamp"].is_string());

    let generic_rest_policy_decision_allow =
        json_line(&lines, "generic_rest_policy_decision_allow");
    assert_json_subset(
        &fixtures["generic_rest_policy_decision_allow"],
        &generic_rest_policy_decision_allow,
    );

    let generic_rest_enriched_allow = json_line(&lines, "generic_rest_enriched_allow");
    assert_json_subset(
        &fixtures["generic_rest_enriched_allow"],
        &generic_rest_enriched_allow,
    );
    assert!(generic_rest_enriched_allow["timestamp"].is_string());

    let generic_rest_normalized_deny = json_line(&lines, "generic_rest_normalized_deny");
    assert_json_subset(
        &fixtures["generic_rest_normalized_deny"],
        &generic_rest_normalized_deny,
    );
    assert!(generic_rest_normalized_deny["timestamp"].is_string());

    let generic_rest_policy_decision_deny = json_line(&lines, "generic_rest_policy_decision_deny");
    assert_json_subset(
        &fixtures["generic_rest_policy_decision_deny"],
        &generic_rest_policy_decision_deny,
    );

    let generic_rest_enriched_deny = json_line(&lines, "generic_rest_enriched_deny");
    assert_json_subset(
        &fixtures["generic_rest_enriched_deny"],
        &generic_rest_enriched_deny,
    );
    assert!(generic_rest_enriched_deny["timestamp"].is_string());

    let persisted_generic_rest_audit_record_require_approval = json_line(
        &lines,
        "persisted_generic_rest_audit_record_require_approval",
    );
    assert_json_subset(
        &fixtures["persisted_generic_rest_audit_record_require_approval"],
        &persisted_generic_rest_audit_record_require_approval,
    );
    assert!(persisted_generic_rest_audit_record_require_approval["timestamp"].is_string());

    let persisted_generic_rest_approval_request =
        json_line(&lines, "persisted_generic_rest_approval_request");
    assert_json_subset(
        &fixtures["persisted_generic_rest_approval_request"],
        &persisted_generic_rest_approval_request,
    );
    assert!(persisted_generic_rest_approval_request["requested_at"].is_string());
    assert!(persisted_generic_rest_approval_request["expires_at"].is_string());

    let persisted_generic_rest_audit_record_allow =
        json_line(&lines, "persisted_generic_rest_audit_record_allow");
    assert_json_subset(
        &fixtures["persisted_generic_rest_audit_record_allow"],
        &persisted_generic_rest_audit_record_allow,
    );
    assert!(persisted_generic_rest_audit_record_allow["timestamp"].is_string());

    let persisted_generic_rest_audit_record_deny =
        json_line(&lines, "persisted_generic_rest_audit_record_deny");
    assert_json_subset(
        &fixtures["persisted_generic_rest_audit_record_deny"],
        &persisted_generic_rest_audit_record_deny,
    );
    assert!(persisted_generic_rest_audit_record_deny["timestamp"].is_string());
}
