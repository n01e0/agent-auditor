mod common;

use serde_json::Value;

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-messaging-governance-smoke-fixtures.json");

#[test]
fn hostd_messaging_governance_smoke_matches_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("messaging_taxonomy").map(String::as_str),
        fixtures["messaging_taxonomy"].as_str()
    );
    assert_eq!(
        lines.get("messaging_policy").map(String::as_str),
        fixtures["messaging_policy"].as_str()
    );
    assert_eq!(
        lines.get("messaging_record").map(String::as_str),
        fixtures["messaging_record"].as_str()
    );

    let messaging_normalized_allow = json_line(&lines, "messaging_normalized_allow");
    assert_json_subset(
        &fixtures["messaging_normalized_allow"],
        &messaging_normalized_allow,
    );
    assert!(messaging_normalized_allow["timestamp"].is_string());

    let messaging_policy_decision_allow = json_line(&lines, "messaging_policy_decision_allow");
    assert_json_subset(
        &fixtures["messaging_policy_decision_allow"],
        &messaging_policy_decision_allow,
    );

    let messaging_enriched_allow = json_line(&lines, "messaging_enriched_allow");
    assert_json_subset(
        &fixtures["messaging_enriched_allow"],
        &messaging_enriched_allow,
    );
    assert!(messaging_enriched_allow["timestamp"].is_string());

    let messaging_normalized_require_approval =
        json_line(&lines, "messaging_normalized_require_approval");
    assert_json_subset(
        &fixtures["messaging_normalized_require_approval"],
        &messaging_normalized_require_approval,
    );
    assert!(messaging_normalized_require_approval["timestamp"].is_string());

    let messaging_policy_decision_require_approval =
        json_line(&lines, "messaging_policy_decision_require_approval");
    assert_json_subset(
        &fixtures["messaging_policy_decision_require_approval"],
        &messaging_policy_decision_require_approval,
    );

    let messaging_approval_request_require_approval =
        json_line(&lines, "messaging_approval_request_require_approval");
    assert_json_subset(
        &fixtures["messaging_approval_request_require_approval"],
        &messaging_approval_request_require_approval,
    );
    assert!(messaging_approval_request_require_approval["requested_at"].is_string());
    assert!(messaging_approval_request_require_approval["expires_at"].is_string());

    let messaging_enriched_require_approval =
        json_line(&lines, "messaging_enriched_require_approval");
    assert_json_subset(
        &fixtures["messaging_enriched_require_approval"],
        &messaging_enriched_require_approval,
    );
    assert!(messaging_enriched_require_approval["timestamp"].is_string());
    assert!(messaging_enriched_require_approval["enforcement"]["expires_at"].is_string());

    let messaging_normalized_deny = json_line(&lines, "messaging_normalized_deny");
    assert_json_subset(
        &fixtures["messaging_normalized_deny"],
        &messaging_normalized_deny,
    );
    assert!(messaging_normalized_deny["timestamp"].is_string());

    let messaging_policy_decision_deny = json_line(&lines, "messaging_policy_decision_deny");
    assert_json_subset(
        &fixtures["messaging_policy_decision_deny"],
        &messaging_policy_decision_deny,
    );

    let messaging_enriched_deny = json_line(&lines, "messaging_enriched_deny");
    assert_json_subset(
        &fixtures["messaging_enriched_deny"],
        &messaging_enriched_deny,
    );
    assert!(messaging_enriched_deny["timestamp"].is_string());

    let messaging_normalized_file_upload = json_line(&lines, "messaging_normalized_file_upload");
    assert_json_subset(
        &fixtures["messaging_normalized_file_upload"],
        &messaging_normalized_file_upload,
    );
    assert!(messaging_normalized_file_upload["timestamp"].is_string());

    let messaging_policy_decision_file_upload =
        json_line(&lines, "messaging_policy_decision_file_upload");
    assert_json_subset(
        &fixtures["messaging_policy_decision_file_upload"],
        &messaging_policy_decision_file_upload,
    );

    let messaging_approval_request_file_upload =
        json_line(&lines, "messaging_approval_request_file_upload");
    assert_json_subset(
        &fixtures["messaging_approval_request_file_upload"],
        &messaging_approval_request_file_upload,
    );
    assert!(messaging_approval_request_file_upload["requested_at"].is_string());
    assert!(messaging_approval_request_file_upload["expires_at"].is_string());

    let messaging_enriched_file_upload = json_line(&lines, "messaging_enriched_file_upload");
    assert_json_subset(
        &fixtures["messaging_enriched_file_upload"],
        &messaging_enriched_file_upload,
    );
    assert!(messaging_enriched_file_upload["timestamp"].is_string());
    assert!(messaging_enriched_file_upload["enforcement"]["expires_at"].is_string());

    let persisted_messaging_audit_record_allow =
        json_line(&lines, "persisted_messaging_audit_record_allow");
    assert_json_subset(
        &fixtures["persisted_messaging_audit_record_allow"],
        &persisted_messaging_audit_record_allow,
    );
    assert!(persisted_messaging_audit_record_allow["timestamp"].is_string());

    let persisted_messaging_audit_record_require_approval =
        json_line(&lines, "persisted_messaging_audit_record_require_approval");
    assert_json_subset(
        &fixtures["persisted_messaging_audit_record_require_approval"],
        &persisted_messaging_audit_record_require_approval,
    );
    assert!(persisted_messaging_audit_record_require_approval["timestamp"].is_string());

    let persisted_messaging_approval_request_require_approval = json_line(
        &lines,
        "persisted_messaging_approval_request_require_approval",
    );
    assert_json_subset(
        &fixtures["persisted_messaging_approval_request_require_approval"],
        &persisted_messaging_approval_request_require_approval,
    );
    assert!(persisted_messaging_approval_request_require_approval["requested_at"].is_string());
    assert!(persisted_messaging_approval_request_require_approval["expires_at"].is_string());

    let persisted_messaging_audit_record_deny =
        json_line(&lines, "persisted_messaging_audit_record_deny");
    assert_json_subset(
        &fixtures["persisted_messaging_audit_record_deny"],
        &persisted_messaging_audit_record_deny,
    );
    assert!(persisted_messaging_audit_record_deny["timestamp"].is_string());

    let persisted_messaging_audit_record_file_upload =
        json_line(&lines, "persisted_messaging_audit_record_file_upload");
    assert_json_subset(
        &fixtures["persisted_messaging_audit_record_file_upload"],
        &persisted_messaging_audit_record_file_upload,
    );
    assert!(persisted_messaging_audit_record_file_upload["timestamp"].is_string());

    let persisted_messaging_approval_request_file_upload =
        json_line(&lines, "persisted_messaging_approval_request_file_upload");
    assert_json_subset(
        &fixtures["persisted_messaging_approval_request_file_upload"],
        &persisted_messaging_approval_request_file_upload,
    );
    assert!(persisted_messaging_approval_request_file_upload["requested_at"].is_string());
    assert!(persisted_messaging_approval_request_file_upload["expires_at"].is_string());
}
