mod common;

use std::collections::BTreeMap;

use serde_json::Value;

use self::common::{assert_json_subset, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-gws-smoke-fixtures.json");

#[test]
fn hostd_gws_poc_smoke_matches_gws_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("gws_session_linkage").map(String::as_str),
        fixtures["gws_session_linkage"].as_str()
    );
    assert_eq!(
        lines.get("gws_session_linked_api").map(String::as_str),
        fixtures["gws_session_linked_api"].as_str()
    );
    assert_eq!(
        lines.get("gws_session_linked_network").map(String::as_str),
        fixtures["gws_session_linked_network"].as_str()
    );
    assert_eq!(
        lines.get("gws_classify").map(String::as_str),
        fixtures["gws_classify"].as_str()
    );
    assert_eq!(
        lines.get("gws_classified_api").map(String::as_str),
        fixtures["gws_classified_api"].as_str()
    );
    assert_eq!(
        lines.get("gws_classified_network").map(String::as_str),
        fixtures["gws_classified_network"].as_str()
    );
    assert_eq!(
        lines.get("gws_evaluate").map(String::as_str),
        fixtures["gws_evaluate"].as_str()
    );
    assert_eq!(
        lines.get("gws_record").map(String::as_str),
        fixtures["gws_record"].as_str()
    );

    let gws_normalized_api = json_line(&lines, "gws_normalized_api");
    assert_json_subset(&fixtures["gws_normalized_api"], &gws_normalized_api);
    assert!(gws_normalized_api["timestamp"].is_string());

    let gws_normalized_network = json_line(&lines, "gws_normalized_network");
    assert_json_subset(&fixtures["gws_normalized_network"], &gws_normalized_network);
    assert!(gws_normalized_network["timestamp"].is_string());

    let gws_enriched_api = json_line(&lines, "gws_enriched_api");
    assert_json_subset(&fixtures["gws_enriched_api"], &gws_enriched_api);
    assert!(gws_enriched_api["timestamp"].is_string());

    let gws_policy_decision_api = json_line(&lines, "gws_policy_decision_api");
    assert_json_subset(
        &fixtures["gws_policy_decision_api"],
        &gws_policy_decision_api,
    );

    let gws_approval_request_api = json_line(&lines, "gws_approval_request_api");
    assert_json_subset(
        &fixtures["gws_approval_request_api"],
        &gws_approval_request_api,
    );
    assert!(gws_approval_request_api["requested_at"].is_string());
    assert!(gws_approval_request_api["expires_at"].is_string());

    let gws_normalized_admin = json_line(&lines, "gws_normalized_admin");
    assert_json_subset(&fixtures["gws_normalized_admin"], &gws_normalized_admin);
    assert!(gws_normalized_admin["timestamp"].is_string());

    let gws_enriched_admin = json_line(&lines, "gws_enriched_admin");
    assert_json_subset(&fixtures["gws_enriched_admin"], &gws_enriched_admin);
    assert!(gws_enriched_admin["timestamp"].is_string());

    let gws_policy_decision_admin = json_line(&lines, "gws_policy_decision_admin");
    assert_json_subset(
        &fixtures["gws_policy_decision_admin"],
        &gws_policy_decision_admin,
    );

    let gws_approval_request_admin = json_line(&lines, "gws_approval_request_admin");
    assert_json_subset(
        &fixtures["gws_approval_request_admin"],
        &gws_approval_request_admin,
    );

    let persisted_gws_audit_record_require_approval =
        json_line(&lines, "persisted_gws_audit_record_require_approval");
    assert_json_subset(
        &fixtures["persisted_gws_audit_record_require_approval"],
        &persisted_gws_audit_record_require_approval,
    );
    assert!(persisted_gws_audit_record_require_approval["timestamp"].is_string());

    let persisted_gws_approval_request = json_line(&lines, "persisted_gws_approval_request");
    assert_json_subset(
        &fixtures["persisted_gws_approval_request"],
        &persisted_gws_approval_request,
    );
    assert!(persisted_gws_approval_request["requested_at"].is_string());
    assert!(persisted_gws_approval_request["expires_at"].is_string());

    let persisted_gws_audit_record_allow = json_line(&lines, "persisted_gws_audit_record_allow");
    assert_json_subset(
        &fixtures["persisted_gws_audit_record_allow"],
        &persisted_gws_audit_record_allow,
    );
    assert!(persisted_gws_audit_record_allow["timestamp"].is_string());
}

fn json_line(lines: &BTreeMap<String, String>, key: &str) -> Value {
    serde_json::from_str(
        lines
            .get(key)
            .unwrap_or_else(|| panic!("smoke output should include {key}")),
    )
    .unwrap_or_else(|_| panic!("{key} should be valid json"))
}
