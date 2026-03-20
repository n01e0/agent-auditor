mod common;

use std::collections::BTreeMap;

use serde_json::Value;

use self::common::{assert_json_subset, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-gws-smoke-fixtures.json");

#[test]
fn hostd_gws_enforcement_smoke_keeps_hold_and_deny_paths_consistent() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    let gws_enriched_api = json_line(&lines, "gws_enriched_api");
    let gws_policy_decision_api = json_line(&lines, "gws_policy_decision_api");
    let gws_approval_request_api = json_line(&lines, "gws_approval_request_api");
    let gws_enforcement_api = json_line(&lines, "gws_enforcement_api");
    assert_json_subset(&fixtures["gws_enforcement_api"], &gws_enforcement_api);
    let persisted_gws_audit_record_require_approval =
        json_line(&lines, "persisted_gws_audit_record_require_approval");
    let persisted_gws_approval_request = json_line(&lines, "persisted_gws_approval_request");

    assert_eq!(gws_policy_decision_api["decision"], "require_approval");
    assert_eq!(gws_enforcement_api["directive"], "hold");
    assert_eq!(gws_enforcement_api["status"], "held");
    assert_eq!(gws_enriched_api["result"]["status"], "approval_required");
    assert_eq!(gws_enriched_api["enforcement"]["directive"], "hold");
    assert_eq!(gws_approval_request_api["status"], "pending");
    assert!(gws_approval_request_api["requested_at"].is_string());
    assert!(gws_approval_request_api["expires_at"].is_string());
    assert!(persisted_gws_approval_request["requested_at"].is_string());
    assert!(persisted_gws_approval_request["expires_at"].is_string());

    let approval_id = &gws_approval_request_api["approval_id"];
    assert_eq!(gws_enforcement_api["approval_id"], *approval_id);
    assert_eq!(gws_enriched_api["enforcement"]["approval_id"], *approval_id);
    assert_eq!(
        persisted_gws_audit_record_require_approval["enforcement"]["approval_id"],
        *approval_id
    );
    assert_eq!(persisted_gws_approval_request["approval_id"], *approval_id);
    assert_eq!(
        persisted_gws_approval_request["enforcement"]["approval_id"],
        *approval_id
    );

    let gws_enriched_deny = json_line(&lines, "gws_enriched_deny");
    let gws_policy_decision_deny = json_line(&lines, "gws_policy_decision_deny");
    let gws_approval_request_deny = json_line(&lines, "gws_approval_request_deny");
    let gws_enforcement_deny = json_line(&lines, "gws_enforcement_deny");
    assert_json_subset(&fixtures["gws_enforcement_deny"], &gws_enforcement_deny);
    let persisted_gws_audit_record_deny = json_line(&lines, "persisted_gws_audit_record_deny");

    assert_eq!(gws_policy_decision_deny["decision"], "deny");
    assert!(gws_policy_decision_deny["approval"].is_null());
    assert!(gws_approval_request_deny.is_null());
    assert_eq!(gws_enforcement_deny["directive"], "deny");
    assert_eq!(gws_enforcement_deny["status"], "denied");
    assert!(gws_enforcement_deny["approval_id"].is_null());
    assert_eq!(gws_enriched_deny["result"]["status"], "denied");
    assert_eq!(gws_enriched_deny["enforcement"]["directive"], "deny");
    assert!(gws_enriched_deny["enforcement"]["approval_id"].is_null());
    assert_eq!(
        persisted_gws_audit_record_deny["enforcement"]["directive"],
        "deny"
    );
    assert!(persisted_gws_audit_record_deny["enforcement"]["approval_id"].is_null());

    let gws_enriched_admin = json_line(&lines, "gws_enriched_admin");
    let gws_policy_decision_admin = json_line(&lines, "gws_policy_decision_admin");
    let gws_approval_request_admin = json_line(&lines, "gws_approval_request_admin");
    let persisted_gws_audit_record_allow = json_line(&lines, "persisted_gws_audit_record_allow");

    assert_eq!(gws_policy_decision_admin["decision"], "allow");
    assert!(gws_approval_request_admin.is_null());
    assert!(gws_enriched_admin["enforcement"].is_null());
    assert!(persisted_gws_audit_record_allow["enforcement"].is_null());
    assert_eq!(
        persisted_gws_audit_record_allow["policy"]["decision"],
        "allow"
    );
}

fn json_line(lines: &BTreeMap<String, String>, key: &str) -> Value {
    serde_json::from_str(
        lines
            .get(key)
            .unwrap_or_else(|| panic!("smoke output should include {key}")),
    )
    .unwrap_or_else(|_| panic!("{key} should be valid json"))
}
