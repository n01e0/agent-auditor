mod common;

use serde_json::Value;

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

const FIXTURES: &str =
    include_str!("fixtures/hostd-github-semantic-governance-smoke-fixtures.json");

#[test]
fn hostd_github_semantic_governance_smoke_matches_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("github_taxonomy").map(String::as_str),
        fixtures["github_taxonomy"].as_str()
    );
    assert_eq!(
        lines.get("github_metadata").map(String::as_str),
        fixtures["github_metadata"].as_str()
    );
    assert_eq!(
        lines.get("github_policy").map(String::as_str),
        fixtures["github_policy"].as_str()
    );
    assert_eq!(
        lines.get("github_record").map(String::as_str),
        fixtures["github_record"].as_str()
    );
    assert_eq!(
        lines
            .get("github_classified_require_approval")
            .map(String::as_str),
        fixtures["github_classified_require_approval"].as_str()
    );

    let github_normalized_require_approval =
        json_line(&lines, "github_normalized_require_approval");
    assert_json_subset(
        &fixtures["github_normalized_require_approval"],
        &github_normalized_require_approval,
    );
    assert!(github_normalized_require_approval["timestamp"].is_string());

    let github_policy_decision_require_approval =
        json_line(&lines, "github_policy_decision_require_approval");
    assert_json_subset(
        &fixtures["github_policy_decision_require_approval"],
        &github_policy_decision_require_approval,
    );

    let github_approval_request_require_approval =
        json_line(&lines, "github_approval_request_require_approval");
    assert_json_subset(
        &fixtures["github_approval_request_require_approval"],
        &github_approval_request_require_approval,
    );
    assert!(github_approval_request_require_approval["requested_at"].is_string());

    let github_enriched_require_approval = json_line(&lines, "github_enriched_require_approval");
    assert_json_subset(
        &fixtures["github_enriched_require_approval"],
        &github_enriched_require_approval,
    );
    assert!(github_enriched_require_approval["timestamp"].is_string());

    let github_normalized_allow = json_line(&lines, "github_normalized_allow");
    assert_json_subset(
        &fixtures["github_normalized_allow"],
        &github_normalized_allow,
    );
    assert!(github_normalized_allow["timestamp"].is_string());

    let github_policy_decision_allow = json_line(&lines, "github_policy_decision_allow");
    assert_json_subset(
        &fixtures["github_policy_decision_allow"],
        &github_policy_decision_allow,
    );

    let github_enriched_allow = json_line(&lines, "github_enriched_allow");
    assert_json_subset(&fixtures["github_enriched_allow"], &github_enriched_allow);
    assert!(github_enriched_allow["timestamp"].is_string());

    let github_normalized_deny = json_line(&lines, "github_normalized_deny");
    assert_json_subset(&fixtures["github_normalized_deny"], &github_normalized_deny);
    assert!(github_normalized_deny["timestamp"].is_string());

    let github_policy_decision_deny = json_line(&lines, "github_policy_decision_deny");
    assert_json_subset(
        &fixtures["github_policy_decision_deny"],
        &github_policy_decision_deny,
    );

    let github_enriched_deny = json_line(&lines, "github_enriched_deny");
    assert_json_subset(&fixtures["github_enriched_deny"], &github_enriched_deny);
    assert!(github_enriched_deny["timestamp"].is_string());

    let persisted_github_audit_record_require_approval =
        json_line(&lines, "persisted_github_audit_record_require_approval");
    assert_json_subset(
        &fixtures["persisted_github_audit_record_require_approval"],
        &persisted_github_audit_record_require_approval,
    );

    let persisted_github_approval_request = json_line(&lines, "persisted_github_approval_request");
    assert_json_subset(
        &fixtures["persisted_github_approval_request"],
        &persisted_github_approval_request,
    );

    let persisted_github_audit_record_allow =
        json_line(&lines, "persisted_github_audit_record_allow");
    assert_json_subset(
        &fixtures["persisted_github_audit_record_allow"],
        &persisted_github_audit_record_allow,
    );

    let persisted_github_audit_record_deny =
        json_line(&lines, "persisted_github_audit_record_deny");
    assert_json_subset(
        &fixtures["persisted_github_audit_record_deny"],
        &persisted_github_audit_record_deny,
    );
}
