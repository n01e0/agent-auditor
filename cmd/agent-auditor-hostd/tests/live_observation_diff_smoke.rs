mod common;

use serde_json::json;

use self::common::{json_line, run_hostd_bootstrap};

#[test]
fn hostd_live_observation_smoke_locks_preview_observed_and_validated_tiers() {
    let lines = run_hostd_bootstrap();

    assert_eq!(
        lines.get("forward_proxy_preview_request_summary"),
        lines.get("forward_proxy_request_summary")
    );
    assert_eq!(
        lines
            .get("forward_proxy_preview_source_kind")
            .map(String::as_str),
        Some("live_proxy_preview")
    );
    assert_eq!(
        lines.get("forward_proxy_source_kind").map(String::as_str),
        Some("live_proxy_observed")
    );

    let preview_event = json_line(&lines, "forward_proxy_preview_normalized_event");
    let observed_event = json_line(&lines, "forward_proxy_normalized_event");
    let preview_approval = json_line(&lines, "forward_proxy_preview_approval_request");
    let observed_approval = json_line(&lines, "forward_proxy_approval_request");
    let preview_inspection = json_line(
        &lines,
        "forward_proxy_preview_observation_local_jsonl_inspection",
    );
    let observed_inspection = json_line(
        &lines,
        "forward_proxy_observed_observation_local_jsonl_inspection",
    );
    let validated_inspection = json_line(
        &lines,
        "persisted_github_validated_approval_observation_local_jsonl_inspection",
    );

    assert_eq!(
        preview_event["action"]["verb"],
        observed_event["action"]["verb"]
    );
    assert_eq!(
        preview_event["action"]["target"],
        observed_event["action"]["target"]
    );
    assert_eq!(
        preview_approval["request"]["action_verb"],
        observed_approval["request"]["action_verb"]
    );

    assert_eq!(
        preview_event["action"]["attributes"]["source_kind"],
        json!("live_proxy_preview")
    );
    assert_eq!(
        observed_event["action"]["attributes"]["source_kind"],
        json!("live_proxy_observed")
    );
    assert_eq!(
        preview_event["action"]["attributes"]["observation_provenance"],
        json!("fixture_preview")
    );
    assert_eq!(
        observed_event["action"]["attributes"]["observation_provenance"],
        json!("observed_request")
    );
    assert_eq!(
        preview_event["action"]["attributes"]["validation_status"],
        json!("fixture_preview")
    );
    assert_eq!(
        observed_event["action"]["attributes"]["validation_status"],
        json!("observed_request")
    );
    assert_eq!(
        preview_event["action"]["attributes"]["session_correlation_status"],
        json!("fixture_lineage")
    );
    assert_eq!(
        observed_event["action"]["attributes"]["session_correlation_status"],
        json!("runtime_path_confirmed")
    );

    assert_eq!(
        preview_approval["request"]["attributes"]["observation_provenance"],
        json!("fixture_preview")
    );
    assert_eq!(
        observed_approval["request"]["attributes"]["observation_provenance"],
        json!("observed_request")
    );

    assert_eq!(
        preview_inspection["observation_provenance"],
        json!("fixture_preview")
    );
    assert_eq!(
        preview_inspection["validation_status"],
        json!("fixture_preview")
    );
    assert_eq!(
        preview_inspection["evidence_tier"],
        json!("fixture_preview")
    );
    assert_eq!(
        observed_inspection["observation_provenance"],
        json!("observed_request")
    );
    assert_eq!(
        observed_inspection["validation_status"],
        json!("observed_request")
    );
    assert_eq!(
        observed_inspection["evidence_tier"],
        json!("observed_request")
    );

    assert_eq!(
        validated_inspection["observation_provenance"],
        json!("observed_request")
    );
    assert_eq!(
        validated_inspection["validation_status"],
        json!("validated_observation")
    );
    assert_eq!(
        validated_inspection["evidence_tier"],
        json!("validated_observation")
    );
    assert_eq!(
        validated_inspection["capture_source"],
        json!("forward_proxy_observed_runtime_path")
    );
}
