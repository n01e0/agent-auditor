mod common;

use serde_json::Value;

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

const FIXTURES: &str = include_str!("fixtures/hostd-provider-abstraction-smoke-fixtures.json");

#[test]
fn hostd_provider_abstraction_smoke_matches_fixtures() {
    let lines = run_hostd_bootstrap();
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("provider_abstraction_plan").map(String::as_str),
        fixtures["provider_abstraction_plan"].as_str()
    );
    assert_eq!(
        lines
            .get("provider_abstraction_catalog")
            .map(String::as_str),
        fixtures["provider_abstraction_catalog"].as_str()
    );

    let provider_abstraction_policy_input = json_line(&lines, "provider_abstraction_policy_input");
    assert_json_subset(
        &fixtures["provider_abstraction_policy_input"],
        &provider_abstraction_policy_input,
    );
    assert!(provider_abstraction_policy_input["timestamp"].is_string());

    let provider_abstraction_metadata_entry =
        json_line(&lines, "provider_abstraction_metadata_entry");
    assert_json_subset(
        &fixtures["provider_abstraction_metadata_entry"],
        &provider_abstraction_metadata_entry,
    );
}
