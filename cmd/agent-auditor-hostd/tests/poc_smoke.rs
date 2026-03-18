use std::{collections::BTreeMap, process::Command};

use serde_json::Value;

const FIXTURES: &str = include_str!("fixtures/hostd-smoke-fixtures.json");

#[test]
fn hostd_bootstrap_smoke_matches_poc_fixtures() {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-auditor-hostd"))
        .output()
        .expect("hostd binary should run for smoke test");

    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let lines = keyed_lines(&stdout);
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture json should parse");

    assert_eq!(
        lines.get("event_log_exec").map(String::as_str),
        fixtures["event_log_exec"].as_str()
    );
    assert_eq!(
        lines.get("event_log_exit").map(String::as_str),
        fixtures["event_log_exit"].as_str()
    );
    assert_eq!(
        lines.get("lifecycle_log").map(String::as_str),
        fixtures["lifecycle_log"].as_str()
    );

    let normalized_exec: Value = serde_json::from_str(
        lines
            .get("normalized_exec")
            .expect("smoke output should include normalized_exec"),
    )
    .expect("normalized_exec should be valid json");
    assert_json_subset(&fixtures["normalized_exec"], &normalized_exec);
    assert!(normalized_exec["timestamp"].is_string());

    let normalized_exit: Value = serde_json::from_str(
        lines
            .get("normalized_exit")
            .expect("smoke output should include normalized_exit"),
    )
    .expect("normalized_exit should be valid json");
    assert_json_subset(&fixtures["normalized_exit"], &normalized_exit);
    assert!(normalized_exit["timestamp"].is_string());
}

fn keyed_lines(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn assert_json_subset(expected: &Value, actual: &Value) {
    match (expected, actual) {
        (Value::Object(expected_map), Value::Object(actual_map)) => {
            for (key, expected_value) in expected_map {
                let actual_value = actual_map
                    .get(key)
                    .unwrap_or_else(|| panic!("missing key `{key}` in actual json: {actual:#}"));
                assert_json_subset(expected_value, actual_value);
            }
        }
        (Value::Array(expected_values), Value::Array(actual_values)) => {
            assert_eq!(expected_values.len(), actual_values.len());
            for (expected_value, actual_value) in expected_values.iter().zip(actual_values.iter()) {
                assert_json_subset(expected_value, actual_value);
            }
        }
        _ => assert_eq!(expected, actual),
    }
}
