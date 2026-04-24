use std::{collections::BTreeMap, process::Command};

use serde_json::Value;

#[allow(dead_code)]
pub fn run_hostd_bootstrap() -> BTreeMap<String, String> {
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
    keyed_lines(&stdout)
}

#[allow(dead_code)]
pub fn json_line(lines: &BTreeMap<String, String>, key: &str) -> Value {
    serde_json::from_str(
        lines
            .get(key)
            .unwrap_or_else(|| panic!("smoke output should include {key}")),
    )
    .unwrap_or_else(|_| panic!("{key} should be valid json"))
}

pub fn keyed_lines(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

#[allow(dead_code)]
pub fn assert_json_subset(expected: &Value, actual: &Value) {
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
        (Value::Null, Value::Object(actual_map)) if looks_like_integrity_metadata(actual_map) => {
            assert!(
                actual_map
                    .get("hash")
                    .and_then(Value::as_str)
                    .is_some_and(|hash| hash.starts_with("sha256:"))
            );
            assert!(matches!(
                actual_map.get("prev_hash"),
                Some(Value::Null) | Some(Value::String(_)) | None
            ));
            assert!(matches!(
                actual_map.get("signature"),
                Some(Value::Null) | None
            ));
        }
        _ => assert_eq!(expected, actual),
    }
}

fn looks_like_integrity_metadata(actual_map: &serde_json::Map<String, Value>) -> bool {
    actual_map.contains_key("hash")
        && actual_map
            .keys()
            .all(|key| matches!(key.as_str(), "hash" | "prev_hash" | "signature"))
}
