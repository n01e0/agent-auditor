mod common;

use serde_json::{Value, json};

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

#[test]
fn hostd_github_validated_observation_smoke_runs_observed_runtime_path_end_to_end() {
    let lines = run_hostd_bootstrap();

    assert_eq!(
        lines
            .get("github_validated_runtime_source")
            .map(String::as_str),
        Some("forward_proxy_observed_runtime_path")
    );
    assert!(
        lines
            .get("github_validated_store_root")
            .is_some_and(|value| value.contains("agent-auditor-hostd-github-poc-store"))
    );
    assert!(
        lines
            .get("github_validated_observed_runtime_root")
            .is_some_and(|value| value.contains("agent-auditor-hostd-live-proxy-observed-runtime"))
    );
    assert!(
        lines
            .get("github_validated_observed_session_inbox")
            .is_some_and(|value| value.ends_with("requests.jsonl"))
    );
    assert_eq!(
        lines
            .get("github_validated_source_kind")
            .map(String::as_str),
        Some("live_proxy_observed")
    );
    assert_eq!(
        lines
            .get("github_validated_session_correlation_status")
            .map(String::as_str),
        Some("runtime_path_confirmed")
    );
    assert!(
        lines
            .get("github_validated_capture_summary")
            .is_some_and(|value| value.contains("api.github.com")
                && value.contains("repos/n01e0/agent-auditor/visibility"))
    );
    assert_eq!(
        lines.get("github_validated_classified").map(String::as_str),
        Some(
            "event=github.classified source=api_observation request_id=req_live_proxy_github_validated_repos_update_visibility semantic_surface=github.repos semantic_action=repos.update_visibility provider_action_id=github:repos.update_visibility target_hint=repos/n01e0/agent-auditor/visibility content_retained=false"
        )
    );

    let envelope = json_line(&lines, "github_validated_envelope");
    assert_json_subset(
        &json!({
            "source": "forward_proxy",
            "request_id": "req_live_proxy_github_validated_repos_update_visibility",
            "correlation_id": "corr_live_proxy_github_validated_repos_update_visibility",
            "session_id": "sess_live_proxy_github_validated_observation",
            "agent_id": "openclaw-main",
            "workspace_id": "ws_live_proxy_github_validated_observation",
            "provider_hint": "github",
            "transport": "https",
            "method": "patch",
            "authority": "api.github.com",
            "path": "/repos/n01e0/agent-auditor",
            "target_hint": "repos/n01e0/agent-auditor/visibility"
        }),
        &envelope,
    );

    let normalized_event = json_line(&lines, "github_validated_normalized_event");
    assert_eq!(
        normalized_event["action"]["attributes"]["source_kind"],
        json!("api_observation")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["validation_status"],
        json!("validated_observation")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["validation_capture_source"],
        json!("forward_proxy_observed_runtime_path")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["live_request_source_kind"],
        json!("live_proxy_observed")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["session_correlation_status"],
        json!("runtime_path_confirmed")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["action_key"],
        json!("repos.update_visibility")
    );
    assert!(normalized_event["timestamp"].is_string());

    let policy_decision = json_line(&lines, "github_validated_policy_decision");
    assert_eq!(policy_decision["decision"], json!("require_approval"));
    assert_eq!(
        policy_decision["rule_id"],
        json!("github.repos.update_visibility.requires_approval")
    );

    let approval_request = json_line(&lines, "github_validated_approval_request");
    assert_eq!(
        approval_request["request"]["action_verb"],
        json!("repos.update_visibility")
    );
    assert_eq!(
        approval_request["request"]["attributes"]["validation_status"],
        json!("validated_observation")
    );
    assert!(approval_request["requested_at"].is_string());

    let persisted_audit = json_line(&lines, "persisted_github_validated_audit_record");
    assert_eq!(
        persisted_audit["action"]["attributes"]["source_kind"],
        json!("api_observation")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["validation_status"],
        json!("validated_observation")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["live_request_source_kind"],
        json!("live_proxy_observed")
    );
    assert_eq!(
        persisted_audit["result"]["status"],
        json!("approval_required")
    );

    let persisted_approval = json_line(&lines, "persisted_github_validated_approval_request");
    assert_eq!(
        persisted_approval["request"]["action_verb"],
        json!("repos.update_visibility")
    );
    assert_eq!(
        persisted_approval["request"]["attributes"]["session_correlation_status"],
        json!("runtime_path_confirmed")
    );
    assert!(persisted_approval["requested_at"].is_string());

    let _ignored: Value = persisted_approval;
}
