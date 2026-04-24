mod common;

use serde_json::{Value, json};

use self::common::{assert_json_subset, json_line, run_hostd_bootstrap};

#[test]
fn hostd_messaging_observed_smoke_preserves_runtime_lineage_into_durable_audit() {
    let lines = run_hostd_bootstrap();

    assert_eq!(
        lines
            .get("messaging_observed_runtime_source")
            .map(String::as_str),
        Some("forward_proxy_observed_runtime_path")
    );
    assert!(
        lines
            .get("messaging_observed_store_root")
            .is_some_and(|value| value.contains("agent-auditor-hostd-messaging-poc-store"))
    );
    assert!(
        lines
            .get("messaging_observed_runtime_root")
            .is_some_and(|value| value.contains("agent-auditor-hostd-live-proxy-observed-runtime"))
    );
    assert!(
        lines
            .get("messaging_observed_session_inbox")
            .is_some_and(|value| value.ends_with("requests.jsonl"))
    );
    assert_eq!(
        lines
            .get("messaging_observed_source_kind")
            .map(String::as_str),
        Some("live_proxy_observed")
    );
    assert_eq!(
        lines
            .get("messaging_observed_session_correlation_status")
            .map(String::as_str),
        Some("runtime_path_confirmed")
    );
    assert!(
        lines
            .get("messaging_observed_capture_summary")
            .is_some_and(|value| value.contains("discord.com")
                && value.contains("/api/v10/channels/123456789012345678/messages"))
    );
    assert_eq!(
        lines
            .get("messaging_observed_classified")
            .map(String::as_str),
        Some(
            "event=messaging.action source=api_observation provider=discord action_key=channels.messages.create family=message.send target_hint=discord.channels/123456789012345678/messages channel_hint=discord.channels/123456789012345678 conversation_hint=- delivery_scope=public_channel attachment_count_hint=- content_retained=false"
        )
    );

    let envelope = json_line(&lines, "messaging_observed_envelope");
    assert_json_subset(
        &json!({
            "source": "forward_proxy",
            "request_id": "req_live_proxy_messaging_discord_channels_messages_create",
            "correlation_id": "corr_live_proxy_messaging_discord_channels_messages_create",
            "session_id": "sess_live_proxy_messaging_observed",
            "agent_id": "openclaw-main",
            "workspace_id": "ws_live_proxy_messaging_observed",
            "provider_hint": "discord",
            "transport": "https",
            "method": "post",
            "authority": "discord.com",
            "path": "/api/v10/channels/123456789012345678/messages"
        }),
        &envelope,
    );

    let normalized_event = json_line(&lines, "messaging_observed_normalized_event");
    assert_eq!(
        normalized_event["session"]["session_id"],
        json!("sess_live_proxy_messaging_observed")
    );
    assert_eq!(
        normalized_event["session"]["agent_id"],
        json!("openclaw-main")
    );
    assert_eq!(
        normalized_event["session"]["workspace_id"],
        json!("ws_live_proxy_messaging_observed")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["source_kind"],
        json!("api_observation")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["observation_provenance"],
        json!("observed_request")
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
        normalized_event["action"]["attributes"]["request_id"],
        json!("req_live_proxy_messaging_discord_channels_messages_create")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["correlation_id"],
        json!("corr_live_proxy_messaging_discord_channels_messages_create")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["validation_status"],
        Value::Null
    );
    assert!(normalized_event["timestamp"].is_string());

    let policy_decision = json_line(&lines, "messaging_observed_policy_decision");
    assert_eq!(policy_decision["decision"], json!("allow"));
    assert_eq!(
        policy_decision["rule_id"],
        json!("messaging.message_send.allow")
    );

    assert_eq!(
        lines
            .get("messaging_observed_approval_request")
            .map(String::as_str),
        Some("null")
    );

    let persisted_audit = json_line(&lines, "persisted_messaging_observed_audit_record");
    assert_eq!(
        persisted_audit["session"]["session_id"],
        json!("sess_live_proxy_messaging_observed")
    );
    assert_eq!(
        persisted_audit["session"]["agent_id"],
        json!("openclaw-main")
    );
    assert_eq!(
        persisted_audit["session"]["workspace_id"],
        json!("ws_live_proxy_messaging_observed")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["observation_provenance"],
        json!("observed_request")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["live_request_source_kind"],
        json!("live_proxy_observed")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["session_correlation_status"],
        json!("runtime_path_confirmed")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["validation_status"],
        Value::Null
    );
    assert_eq!(persisted_audit["result"]["status"], json!("allowed"));

    let persisted_audit_observation_local_inspection = json_line(
        &lines,
        "persisted_messaging_observed_audit_observation_local_jsonl_inspection",
    );
    assert_eq!(
        persisted_audit_observation_local_inspection["observation_provenance"],
        json!("observed_request")
    );
    assert_eq!(
        persisted_audit_observation_local_inspection["validation_status"],
        json!("observed_request")
    );
    assert_eq!(
        persisted_audit_observation_local_inspection["evidence_tier"],
        json!("observed_request")
    );
    assert_eq!(
        persisted_audit_observation_local_inspection["session_correlation_status"],
        json!("runtime_path_confirmed")
    );

    let _ignored: Value = persisted_audit;
}
