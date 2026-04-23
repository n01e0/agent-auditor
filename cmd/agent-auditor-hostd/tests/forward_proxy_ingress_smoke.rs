mod common;

use common::{assert_json_subset, json_line, run_hostd_bootstrap};
use serde_json::json;

#[test]
fn hostd_forward_proxy_ingress_smoke_persists_redaction_safe_live_request_metadata() {
    let lines = run_hostd_bootstrap();

    assert_eq!(
        lines
            .get("forward_proxy_ingress_source")
            .map(String::as_str),
        Some("forward_proxy_jsonl")
    );
    assert!(
        lines
            .get("forward_proxy_ingress_inbox")
            .is_some_and(|path| path
                .contains("agent-auditor-hostd-live-proxy-forward-proxy-ingress/requests.jsonl"))
    );
    assert!(
        lines
            .get("forward_proxy_ingress_cursor")
            .is_some_and(|path| path
                .contains("agent-auditor-hostd-live-proxy-forward-proxy-ingress/requests.cursor"))
    );

    let envelope = json_line(&lines, "forward_proxy_envelope");
    assert_json_subset(
        &json!({
            "source": "forward_proxy",
            "request_id": "req_live_proxy_forward_proxy_gmail_users_messages_send_preview",
            "correlation_id": "corr_live_proxy_forward_proxy_gmail_users_messages_send_preview",
            "session_id": "sess_live_proxy_forward_proxy_ingress",
            "provider_hint": "gws",
            "transport": "https",
            "method": "post",
            "authority": "gmail.googleapis.com",
            "path": "/gmail/v1/users/me/messages/send",
            "headers": ["authorization", "content_json"],
            "body_class": "json",
            "auth_hint": "bearer",
            "target_hint": "gmail.users/me",
            "mode": "enforce_preview",
            "content_retained": false
        }),
        &envelope,
    );

    assert_eq!(
        lines
            .get("forward_proxy_request_summary")
            .map(String::as_str),
        Some(
            "event=live_proxy.http_request source=forward_proxy request_id=req_live_proxy_forward_proxy_gmail_users_messages_send_preview correlation_id=corr_live_proxy_forward_proxy_gmail_users_messages_send_preview transport=https method=POST authority=gmail.googleapis.com path=/gmail/v1/users/me/messages/send headers=authorization,content_json body_class=json auth_hint=bearer mode=enforce_preview"
        )
    );

    let normalized_event = json_line(&lines, "forward_proxy_normalized_event");
    assert_eq!(normalized_event["event_type"], json!("gws_action"));
    assert_eq!(
        normalized_event["action"]["verb"],
        json!("gmail.users.messages.send")
    );
    assert_eq!(
        normalized_event["action"]["target"],
        json!("gmail.users/me")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["source_kind"],
        json!("live_proxy_preview")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["content_retained"],
        json!(false)
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["mode"],
        json!("enforce_preview")
    );
    assert_eq!(
        normalized_event["action"]["attributes"]["live_request_summary"],
        json!(
            "event=live_proxy.http_request source=forward_proxy request_id=req_live_proxy_forward_proxy_gmail_users_messages_send_preview correlation_id=corr_live_proxy_forward_proxy_gmail_users_messages_send_preview transport=https method=POST authority=gmail.googleapis.com path=/gmail/v1/users/me/messages/send headers=authorization,content_json body_class=json auth_hint=bearer mode=enforce_preview"
        )
    );
    assert!(normalized_event["timestamp"].is_string());

    let policy_decision = json_line(&lines, "forward_proxy_policy_decision");
    assert_eq!(policy_decision["decision"], json!("require_approval"));

    let approval_request = json_line(&lines, "forward_proxy_approval_request");
    assert_eq!(approval_request["status"], json!("pending"));
    assert_eq!(
        approval_request["request"]["action_verb"],
        json!("gmail.users.messages.send")
    );
    assert!(approval_request["requested_at"].is_string());
    assert!(approval_request["expires_at"].is_string());

    assert!(
        lines
            .get("forward_proxy_approval_summary")
            .is_some_and(|summary| summary.contains("pending_approval_record_only"))
    );
    assert!(
        lines
            .get("forward_proxy_reflection_summary")
            .is_some_and(|summary| {
                summary.contains("mode_status=enforce_preview_record_only")
                    && summary.contains("failure_posture=fail_open")
                    && summary.contains("redaction_status=redaction_safe_preview_only")
            })
    );

    let persisted_audit = json_line(&lines, "persisted_forward_proxy_audit_record");
    assert_eq!(persisted_audit["event_type"], json!("gws_action"));
    assert_eq!(
        persisted_audit["action"]["attributes"]["mode_status"],
        json!("enforce_preview_record_only")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["record_status"],
        json!("enforce_preview_approval_request_recorded")
    );
    assert_eq!(
        persisted_audit["action"]["attributes"]["redaction_status"],
        json!("redaction_safe_preview_only")
    );
    assert!(persisted_audit["timestamp"].is_string());

    let persisted_approval = json_line(&lines, "persisted_forward_proxy_approval_request");
    assert_eq!(persisted_approval["status"], json!("pending"));
    assert_eq!(
        persisted_approval["enforcement"]["status"],
        json!("observe_only_fallback")
    );
    assert!(persisted_approval["requested_at"].is_string());
    assert!(persisted_approval["expires_at"].is_string());
}
