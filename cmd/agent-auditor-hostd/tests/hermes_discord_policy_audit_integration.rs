use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use agent_auditor_hostd::{
    poc::live_proxy::{
        forward_proxy::ForwardProxyIngressRuntime, messaging_observed::MessagingObservedRuntime,
        session_correlation::RuntimeSessionLineage,
    },
    runtime,
};
use agenta_core::{
    PolicyDecisionKind, ResultStatus,
    controlplane::{
        ObservationEvidenceTier, ObservationLocalJsonlInspectionRecord, ObservationProvenance,
        ObservationValidationStatus,
    },
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
        LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
    },
    provider::{ProviderId, ProviderMethod},
    rest::RestHost,
};
use serde_json::json;

#[test]
fn hermes_discord_permission_update_integrates_policy_into_durable_audit() {
    runtime::configure_state_dir(Some(unique_state_dir()))
        .expect("integration test should configure a dedicated state dir");

    let forward_proxy = ForwardProxyIngressRuntime::bootstrap()
        .expect("forward proxy runtime should bootstrap for Hermes integration test");
    let messaging_observed = MessagingObservedRuntime::bootstrap()
        .expect("messaging observed runtime should bootstrap for Hermes integration test");

    let envelope = hermes_discord_permission_update_envelope();
    let lineage = RuntimeSessionLineage::new(
        envelope.session_id.clone(),
        envelope
            .agent_id
            .clone()
            .expect("Hermes Discord fixture should include agent lineage"),
        envelope.workspace_id.clone(),
    );
    let observed_session = forward_proxy
        .observed_runtime()
        .session_path(lineage.clone())
        .expect("observed runtime session path should bootstrap");
    observed_session
        .append(&envelope)
        .expect("Hermes Discord request should append into observed runtime inbox");

    let observed = observed_session
        .drain_available()
        .expect("observed runtime inbox should drain")
        .into_iter()
        .find(|record| record.request_id == envelope.request_id)
        .expect("drained observed runtime should include the Hermes Discord request");

    let record = messaging_observed
        .record_observed(&observed, &lineage)
        .expect("Hermes Discord observed request should evaluate policy")
        .expect("Hermes Discord observed request should classify as messaging");

    assert_eq!(
        record.classified.semantic_action.to_string(),
        "channels.permissions.put"
    );
    assert_eq!(record.policy_decision.decision, PolicyDecisionKind::Deny);
    assert_eq!(
        record.policy_decision.rule_id.as_deref(),
        Some("messaging.permission_update.denied")
    );
    assert!(record.approval_request.is_none());
    assert_eq!(
        record.normalized_event.session.session_id,
        lineage.session_id
    );
    assert_eq!(
        record.normalized_event.session.agent_id,
        Some(lineage.agent_id.clone())
    );
    assert_eq!(
        record.normalized_event.session.workspace_id,
        lineage.workspace_id.clone()
    );
    assert_eq!(
        record
            .normalized_event
            .action
            .attributes
            .get("observation_provenance"),
        Some(&json!("observed_request"))
    );
    assert_eq!(
        record
            .normalized_event
            .action
            .attributes
            .get("live_request_source_kind"),
        Some(&json!("live_proxy_observed"))
    );
    assert_eq!(
        record
            .normalized_event
            .action
            .attributes
            .get("session_correlation_status"),
        Some(&json!("runtime_path_confirmed"))
    );
    assert_eq!(
        record.normalized_event.action.attributes.get("request_id"),
        Some(&json!("req_hermes_discord_permission_update_integration"))
    );
    assert_eq!(
        record
            .normalized_event
            .action
            .attributes
            .get("correlation_id"),
        Some(&json!("corr_hermes_discord_permission_update_integration"))
    );

    let persisted_audit = messaging_observed
        .store()
        .latest_audit_record()
        .expect("persisted audit record should read")
        .expect("persisted audit record should exist");
    assert_eq!(persisted_audit.session.session_id, lineage.session_id);
    assert_eq!(
        persisted_audit.session.agent_id,
        Some(lineage.agent_id.clone())
    );
    assert_eq!(
        persisted_audit.session.workspace_id,
        lineage.workspace_id.clone()
    );
    assert_eq!(persisted_audit.result.status, ResultStatus::Denied);
    assert_eq!(
        persisted_audit.action.verb.as_deref(),
        Some("channels.permissions.put")
    );
    assert_eq!(
        persisted_audit.action.attributes.get("provider_id"),
        Some(&json!("discord"))
    );
    assert_eq!(
        persisted_audit.action.attributes.get("action_family"),
        Some(&json!("permission.update"))
    );
    assert_eq!(
        persisted_audit
            .action
            .attributes
            .get("observation_provenance"),
        Some(&json!("observed_request"))
    );
    assert_eq!(
        persisted_audit
            .action
            .attributes
            .get("session_correlation_status"),
        Some(&json!("runtime_path_confirmed"))
    );
    assert_eq!(
        messaging_observed
            .store()
            .latest_approval_request()
            .expect("approval request should read"),
        None
    );

    let inspection = ObservationLocalJsonlInspectionRecord::from_event(&persisted_audit);
    assert_eq!(
        inspection.observation_provenance,
        Some(ObservationProvenance::ObservedRequest)
    );
    assert_eq!(
        inspection.validation_status,
        Some(ObservationValidationStatus::ObservedRequest)
    );
    assert_eq!(
        inspection.evidence_tier,
        Some(ObservationEvidenceTier::ObservedRequest)
    );
    assert_eq!(
        inspection.session_correlation_status.as_deref(),
        Some("runtime_path_confirmed")
    );
}

fn hermes_discord_permission_update_envelope() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_hermes_discord_permission_update_integration")
            .expect("integration request id should stay valid"),
        LiveCorrelationId::new("corr_hermes_discord_permission_update_integration")
            .expect("integration correlation id should stay valid"),
        "sess_hermes_discord_policy_audit_integration",
        Some("openclaw-main".to_owned()),
        Some("ws_hermes_discord_policy_audit_integration".to_owned()),
        Some(ProviderId::discord()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").expect("integration transport should stay valid"),
        ProviderMethod::Put,
        RestHost::new("discord.com").expect("integration host should stay valid"),
        LivePath::new("/api/v10/channels/123456789012345678/permissions/role:345678901234567890")
            .expect("integration path should stay valid"),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::EnforcePreview,
    )
}

fn unique_state_dir() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should advance")
        .as_nanos();
    env::temp_dir().join(format!(
        "agent-auditor-hostd-hermes-discord-policy-audit-integration-{nonce}"
    ))
}
