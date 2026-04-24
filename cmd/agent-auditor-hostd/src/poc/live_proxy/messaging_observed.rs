#![allow(clippy::result_large_err)]

use agenta_core::{
    ApprovalRequest, EventEnvelope, PolicyDecision, PolicyDecisionKind, SessionRecord,
    SessionWorkspace,
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
        LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
    },
    provider::{ProviderId, ProviderMethod},
    rest::RestHost,
};
use agenta_policy::{
    PolicyError, PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, apply_decision_to_event,
    approval_request_from_decision,
};
use serde_json::json;
use thiserror::Error;

use crate::poc::{
    messaging::{
        MessagingCollaborationGovernancePlan, contract::ClassifiedMessagingAction,
        persist::MessagingPocStore, record::RecordReflectionError,
    },
    persistence::PersistenceError,
};

use super::{
    LiveProxyInterceptionPlan,
    messaging::MessagingLivePreviewAdapterPlan,
    session_correlation::{
        CorrelatedLiveRequest, LiveRequestProvenance, RuntimeSessionLineage,
        SessionCorrelationError,
    },
};

#[derive(Debug, Clone, PartialEq)]
pub struct MessagingObservedRecord {
    pub correlated: CorrelatedLiveRequest,
    pub classified: ClassifiedMessagingAction,
    pub normalized_event: EventEnvelope,
    pub policy_decision: PolicyDecision,
    pub approval_request: Option<ApprovalRequest>,
    pub audit_record: EventEnvelope,
}

impl MessagingObservedRecord {
    pub fn summary(&self) -> String {
        format!(
            "request_id={} source_kind={} semantic_action={} policy_decision={:?} approval_request={} validation_status=absent",
            self.correlated.envelope.request_id,
            self.correlated.source_kind(),
            self.classified.semantic_action,
            self.policy_decision.decision,
            self.approval_request.is_some(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingObservedRuntime {
    live_proxy: LiveProxyInterceptionPlan,
    messaging_live: MessagingLivePreviewAdapterPlan,
    messaging: MessagingCollaborationGovernancePlan,
    store: MessagingPocStore,
}

impl MessagingObservedRuntime {
    pub fn bootstrap() -> Result<Self, MessagingObservedRuntimeError> {
        Ok(Self {
            live_proxy: LiveProxyInterceptionPlan::bootstrap(),
            messaging_live: MessagingLivePreviewAdapterPlan::default(),
            messaging: MessagingCollaborationGovernancePlan::bootstrap(),
            store: MessagingPocStore::bootstrap().map_err(MessagingObservedRuntimeError::Store)?,
        })
    }

    #[cfg(test)]
    fn fresh(root: impl Into<std::path::PathBuf>) -> Result<Self, MessagingObservedRuntimeError> {
        Ok(Self {
            live_proxy: LiveProxyInterceptionPlan::bootstrap(),
            messaging_live: MessagingLivePreviewAdapterPlan::default(),
            messaging: MessagingCollaborationGovernancePlan::bootstrap(),
            store: MessagingPocStore::fresh(root.into())
                .map_err(MessagingObservedRuntimeError::Store)?,
        })
    }

    pub fn store(&self) -> &MessagingPocStore {
        &self.store
    }

    pub fn preview_fixture(session_id: impl Into<String>) -> GenericLiveActionEnvelope {
        GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_live_proxy_messaging_discord_channels_messages_create")
                .expect("messaging observed request id should stay valid"),
            LiveCorrelationId::new("corr_live_proxy_messaging_discord_channels_messages_create")
                .expect("messaging observed correlation id should stay valid"),
            session_id,
            Some("openclaw-main".to_owned()),
            Some("ws_live_proxy_messaging_observed".to_owned()),
            Some(ProviderId::discord()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").expect("messaging observed transport should stay valid"),
            ProviderMethod::Post,
            RestHost::new("discord.com").expect("messaging observed authority should stay valid"),
            LivePath::new("/api/v10/channels/123456789012345678/messages")
                .expect("messaging observed path should stay valid"),
            LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
            LiveBodyClass::Json,
            LiveAuthHint::Bearer,
            None,
            LiveInterceptionMode::EnforcePreview,
        )
    }

    pub fn record_observed(
        &self,
        envelope: &GenericLiveActionEnvelope,
        lineage: &RuntimeSessionLineage,
    ) -> Result<Option<MessagingObservedRecord>, MessagingObservedRuntimeError> {
        let correlated = self
            .live_proxy
            .session_correlation
            .correlate_observed_request(envelope, lineage)
            .map_err(MessagingObservedRuntimeError::SessionCorrelation)?;
        self.record_correlated(&correlated)
    }

    pub fn record_correlated(
        &self,
        correlated: &CorrelatedLiveRequest,
    ) -> Result<Option<MessagingObservedRecord>, MessagingObservedRuntimeError> {
        if correlated.provenance != LiveRequestProvenance::ObservedRuntimePath {
            return Err(MessagingObservedRuntimeError::UnsupportedProvenance(
                correlated.source_kind().to_owned(),
            ));
        }

        let classified = match self
            .messaging_live
            .classify_live_preview(&correlated.envelope)
        {
            Ok(classified) => classified,
            Err(_) => return Ok(None),
        };

        let session = session_record_from_correlated(correlated)?;
        let mut normalized_event = self
            .messaging
            .policy
            .normalize_classified_action(&classified, &session);
        normalized_event.session = correlated.session.clone();
        annotate_observed_request(&mut normalized_event, correlated);

        let policy_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&normalized_event))
            .map_err(MessagingObservedRuntimeError::Policy)?;
        let decision_applied = apply_decision_to_event(&normalized_event, &policy_decision);
        let materialized_approval =
            approval_request_from_decision(&decision_applied, &policy_decision);

        let (audit_record, approval_request) = match policy_decision.decision {
            PolicyDecisionKind::Allow => (
                self.messaging
                    .record
                    .reflect_allow(&normalized_event, &policy_decision)
                    .map_err(MessagingObservedRuntimeError::Record)?,
                None,
            ),
            PolicyDecisionKind::RequireApproval => {
                let approval_request = materialized_approval.ok_or_else(|| {
                    MessagingObservedRuntimeError::MissingApprovalRequest {
                        event_id: normalized_event.event_id.clone(),
                    }
                })?;
                let (audit_record, approval_request) = self
                    .messaging
                    .record
                    .reflect_hold(&normalized_event, &policy_decision, &approval_request)
                    .map_err(MessagingObservedRuntimeError::Record)?;
                self.store
                    .append_approval_request(&approval_request)
                    .map_err(MessagingObservedRuntimeError::Store)?;
                (audit_record, Some(approval_request))
            }
            PolicyDecisionKind::Deny => (
                self.messaging
                    .record
                    .reflect_deny(&normalized_event, &policy_decision)
                    .map_err(MessagingObservedRuntimeError::Record)?,
                None,
            ),
        };

        self.store
            .append_audit_record(&audit_record)
            .map_err(MessagingObservedRuntimeError::Store)?;

        Ok(Some(MessagingObservedRecord {
            correlated: correlated.clone(),
            classified,
            normalized_event,
            policy_decision,
            approval_request,
            audit_record,
        }))
    }
}

fn session_record_from_correlated(
    correlated: &CorrelatedLiveRequest,
) -> Result<SessionRecord, MessagingObservedRuntimeError> {
    let agent_id = correlated
        .session
        .agent_id
        .clone()
        .ok_or(MessagingObservedRuntimeError::MissingAgentId)?;
    let mut session = SessionRecord::placeholder(agent_id, correlated.session.session_id.clone());
    session.policy_bundle_version = correlated.session.policy_bundle_version.clone();
    if correlated.session.workspace_id.is_some() {
        session.workspace = Some(SessionWorkspace {
            workspace_id: correlated.session.workspace_id.clone(),
            path: None,
            repo: None,
            branch: None,
        });
    }
    Ok(session)
}

fn annotate_observed_request(event: &mut EventEnvelope, correlated: &CorrelatedLiveRequest) {
    event.action.attributes.insert(
        "request_id".to_owned(),
        json!(correlated.envelope.request_id.as_str()),
    );
    event.action.attributes.insert(
        "correlation_id".to_owned(),
        json!(correlated.envelope.correlation_id.as_str()),
    );
    event.action.attributes.insert(
        "observation_provenance".to_owned(),
        json!(correlated.provenance.observation_provenance()),
    );
    event.action.attributes.insert(
        "live_request_source_kind".to_owned(),
        json!(correlated.source_kind()),
    );
    event.action.attributes.insert(
        "session_correlation_status".to_owned(),
        json!(correlated.session_correlation_status),
    );
    event.action.attributes.insert(
        "session_correlation_reason".to_owned(),
        json!(correlated.session_correlation_reason),
    );
    event.action.attributes.insert(
        "live_request_summary".to_owned(),
        json!(correlated.envelope.summary_line()),
    );
}

#[derive(Debug, Error)]
pub enum MessagingObservedRuntimeError {
    #[error("messaging observed runtime requires a correlated agent_id")]
    MissingAgentId,
    #[error("messaging observed runtime only accepts observed live-proxy provenance, got `{0}`")]
    UnsupportedProvenance(String),
    #[error("messaging observed runtime session correlation failed: {0}")]
    SessionCorrelation(#[source] SessionCorrelationError),
    #[error("messaging observed runtime policy evaluation failed: {0}")]
    Policy(#[source] PolicyError),
    #[error("messaging observed runtime record reflection failed: {0}")]
    Record(#[source] RecordReflectionError),
    #[error("messaging observed runtime persistence failed: {0}")]
    Store(#[source] PersistenceError),
    #[error("messaging observed runtime expected an approval request for event `{event_id}`")]
    MissingApprovalRequest { event_id: String },
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::PolicyDecisionKind;
    use serde_json::json;

    use super::MessagingObservedRuntime;
    use crate::poc::live_proxy::{
        forward_proxy::ForwardProxyIngressRuntime, session_correlation::RuntimeSessionLineage,
    };

    #[test]
    fn observed_discord_message_send_preserves_runtime_lineage_into_durable_audit() {
        let runtime = MessagingObservedRuntime::fresh(unique_state_dir())
            .expect("messaging observed runtime should bootstrap");
        let mut envelope =
            MessagingObservedRuntime::preview_fixture("sess_messaging_observed_runtime_lineage");
        envelope.workspace_id = Some("ws_messaging_observed_runtime_lineage".to_owned());
        let lineage = RuntimeSessionLineage::new(
            envelope.session_id.clone(),
            envelope
                .agent_id
                .clone()
                .expect("preview envelope should carry agent_id"),
            envelope.workspace_id.clone(),
        );

        let record = runtime
            .record_observed(&envelope, &lineage)
            .expect("observed messaging request should record")
            .expect("observed messaging request should classify");

        assert_eq!(
            record.classified.semantic_action.to_string(),
            "channels.messages.create"
        );
        assert_eq!(record.policy_decision.decision, PolicyDecisionKind::Allow);
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
            record.normalized_event.action.attributes.get("request_id"),
            Some(&json!(envelope.request_id.as_str()))
        );
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("correlation_id"),
            Some(&json!(envelope.correlation_id.as_str()))
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
        assert!(
            !record
                .normalized_event
                .action
                .attributes
                .contains_key("validation_status")
        );
        assert!(record.approval_request.is_none());
        assert_eq!(
            runtime
                .store()
                .latest_approval_request()
                .expect("approval request should read"),
            None
        );
        assert!(
            runtime
                .store()
                .latest_audit_record()
                .expect("audit record should read")
                .is_some_and(|audit_record| {
                    audit_record.session.session_id == lineage.session_id
                        && audit_record.session.agent_id == Some(lineage.agent_id.clone())
                        && audit_record.session.workspace_id == lineage.workspace_id.clone()
                        && audit_record.action.attributes.get("observation_provenance")
                            == Some(&json!("observed_request"))
                        && audit_record.action.attributes.get("validation_status")
                            == Some(&json!("validated_observation"))
                        && audit_record
                            .action
                            .attributes
                            .get("validation_capture_source")
                            == Some(&json!("forward_proxy_observed_runtime_path"))
                })
        );
    }

    #[test]
    fn non_messaging_observed_request_is_skipped() {
        let runtime = MessagingObservedRuntime::fresh(unique_state_dir())
            .expect("messaging observed runtime should bootstrap");
        let envelope = ForwardProxyIngressRuntime::preview_fixture("sess_non_messaging_observed");
        let lineage = RuntimeSessionLineage::new(
            envelope.session_id.clone(),
            envelope
                .agent_id
                .clone()
                .expect("forward proxy preview should carry agent_id"),
            envelope.workspace_id.clone(),
        );

        let result = runtime
            .record_observed(&envelope, &lineage)
            .expect("non messaging observation should not hard fail");

        assert!(result.is_none());
    }

    fn unique_state_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!(
            "agent-auditor-hostd-messaging-observed-runtime-test-{nonce}"
        ))
    }
}
