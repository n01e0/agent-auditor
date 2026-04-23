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
    github::{
        GitHubSemanticGovernancePocPlan, contract::ClassifiedGitHubGovernanceAction,
        persist::GitHubPocStore, record::RecordReflectionError,
    },
    persistence::PersistenceError,
};

use super::{
    LiveProxyInterceptionPlan,
    github::GitHubLivePreviewAdapterPlan,
    session_correlation::{
        CorrelatedLiveRequest, LiveRequestProvenance, ObservedRuntimePath, RuntimeSessionLineage,
        SessionCorrelationError,
    },
};

#[derive(Debug, Clone, PartialEq)]
pub struct GitHubValidatedObservationRecord {
    pub correlated: CorrelatedLiveRequest,
    pub classified: ClassifiedGitHubGovernanceAction,
    pub normalized_event: EventEnvelope,
    pub policy_decision: PolicyDecision,
    pub approval_request: Option<ApprovalRequest>,
    pub audit_record: EventEnvelope,
}

impl GitHubValidatedObservationRecord {
    pub fn summary(&self) -> String {
        format!(
            "request_id={} source_kind={} semantic_action={} policy_decision={:?} approval_request={} validation_status=validated_observation",
            self.classified.request_id,
            self.correlated.source_kind(),
            self.classified.semantic_action,
            self.policy_decision.decision,
            self.approval_request.is_some(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubValidatedObservationRuntime {
    live_proxy: LiveProxyInterceptionPlan,
    github_live: GitHubLivePreviewAdapterPlan,
    github: GitHubSemanticGovernancePocPlan,
    store: GitHubPocStore,
}

impl GitHubValidatedObservationRuntime {
    pub fn bootstrap() -> Result<Self, GitHubValidatedObservationRuntimeError> {
        Ok(Self {
            live_proxy: LiveProxyInterceptionPlan::bootstrap(),
            github_live: GitHubLivePreviewAdapterPlan::default(),
            github: GitHubSemanticGovernancePocPlan::bootstrap(),
            store: GitHubPocStore::bootstrap()
                .map_err(GitHubValidatedObservationRuntimeError::Store)?,
        })
    }

    #[cfg(test)]
    fn fresh(
        root: impl Into<std::path::PathBuf>,
    ) -> Result<Self, GitHubValidatedObservationRuntimeError> {
        Ok(Self {
            live_proxy: LiveProxyInterceptionPlan::bootstrap(),
            github_live: GitHubLivePreviewAdapterPlan::default(),
            github: GitHubSemanticGovernancePocPlan::bootstrap(),
            store: GitHubPocStore::fresh(root.into())
                .map_err(GitHubValidatedObservationRuntimeError::Store)?,
        })
    }

    pub fn store(&self) -> &GitHubPocStore {
        &self.store
    }

    pub fn preview_fixture(session_id: impl Into<String>) -> GenericLiveActionEnvelope {
        GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_live_proxy_github_validated_repos_update_visibility")
                .expect("github validated request id should stay valid"),
            LiveCorrelationId::new("corr_live_proxy_github_validated_repos_update_visibility")
                .expect("github validated correlation id should stay valid"),
            session_id,
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::github()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").expect("github validated transport should stay valid"),
            ProviderMethod::Patch,
            RestHost::new("api.github.com").expect("github validated authority should stay valid"),
            LivePath::new("/repos/n01e0/agent-auditor")
                .expect("github validated path should stay valid"),
            LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
            LiveBodyClass::Json,
            LiveAuthHint::Bearer,
            Some("repos/n01e0/agent-auditor/visibility".to_owned()),
            LiveInterceptionMode::EnforcePreview,
        )
    }

    pub fn record_observed(
        &self,
        envelope: &GenericLiveActionEnvelope,
        lineage: &RuntimeSessionLineage,
    ) -> Result<Option<GitHubValidatedObservationRecord>, GitHubValidatedObservationRuntimeError>
    {
        let correlated = self
            .live_proxy
            .session_correlation
            .correlate_observed_request(envelope, lineage)
            .map_err(GitHubValidatedObservationRuntimeError::SessionCorrelation)?;
        self.record_correlated(&correlated)
    }

    pub fn record_correlated(
        &self,
        correlated: &CorrelatedLiveRequest,
    ) -> Result<Option<GitHubValidatedObservationRecord>, GitHubValidatedObservationRuntimeError>
    {
        if correlated.provenance != LiveRequestProvenance::ObservedRuntimePath {
            return Err(
                GitHubValidatedObservationRuntimeError::UnsupportedProvenance(
                    correlated.source_kind().to_owned(),
                ),
            );
        }

        let classified = match self.github_live.classify_live_preview(&correlated.envelope) {
            Ok(classified) => classified,
            Err(_) => return Ok(None),
        };

        let session = session_record_from_correlated(correlated)?;
        let mut normalized_event = self
            .github
            .policy
            .normalize_classified_action(&classified, &session);
        annotate_validated_observation(&mut normalized_event, correlated);

        let policy_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(&normalized_event))
            .map_err(GitHubValidatedObservationRuntimeError::Policy)?;
        let decision_applied = apply_decision_to_event(&normalized_event, &policy_decision);
        let materialized_approval =
            approval_request_from_decision(&decision_applied, &policy_decision);

        let (audit_record, approval_request) = match policy_decision.decision {
            PolicyDecisionKind::Allow => (
                self.github
                    .record
                    .reflect_allow(&normalized_event, &policy_decision)
                    .map_err(GitHubValidatedObservationRuntimeError::Record)?,
                None,
            ),
            PolicyDecisionKind::RequireApproval => {
                let approval_request = materialized_approval.ok_or_else(|| {
                    GitHubValidatedObservationRuntimeError::MissingApprovalRequest {
                        event_id: normalized_event.event_id.clone(),
                    }
                })?;
                let (audit_record, approval_request) = self
                    .github
                    .record
                    .reflect_hold(&normalized_event, &policy_decision, &approval_request)
                    .map_err(GitHubValidatedObservationRuntimeError::Record)?;
                self.store
                    .append_approval_request(&approval_request)
                    .map_err(GitHubValidatedObservationRuntimeError::Store)?;
                (audit_record, Some(approval_request))
            }
            PolicyDecisionKind::Deny => (
                self.github
                    .record
                    .reflect_deny(&normalized_event, &policy_decision)
                    .map_err(GitHubValidatedObservationRuntimeError::Record)?,
                None,
            ),
        };

        self.store
            .append_audit_record(&audit_record)
            .map_err(GitHubValidatedObservationRuntimeError::Store)?;

        Ok(Some(GitHubValidatedObservationRecord {
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
) -> Result<SessionRecord, GitHubValidatedObservationRuntimeError> {
    let agent_id = correlated
        .session
        .agent_id
        .clone()
        .ok_or(GitHubValidatedObservationRuntimeError::MissingAgentId)?;
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

fn annotate_validated_observation(event: &mut EventEnvelope, correlated: &CorrelatedLiveRequest) {
    event.action.attributes.insert(
        "validation_status".to_owned(),
        json!("validated_observation"),
    );
    event.action.attributes.insert(
        "validation_capture_source".to_owned(),
        json!(ObservedRuntimePath::SOURCE_LABEL),
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
pub enum GitHubValidatedObservationRuntimeError {
    #[error("github validated observation requires a correlated agent_id")]
    MissingAgentId,
    #[error("github validated observation only accepts observed live-proxy provenance, got `{0}`")]
    UnsupportedProvenance(String),
    #[error("github validated observation session correlation failed: {0}")]
    SessionCorrelation(#[source] SessionCorrelationError),
    #[error("github validated observation policy evaluation failed: {0}")]
    Policy(#[source] PolicyError),
    #[error("github validated observation record reflection failed: {0}")]
    Record(#[source] RecordReflectionError),
    #[error("github validated observation persistence failed: {0}")]
    Store(#[source] PersistenceError),
    #[error("github validated observation expected an approval request for event `{event_id}`")]
    MissingApprovalRequest { event_id: String },
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::{PolicyDecisionKind, ResultStatus};
    use serde_json::json;

    use super::GitHubValidatedObservationRuntime;
    use crate::poc::live_proxy::{
        forward_proxy::ForwardProxyIngressRuntime, session_correlation::RuntimeSessionLineage,
    };

    #[test]
    fn observed_github_request_round_trips_through_policy_and_audit() {
        let runtime = GitHubValidatedObservationRuntime::fresh(unique_state_dir())
            .expect("github validated runtime should bootstrap");
        let envelope = GitHubValidatedObservationRuntime::preview_fixture(
            "sess_github_validated_observation_runtime",
        );
        let lineage = RuntimeSessionLineage::new(
            envelope.session_id.clone(),
            envelope
                .agent_id
                .clone()
                .expect("preview envelope should carry agent_id"),
            Some("ws_github_validated_observation".to_owned()),
        );
        let mut observed = envelope.clone();
        observed.workspace_id = lineage.workspace_id.clone();

        let record = runtime
            .record_observed(&observed, &lineage)
            .expect("observed github request should record")
            .expect("observed github request should classify");

        assert_eq!(record.correlated.source_kind(), "live_proxy_observed");
        assert_eq!(
            record.classified.semantic_action.to_string(),
            "repos.update_visibility"
        );
        assert_eq!(
            record.policy_decision.decision,
            PolicyDecisionKind::RequireApproval
        );
        assert_eq!(
            record.audit_record.result.status,
            ResultStatus::ApprovalRequired
        );
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("validation_status"),
            Some(&json!("validated_observation"))
        );
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("validation_capture_source"),
            Some(&json!("forward_proxy_observed_runtime_path"))
        );
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("live_request_source_kind"),
            Some(&json!("live_proxy_observed"))
        );
        assert!(record.approval_request.is_some());
        assert!(
            runtime
                .store()
                .latest_audit_record()
                .expect("audit record should read")
                .is_some()
        );
        assert!(
            runtime
                .store()
                .latest_approval_request()
                .expect("approval request should read")
                .is_some()
        );
    }

    #[test]
    fn non_github_observed_request_is_skipped() {
        let runtime = GitHubValidatedObservationRuntime::fresh(unique_state_dir())
            .expect("github validated runtime should bootstrap");
        let envelope = ForwardProxyIngressRuntime::preview_fixture("sess_non_github_observed");
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
            .expect("non github observation should not hard fail");

        assert!(result.is_none());
    }

    fn unique_state_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!(
            "agent-auditor-hostd-github-validated-runtime-test-{nonce}"
        ))
    }
}
