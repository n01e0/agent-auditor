use agenta_core::{EventEnvelope, PolicyDecisionKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveMode {
    Shadow,
    EnforcePreview,
    Unsupported,
}

impl LiveMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::EnforcePreview => "enforce_preview",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn from_label(label: &str) -> Self {
        match label {
            "shadow" => Self::Shadow,
            "enforce_preview" => Self::EnforcePreview,
            "unsupported" => Self::Unsupported,
            _ => Self::Unsupported,
        }
    }

    pub fn from_event(event: &EventEnvelope) -> Self {
        let label = event
            .action
            .attributes
            .get("mode")
            .and_then(|value| value.as_str())
            .unwrap_or("unsupported");
        Self::from_label(label)
    }

    pub fn project(self, decision: PolicyDecisionKind) -> LiveModeProjection {
        match self {
            Self::Shadow => shadow_projection(decision),
            Self::EnforcePreview => enforce_preview_projection(decision),
            Self::Unsupported => unsupported_projection(decision),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveModeBehavior {
    ObserveOnly,
    RecordOnly,
    Unsupported,
}

impl LiveModeBehavior {
    pub fn label(self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::RecordOnly => "record_only",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveCoveragePosture {
    ObserveOnlyPreview,
    RecordOnlyPreview,
    UnsupportedPreview,
}

impl LiveCoveragePosture {
    pub fn label(self) -> &'static str {
        match self {
            Self::ObserveOnlyPreview => "observe_only_preview",
            Self::RecordOnlyPreview => "record_only_preview",
            Self::UnsupportedPreview => "unsupported_preview",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalEligibility {
    NotRequired,
    AdvisoryOnly,
    RecordOnly,
    Unsupported,
}

impl ApprovalEligibility {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::AdvisoryOnly => "advisory_only",
            Self::RecordOnly => "record_only",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveFailurePosture {
    FailOpen,
    FailClosed,
}

impl LiveFailurePosture {
    pub fn label(self) -> &'static str {
        match self {
            Self::FailOpen => "fail_open",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveCoverageSupport {
    PreviewSupported,
    Unsupported,
}

impl LiveCoverageSupport {
    pub fn label(self) -> &'static str {
        match self {
            Self::PreviewSupported => "preview_supported",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveModeProjection {
    pub mode: LiveMode,
    pub mode_behavior: LiveModeBehavior,
    pub coverage_posture: LiveCoveragePosture,
    pub failure_posture: LiveFailurePosture,
    pub coverage_support: LiveCoverageSupport,
    pub coverage_summary: &'static str,
    pub mode_status: &'static str,
    pub record_status: &'static str,
    pub approval_eligibility: ApprovalEligibility,
    pub coverage_gap: &'static str,
    pub hold_reason: Option<&'static str>,
    pub wait_state: Option<&'static str>,
    pub status_reason: &'static str,
}

fn shadow_projection(decision: PolicyDecisionKind) -> LiveModeProjection {
    let (record_status, approval_eligibility, hold_reason, wait_state, status_reason) =
        match decision {
            PolicyDecisionKind::Allow => (
                "shadow_allow_recorded",
                ApprovalEligibility::NotRequired,
                None,
                None,
                "shadow mode observed an allow decision without any inline runtime intervention",
            ),
            PolicyDecisionKind::Deny => (
                "shadow_deny_recorded",
                ApprovalEligibility::NotRequired,
                None,
                None,
                "shadow mode observed a deny decision but does not attempt inline blocking",
            ),
            PolicyDecisionKind::RequireApproval => (
                "shadow_require_approval_recorded",
                ApprovalEligibility::AdvisoryOnly,
                Some(
                    "shadow mode is observe-only and records approval intent as an advisory signal without creating approval queue state",
                ),
                Some("shadow_observe_only"),
                "shadow mode observed a require_approval decision but does not create approval queue state or inline holds",
            ),
        };

    LiveModeProjection {
        mode: LiveMode::Shadow,
        mode_behavior: LiveModeBehavior::ObserveOnly,
        coverage_posture: LiveCoveragePosture::ObserveOnlyPreview,
        failure_posture: LiveFailurePosture::FailOpen,
        coverage_support: LiveCoverageSupport::PreviewSupported,
        coverage_summary: "preview-supported observe-only path; policy intent is recorded but the live request remains fail-open",
        mode_status: "shadow_observe_only",
        record_status,
        approval_eligibility,
        coverage_gap: "shadow_mode_has_no_inline_hold_deny_or_resume",
        hold_reason,
        wait_state,
        status_reason,
    }
}

fn enforce_preview_projection(decision: PolicyDecisionKind) -> LiveModeProjection {
    let (record_status, approval_eligibility, hold_reason, wait_state, status_reason) =
        match decision {
            PolicyDecisionKind::Allow => (
                "enforce_preview_allow_recorded",
                ApprovalEligibility::NotRequired,
                None,
                None,
                "enforce-preview mode recorded an allow result but still has no inline runtime intervention",
            ),
            PolicyDecisionKind::Deny => (
                "enforce_preview_deny_recorded",
                ApprovalEligibility::NotRequired,
                None,
                None,
                "enforce-preview mode recorded a deny result but cannot block the in-flight provider request yet",
            ),
            PolicyDecisionKind::RequireApproval => (
                "enforce_preview_approval_request_recorded",
                ApprovalEligibility::RecordOnly,
                Some(
                    "enforce-preview mode can record approval intent but cannot pause or resume the in-flight provider request yet",
                ),
                Some("pending_approval_record_only"),
                "enforce-preview mode recorded approval intent but cannot pause or resume the in-flight provider request yet",
            ),
        };

    LiveModeProjection {
        mode: LiveMode::EnforcePreview,
        mode_behavior: LiveModeBehavior::RecordOnly,
        coverage_posture: LiveCoveragePosture::RecordOnlyPreview,
        failure_posture: LiveFailurePosture::FailOpen,
        coverage_support: LiveCoverageSupport::PreviewSupported,
        coverage_summary: "preview-supported record-only path; approval or deny intent is reflected locally but the live request remains fail-open",
        mode_status: "enforce_preview_record_only",
        record_status,
        approval_eligibility,
        coverage_gap: "enforce_preview_has_no_inline_hold_deny_or_resume",
        hold_reason,
        wait_state,
        status_reason,
    }
}

fn unsupported_projection(decision: PolicyDecisionKind) -> LiveModeProjection {
    let (record_status, approval_eligibility, hold_reason, wait_state, status_reason) =
        match decision {
            PolicyDecisionKind::Allow => (
                "unsupported_allow_recorded",
                ApprovalEligibility::NotRequired,
                None,
                None,
                "unsupported mode recorded an allow signal for diagnostics only because no supported live preview contract exists",
            ),
            PolicyDecisionKind::Deny => (
                "unsupported_deny_recorded",
                ApprovalEligibility::NotRequired,
                None,
                None,
                "unsupported mode recorded a deny signal for diagnostics only because no supported live preview contract exists",
            ),
            PolicyDecisionKind::RequireApproval => (
                "unsupported_require_approval_recorded",
                ApprovalEligibility::Unsupported,
                Some(
                    "unsupported mode records approval-like policy signals for diagnostics only and does not create approval requests",
                ),
                Some("unsupported_mode_no_approval_path"),
                "unsupported mode recorded a require_approval signal for diagnostics only because no supported live preview contract exists",
            ),
        };

    LiveModeProjection {
        mode: LiveMode::Unsupported,
        mode_behavior: LiveModeBehavior::Unsupported,
        coverage_posture: LiveCoveragePosture::UnsupportedPreview,
        failure_posture: LiveFailurePosture::FailOpen,
        coverage_support: LiveCoverageSupport::Unsupported,
        coverage_summary: "unsupported live preview path; policy signals are diagnostic only and the live request remains fail-open",
        mode_status: "unsupported_preview_only",
        record_status,
        approval_eligibility,
        coverage_gap: "unsupported_mode_has_no_supported_live_preview_contract",
        hold_reason,
        wait_state,
        status_reason,
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, ResultInfo,
        ResultStatus, SessionRef, SourceInfo,
    };
    use serde_json::json;

    use super::{
        ApprovalEligibility, LiveCoveragePosture, LiveCoverageSupport, LiveFailurePosture, LiveMode,
    };

    #[test]
    fn mode_projection_separates_shadow_enforce_preview_and_unsupported_behaviors() {
        let shadow = LiveMode::Shadow.project(agenta_core::PolicyDecisionKind::RequireApproval);
        let enforce =
            LiveMode::EnforcePreview.project(agenta_core::PolicyDecisionKind::RequireApproval);
        let unsupported =
            LiveMode::Unsupported.project(agenta_core::PolicyDecisionKind::RequireApproval);

        assert_eq!(
            shadow.coverage_posture,
            LiveCoveragePosture::ObserveOnlyPreview
        );
        assert_eq!(
            shadow.approval_eligibility,
            ApprovalEligibility::AdvisoryOnly
        );
        assert_eq!(shadow.failure_posture, LiveFailurePosture::FailOpen);
        assert_eq!(
            shadow.coverage_support,
            LiveCoverageSupport::PreviewSupported
        );
        assert!(shadow.coverage_summary.contains("fail-open"));
        assert_eq!(shadow.wait_state, Some("shadow_observe_only"));

        assert_eq!(
            enforce.coverage_posture,
            LiveCoveragePosture::RecordOnlyPreview
        );
        assert_eq!(
            enforce.approval_eligibility,
            ApprovalEligibility::RecordOnly
        );
        assert_eq!(enforce.failure_posture, LiveFailurePosture::FailOpen);
        assert_eq!(
            enforce.coverage_support,
            LiveCoverageSupport::PreviewSupported
        );
        assert!(enforce.coverage_summary.contains("record-only"));
        assert_eq!(enforce.wait_state, Some("pending_approval_record_only"));

        assert_eq!(
            unsupported.coverage_posture,
            LiveCoveragePosture::UnsupportedPreview
        );
        assert_eq!(
            unsupported.approval_eligibility,
            ApprovalEligibility::Unsupported
        );
        assert_eq!(unsupported.failure_posture, LiveFailurePosture::FailOpen);
        assert_eq!(
            unsupported.coverage_support,
            LiveCoverageSupport::Unsupported
        );
        assert!(
            unsupported
                .coverage_summary
                .contains("unsupported live preview path")
        );
        assert_eq!(
            unsupported.wait_state,
            Some("unsupported_mode_no_approval_path")
        );
    }

    #[test]
    fn mode_can_be_recovered_from_event_attributes() {
        let event = EventEnvelope::new(
            "evt_live_mode_projection".to_owned(),
            EventType::NetworkConnect,
            SessionRef {
                session_id: "sess_live_mode_projection".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("agent-auditor".to_owned()),
                policy_bundle_version: None,
                environment: None,
            },
            Actor {
                kind: ActorKind::System,
                id: Some("hostd".to_owned()),
                display_name: Some("hostd".to_owned()),
            },
            Action {
                class: ActionClass::Browser,
                verb: Some("preview".to_owned()),
                target: Some("example".to_owned()),
                attributes: [("mode".to_owned(), json!("enforce_preview"))]
                    .into_iter()
                    .collect(),
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: None,
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some("hostd".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        );

        assert_eq!(LiveMode::from_event(&event), LiveMode::EnforcePreview);
    }
}
