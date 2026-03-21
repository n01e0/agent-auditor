use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{ActionClass, ApprovalRequest, ApprovalScope, ApprovalStatus, JsonMap, Severity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecisionSummary {
    pub action_summary: String,
    pub target_hint: Option<String>,
    pub severity: Option<Severity>,
    pub policy_reason: Option<String>,
    pub scope: Option<ApprovalScope>,
    pub ttl_seconds: Option<u32>,
    pub reviewer_hint: Option<String>,
}

impl ApprovalDecisionSummary {
    pub fn from_request(request: &ApprovalRequest) -> Self {
        Self {
            action_summary: action_summary_for_request(request),
            target_hint: request.request.target.clone(),
            severity: request.policy.severity,
            policy_reason: request.policy.reason.clone(),
            scope: request.policy.scope,
            ttl_seconds: request.policy.ttl_seconds,
            reviewer_hint: request.policy.reviewer_hint.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRationaleCapture {
    pub policy_reason: Option<String>,
    pub agent_reason: Option<String>,
    pub human_request: Option<String>,
    pub reviewer_id: Option<String>,
    pub reviewer_note: Option<String>,
    pub outcome: Option<ApprovalStatus>,
}

impl ApprovalRationaleCapture {
    pub fn from_request(request: &ApprovalRequest) -> Self {
        Self {
            policy_reason: request.policy.reason.clone(),
            agent_reason: request
                .requester_context
                .as_ref()
                .and_then(|context| context.agent_reason.clone()),
            human_request: request
                .requester_context
                .as_ref()
                .and_then(|context| context.human_request.clone()),
            reviewer_id: request
                .decision
                .as_ref()
                .and_then(|decision| decision.reviewer_id.clone()),
            reviewer_note: request
                .decision
                .as_ref()
                .and_then(|decision| decision.reviewer_note.clone()),
            outcome: request
                .decision
                .as_ref()
                .and_then(|decision| decision.outcome),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalQueueItem {
    pub approval_id: String,
    pub status: ApprovalStatus,
    pub requested_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub session_id: String,
    pub event_id: Option<String>,
    pub action_class: ActionClass,
    pub action_verb: String,
    pub target: Option<String>,
    #[serde(default)]
    pub attributes: JsonMap,
    pub decision_summary: ApprovalDecisionSummary,
    pub rationale_capture: ApprovalRationaleCapture,
}

impl ApprovalQueueItem {
    pub fn from_request(request: &ApprovalRequest) -> Self {
        Self {
            approval_id: request.approval_id.clone(),
            status: request.status,
            requested_at: request.requested_at,
            resolved_at: request.resolved_at,
            expires_at: request.expires_at,
            session_id: request.session_id.clone(),
            event_id: request.event_id.clone(),
            action_class: request.request.action_class,
            action_verb: request.request.action_verb.clone(),
            target: request.request.target.clone(),
            attributes: request.request.attributes.clone(),
            decision_summary: ApprovalDecisionSummary::from_request(request),
            rationale_capture: ApprovalRationaleCapture::from_request(request),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalOpsSignals {
    pub stale: bool,
    pub audit_record_present: bool,
    pub decision_record_present: bool,
    pub downstream_completion_recorded: bool,
    pub requires_merge_follow_up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalQueueFreshness {
    Fresh,
    Stale,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalQueueDrift {
    InSync,
    MissingAuditRecord,
    MissingDecisionRecord,
    MissingDownstreamCompletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRecoveryAction {
    NoneNeeded,
    RefreshQueueProjection,
    ReplayFromAudit,
    AwaitDownstreamCompletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalWaitingState {
    ReviewerDecision,
    DownstreamCompletion,
    WaitingMerge,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalOpsHardeningStatus {
    pub freshness: ApprovalQueueFreshness,
    pub drift: ApprovalQueueDrift,
    pub recovery: ApprovalRecoveryAction,
    pub waiting: ApprovalWaitingState,
}

impl ApprovalOpsHardeningStatus {
    pub fn derive(queue_item: &ApprovalQueueItem, signals: &ApprovalOpsSignals) -> Self {
        let freshness = if queue_item.status == ApprovalStatus::Expired {
            ApprovalQueueFreshness::Expired
        } else if signals.stale {
            ApprovalQueueFreshness::Stale
        } else {
            ApprovalQueueFreshness::Fresh
        };

        let drift = if !signals.audit_record_present {
            ApprovalQueueDrift::MissingAuditRecord
        } else if queue_item.rationale_capture.outcome.is_some() && !signals.decision_record_present
        {
            ApprovalQueueDrift::MissingDecisionRecord
        } else if queue_item.status == ApprovalStatus::Approved
            && !signals.downstream_completion_recorded
        {
            ApprovalQueueDrift::MissingDownstreamCompletion
        } else {
            ApprovalQueueDrift::InSync
        };

        let waiting = match queue_item.status {
            ApprovalStatus::Pending => ApprovalWaitingState::ReviewerDecision,
            ApprovalStatus::Approved if signals.requires_merge_follow_up => {
                ApprovalWaitingState::WaitingMerge
            }
            ApprovalStatus::Approved if !signals.downstream_completion_recorded => {
                ApprovalWaitingState::DownstreamCompletion
            }
            ApprovalStatus::Approved
            | ApprovalStatus::Rejected
            | ApprovalStatus::Expired
            | ApprovalStatus::Cancelled => ApprovalWaitingState::Resolved,
        };

        let recovery = match drift {
            ApprovalQueueDrift::MissingAuditRecord | ApprovalQueueDrift::MissingDecisionRecord => {
                ApprovalRecoveryAction::ReplayFromAudit
            }
            ApprovalQueueDrift::MissingDownstreamCompletion => {
                ApprovalRecoveryAction::AwaitDownstreamCompletion
            }
            ApprovalQueueDrift::InSync => match waiting {
                ApprovalWaitingState::WaitingMerge | ApprovalWaitingState::DownstreamCompletion => {
                    ApprovalRecoveryAction::AwaitDownstreamCompletion
                }
                ApprovalWaitingState::ReviewerDecision
                    if freshness == ApprovalQueueFreshness::Stale =>
                {
                    ApprovalRecoveryAction::RefreshQueueProjection
                }
                ApprovalWaitingState::ReviewerDecision | ApprovalWaitingState::Resolved => {
                    ApprovalRecoveryAction::NoneNeeded
                }
            },
        };

        Self {
            freshness,
            drift,
            recovery,
            waiting,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatusKind {
    PendingReview,
    StaleQueue,
    Drifted,
    WaitingDownstream,
    WaitingMerge,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalStatusSummary {
    pub kind: ApprovalStatusKind,
    pub headline: String,
    pub detail: String,
    pub actionable: bool,
}

impl ApprovalStatusSummary {
    pub fn derive(queue_item: &ApprovalQueueItem, ops_status: &ApprovalOpsHardeningStatus) -> Self {
        match ops_status.drift {
            ApprovalQueueDrift::MissingAuditRecord => Self {
                kind: ApprovalStatusKind::Drifted,
                headline: "Approval queue drift detected".to_owned(),
                detail: format!(
                    "{} is missing durable audit evidence and should be replayed from audit",
                    queue_item.approval_id
                ),
                actionable: false,
            },
            ApprovalQueueDrift::MissingDecisionRecord => Self {
                kind: ApprovalStatusKind::Drifted,
                headline: "Approval decision drift detected".to_owned(),
                detail: format!(
                    "{} has a reviewer outcome but is missing the durable decision record",
                    queue_item.approval_id
                ),
                actionable: false,
            },
            ApprovalQueueDrift::MissingDownstreamCompletion => match ops_status.waiting {
                ApprovalWaitingState::WaitingMerge => Self {
                    kind: ApprovalStatusKind::WaitingMerge,
                    headline: "Approval is waiting for merge".to_owned(),
                    detail: format!(
                        "{} is approved but still waiting for merge-like completion",
                        queue_item.approval_id
                    ),
                    actionable: false,
                },
                _ => Self {
                    kind: ApprovalStatusKind::WaitingDownstream,
                    headline: "Approval is waiting for downstream completion".to_owned(),
                    detail: format!(
                        "{} is approved but the downstream completion signal is still missing",
                        queue_item.approval_id
                    ),
                    actionable: false,
                },
            },
            ApprovalQueueDrift::InSync => match ops_status.freshness {
                ApprovalQueueFreshness::Stale => Self {
                    kind: ApprovalStatusKind::StaleQueue,
                    headline: "Approval queue item is stale".to_owned(),
                    detail: format!(
                        "{} should be refreshed before a reviewer acts on it",
                        queue_item.approval_id
                    ),
                    actionable: false,
                },
                _ => match ops_status.waiting {
                    ApprovalWaitingState::ReviewerDecision => Self {
                        kind: ApprovalStatusKind::PendingReview,
                        headline: "Approval is waiting for reviewer decision".to_owned(),
                        detail: queue_item.decision_summary.action_summary.clone(),
                        actionable: true,
                    },
                    ApprovalWaitingState::DownstreamCompletion => Self {
                        kind: ApprovalStatusKind::WaitingDownstream,
                        headline: "Approval is waiting for downstream completion".to_owned(),
                        detail: format!(
                            "{} is approved and waiting for downstream completion",
                            queue_item.approval_id
                        ),
                        actionable: false,
                    },
                    ApprovalWaitingState::WaitingMerge => Self {
                        kind: ApprovalStatusKind::WaitingMerge,
                        headline: "Approval is waiting for merge".to_owned(),
                        detail: format!(
                            "{} is approved and waiting for merge-like completion",
                            queue_item.approval_id
                        ),
                        actionable: false,
                    },
                    ApprovalWaitingState::Resolved => Self {
                        kind: ApprovalStatusKind::Resolved,
                        headline: "Approval flow is resolved".to_owned(),
                        detail: format!(
                            "{} no longer requires reviewer or downstream action",
                            queue_item.approval_id
                        ),
                        actionable: false,
                    },
                },
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalNotificationClass {
    ReviewRequired,
    StaleQueueAlert,
    DriftAlert,
    WaitingMergeReminder,
    ResolutionUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalNotificationAudience {
    Reviewer,
    Ops,
    Requester,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalNotificationSummary {
    pub class: ApprovalNotificationClass,
    pub audience: ApprovalNotificationAudience,
    pub headline: String,
    pub status_line: String,
}

impl ApprovalNotificationSummary {
    pub fn derive(queue_item: &ApprovalQueueItem, status: &ApprovalStatusSummary) -> Self {
        match status.kind {
            ApprovalStatusKind::PendingReview => Self {
                class: ApprovalNotificationClass::ReviewRequired,
                audience: ApprovalNotificationAudience::Reviewer,
                headline: "Reviewer action required".to_owned(),
                status_line: format!(
                    "{} requires review: {}",
                    queue_item.approval_id, status.detail
                ),
            },
            ApprovalStatusKind::StaleQueue => Self {
                class: ApprovalNotificationClass::StaleQueueAlert,
                audience: ApprovalNotificationAudience::Ops,
                headline: "Approval queue item became stale".to_owned(),
                status_line: status.detail.clone(),
            },
            ApprovalStatusKind::Drifted => Self {
                class: ApprovalNotificationClass::DriftAlert,
                audience: ApprovalNotificationAudience::Ops,
                headline: "Approval reconciliation drift detected".to_owned(),
                status_line: status.detail.clone(),
            },
            ApprovalStatusKind::WaitingDownstream | ApprovalStatusKind::WaitingMerge => Self {
                class: ApprovalNotificationClass::WaitingMergeReminder,
                audience: ApprovalNotificationAudience::Requester,
                headline: "Approval is waiting on follow-up completion".to_owned(),
                status_line: status.detail.clone(),
            },
            ApprovalStatusKind::Resolved => Self {
                class: ApprovalNotificationClass::ResolutionUpdate,
                audience: ApprovalNotificationAudience::Requester,
                headline: "Approval flow resolved".to_owned(),
                status_line: status.detail.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalReconciliationState {
    InSync,
    NeedsQueueRefresh,
    NeedsAuditReplay,
    AwaitingCompletion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReconciliationSummary {
    pub state: ApprovalReconciliationState,
    pub note: String,
}

impl ApprovalReconciliationSummary {
    pub fn derive(queue_item: &ApprovalQueueItem, ops_status: &ApprovalOpsHardeningStatus) -> Self {
        match ops_status.recovery {
            ApprovalRecoveryAction::ReplayFromAudit => Self {
                state: ApprovalReconciliationState::NeedsAuditReplay,
                note: format!(
                    "{} should be rebuilt from durable approval/audit records",
                    queue_item.approval_id
                ),
            },
            ApprovalRecoveryAction::RefreshQueueProjection => Self {
                state: ApprovalReconciliationState::NeedsQueueRefresh,
                note: format!(
                    "{} should be refreshed from append-only inputs before review continues",
                    queue_item.approval_id
                ),
            },
            ApprovalRecoveryAction::AwaitDownstreamCompletion => Self {
                state: ApprovalReconciliationState::AwaitingCompletion,
                note: format!(
                    "{} is still waiting for downstream or merge-like completion",
                    queue_item.approval_id
                ),
            },
            ApprovalRecoveryAction::NoneNeeded => Self {
                state: ApprovalReconciliationState::InSync,
                note: format!(
                    "{} is consistent with the current control-plane view",
                    queue_item.approval_id
                ),
            },
        }
    }
}

fn action_summary_for_request(request: &ApprovalRequest) -> String {
    request
        .request
        .summary
        .clone()
        .or_else(|| {
            request
                .request
                .target
                .as_ref()
                .map(|target| format!("{} {}", request.request.action_verb, target))
        })
        .unwrap_or_else(|| request.request.action_verb.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApprovalDecisionRecord, ApprovalPolicy, ApprovalRequestAction, ApprovalStatus,
        RequesterContext,
    };
    use chrono::TimeZone;
    use serde_json::json;

    fn sample_request() -> ApprovalRequest {
        let mut attributes = JsonMap::new();
        attributes.insert("provider_id".to_owned(), json!("discord"));
        attributes.insert("action_family".to_owned(), json!("channel.invite"));

        ApprovalRequest {
            approval_id: "apr_controld_bootstrap".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: Utc
                .with_ymd_and_hms(2026, 3, 21, 19, 30, 0)
                .single()
                .expect("fixed timestamp should be valid"),
            resolved_at: None,
            expires_at: Some(
                Utc.with_ymd_and_hms(2026, 3, 21, 20, 0, 0)
                    .single()
                    .expect("fixed timestamp should be valid"),
            ),
            session_id: "sess_controld_bootstrap".to_owned(),
            event_id: Some("evt_msg_invite".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Browser,
                action_verb: "channel.invite".to_owned(),
                target: Some("discord://server/ops/thread/incident-room".to_owned()),
                summary: Some("Invite a new member into the incident thread".to_owned()),
                attributes,
            },
            policy: ApprovalPolicy {
                rule_id: "messaging.channel_invite.requires_approval".to_owned(),
                severity: Some(Severity::High),
                reason: Some("Messaging membership expansion requires approval".to_owned()),
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            requester_context: Some(RequesterContext {
                agent_reason: Some("Need to add the incident commander to the thread".to_owned()),
                human_request: Some("please bring ops into the live incident room".to_owned()),
            }),
            decision: Some(ApprovalDecisionRecord {
                reviewer_id: Some("user:security-oncall".to_owned()),
                reviewer_note: Some("approved for the ongoing sev1 incident".to_owned()),
                outcome: Some(ApprovalStatus::Approved),
            }),
            enforcement: None,
        }
    }

    #[test]
    fn decision_summary_uses_request_and_policy_fields() {
        let summary = ApprovalDecisionSummary::from_request(&sample_request());

        assert_eq!(
            summary.action_summary,
            "Invite a new member into the incident thread"
        );
        assert_eq!(
            summary.target_hint.as_deref(),
            Some("discord://server/ops/thread/incident-room")
        );
        assert_eq!(summary.severity, Some(Severity::High));
        assert_eq!(
            summary.policy_reason.as_deref(),
            Some("Messaging membership expansion requires approval")
        );
        assert_eq!(summary.scope, Some(ApprovalScope::SingleAction));
        assert_eq!(summary.ttl_seconds, Some(1800));
        assert_eq!(summary.reviewer_hint.as_deref(), Some("security-oncall"));
    }

    #[test]
    fn rationale_capture_collects_policy_requester_and_reviewer_context() {
        let rationale = ApprovalRationaleCapture::from_request(&sample_request());

        assert_eq!(
            rationale.policy_reason.as_deref(),
            Some("Messaging membership expansion requires approval")
        );
        assert_eq!(
            rationale.agent_reason.as_deref(),
            Some("Need to add the incident commander to the thread")
        );
        assert_eq!(
            rationale.human_request.as_deref(),
            Some("please bring ops into the live incident room")
        );
        assert_eq!(
            rationale.reviewer_id.as_deref(),
            Some("user:security-oncall")
        );
        assert_eq!(
            rationale.reviewer_note.as_deref(),
            Some("approved for the ongoing sev1 incident")
        );
        assert_eq!(rationale.outcome, Some(ApprovalStatus::Approved));
    }

    #[test]
    fn queue_item_preserves_redaction_safe_request_shape() {
        let queue_item = ApprovalQueueItem::from_request(&sample_request());

        assert_eq!(queue_item.approval_id, "apr_controld_bootstrap");
        assert_eq!(queue_item.status, ApprovalStatus::Pending);
        assert_eq!(queue_item.action_class, ActionClass::Browser);
        assert_eq!(queue_item.action_verb, "channel.invite");
        assert_eq!(
            queue_item.target.as_deref(),
            Some("discord://server/ops/thread/incident-room")
        );
        assert_eq!(
            queue_item.attributes.get("provider_id"),
            Some(&json!("discord"))
        );
        assert_eq!(
            queue_item.attributes.get("action_family"),
            Some(&json!("channel.invite"))
        );
        assert_eq!(
            queue_item.decision_summary.action_summary,
            "Invite a new member into the incident thread"
        );
        assert_eq!(
            queue_item.rationale_capture.outcome,
            Some(ApprovalStatus::Approved)
        );
    }

    #[test]
    fn queue_item_falls_back_to_verb_and_target_when_summary_is_missing() {
        let mut request = sample_request();
        request.request.summary = None;
        request.decision = None;

        let queue_item = ApprovalQueueItem::from_request(&request);

        assert_eq!(
            queue_item.decision_summary.action_summary,
            "channel.invite discord://server/ops/thread/incident-room"
        );
        assert!(queue_item.rationale_capture.reviewer_note.is_none());
        assert!(queue_item.rationale_capture.outcome.is_none());
    }

    #[test]
    fn ops_status_marks_stale_pending_queue_items_for_projection_refresh() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Pending;
        request.decision = None;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: true,
                audit_record_present: true,
                decision_record_present: false,
                downstream_completion_recorded: false,
                requires_merge_follow_up: false,
            },
        );

        assert_eq!(status.freshness, ApprovalQueueFreshness::Stale);
        assert_eq!(status.drift, ApprovalQueueDrift::InSync);
        assert_eq!(
            status.recovery,
            ApprovalRecoveryAction::RefreshQueueProjection
        );
        assert_eq!(status.waiting, ApprovalWaitingState::ReviewerDecision);
    }

    #[test]
    fn ops_status_marks_drift_when_audit_record_is_missing() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Pending;
        request.decision = None;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: false,
                audit_record_present: false,
                decision_record_present: false,
                downstream_completion_recorded: false,
                requires_merge_follow_up: false,
            },
        );

        assert_eq!(status.freshness, ApprovalQueueFreshness::Fresh);
        assert_eq!(status.drift, ApprovalQueueDrift::MissingAuditRecord);
        assert_eq!(status.recovery, ApprovalRecoveryAction::ReplayFromAudit);
        assert_eq!(status.waiting, ApprovalWaitingState::ReviewerDecision);
    }

    #[test]
    fn ops_status_treats_merge_follow_up_as_waiting_merge() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Approved;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: false,
                audit_record_present: true,
                decision_record_present: true,
                downstream_completion_recorded: false,
                requires_merge_follow_up: true,
            },
        );

        assert_eq!(status.freshness, ApprovalQueueFreshness::Fresh);
        assert_eq!(
            status.drift,
            ApprovalQueueDrift::MissingDownstreamCompletion
        );
        assert_eq!(
            status.recovery,
            ApprovalRecoveryAction::AwaitDownstreamCompletion
        );
        assert_eq!(status.waiting, ApprovalWaitingState::WaitingMerge);
    }

    #[test]
    fn ops_status_marks_resolved_items_as_in_sync_when_completion_is_recorded() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Rejected;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: false,
                audit_record_present: true,
                decision_record_present: true,
                downstream_completion_recorded: true,
                requires_merge_follow_up: false,
            },
        );

        assert_eq!(status.freshness, ApprovalQueueFreshness::Fresh);
        assert_eq!(status.drift, ApprovalQueueDrift::InSync);
        assert_eq!(status.recovery, ApprovalRecoveryAction::NoneNeeded);
        assert_eq!(status.waiting, ApprovalWaitingState::Resolved);
    }

    #[test]
    fn status_summary_marks_pending_review_as_actionable() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Pending;
        request.decision = None;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let ops_status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: false,
                audit_record_present: true,
                decision_record_present: false,
                downstream_completion_recorded: false,
                requires_merge_follow_up: false,
            },
        );
        let status = ApprovalStatusSummary::derive(&queue_item, &ops_status);

        assert_eq!(status.kind, ApprovalStatusKind::PendingReview);
        assert!(status.actionable);
        assert_eq!(
            status.detail,
            "Invite a new member into the incident thread"
        );
    }

    #[test]
    fn notification_summary_prioritizes_drift_alerts_for_ops() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Pending;
        request.decision = None;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let ops_status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: false,
                audit_record_present: false,
                decision_record_present: false,
                downstream_completion_recorded: false,
                requires_merge_follow_up: false,
            },
        );
        let status = ApprovalStatusSummary::derive(&queue_item, &ops_status);
        let notification = ApprovalNotificationSummary::derive(&queue_item, &status);

        assert_eq!(status.kind, ApprovalStatusKind::Drifted);
        assert_eq!(notification.class, ApprovalNotificationClass::DriftAlert);
        assert_eq!(notification.audience, ApprovalNotificationAudience::Ops);
        assert!(
            notification
                .status_line
                .contains("missing durable audit evidence")
        );
    }

    #[test]
    fn reconciliation_summary_maps_stale_pending_items_to_queue_refresh() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Pending;
        request.decision = None;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let ops_status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: true,
                audit_record_present: true,
                decision_record_present: false,
                downstream_completion_recorded: false,
                requires_merge_follow_up: false,
            },
        );
        let reconciliation = ApprovalReconciliationSummary::derive(&queue_item, &ops_status);

        assert_eq!(
            reconciliation.state,
            ApprovalReconciliationState::NeedsQueueRefresh
        );
        assert!(
            reconciliation
                .note
                .contains("refreshed from append-only inputs")
        );
    }

    #[test]
    fn waiting_merge_status_surfaces_requester_notification_and_completion_wait() {
        let mut request = sample_request();
        request.status = ApprovalStatus::Approved;

        let queue_item = ApprovalQueueItem::from_request(&request);
        let ops_status = ApprovalOpsHardeningStatus::derive(
            &queue_item,
            &ApprovalOpsSignals {
                stale: false,
                audit_record_present: true,
                decision_record_present: true,
                downstream_completion_recorded: false,
                requires_merge_follow_up: true,
            },
        );
        let status = ApprovalStatusSummary::derive(&queue_item, &ops_status);
        let notification = ApprovalNotificationSummary::derive(&queue_item, &status);
        let reconciliation = ApprovalReconciliationSummary::derive(&queue_item, &ops_status);

        assert_eq!(status.kind, ApprovalStatusKind::WaitingMerge);
        assert_eq!(
            notification.class,
            ApprovalNotificationClass::WaitingMergeReminder
        );
        assert_eq!(
            notification.audience,
            ApprovalNotificationAudience::Requester
        );
        assert_eq!(
            reconciliation.state,
            ApprovalReconciliationState::AwaitingCompletion
        );
    }
}
