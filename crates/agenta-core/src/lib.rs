use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type JsonMap = BTreeMap<String, Value>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    SessionLifecycle,
    ProcessExec,
    ProcessExit,
    FilesystemAccess,
    NetworkConnect,
    SecretAccess,
    PolicyDecision,
    ApprovalRequested,
    ApprovalResolved,
    AlertRaised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Agent,
    Human,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    Process,
    Filesystem,
    Network,
    Secret,
    Approval,
    Session,
    Alert,
    Browser,
    Gws,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Observed,
    Allowed,
    Denied,
    ApprovalRequired,
    Approved,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorKind {
    Ebpf,
    Fanotify,
    RuntimeHint,
    ControlPlane,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    SingleAction,
    EquivalentActionTtl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Starting,
    Running,
    WaitingApproval,
    Completed,
    Failed,
    Killed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Openclaw,
    Custom,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntime {
    Docker,
    Kubernetes,
    Podman,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    None,
    Observe,
    Enforce,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRef {
    pub session_id: String,
    pub agent_id: Option<String>,
    pub initiator_id: Option<String>,
    pub workspace_id: Option<String>,
    pub policy_bundle_version: Option<String>,
    pub environment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub class: ActionClass,
    pub verb: Option<String>,
    pub target: Option<String>,
    #[serde(default)]
    pub attributes: JsonMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultInfo {
    pub status: ResultStatus,
    pub reason: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub decision: Option<PolicyDecisionKind>,
    pub rule_id: Option<String>,
    pub severity: Option<Severity>,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub collector: CollectorKind,
    pub host_id: Option<String>,
    pub container_id: Option<String>,
    pub pod_uid: Option<String>,
    pub pid: Option<i32>,
    pub ppid: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityInfo {
    pub hash: Option<String>,
    pub prev_hash: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub session: SessionRef,
    pub actor: Actor,
    pub action: Action,
    pub result: ResultInfo,
    pub policy: Option<PolicyMetadata>,
    pub source: SourceInfo,
    pub integrity: Option<IntegrityInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRuntime {
    pub kind: RuntimeKind,
    pub version: Option<String>,
    pub session_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPlacement {
    pub host_id: Option<String>,
    pub container_id: Option<String>,
    pub container_runtime: Option<ContainerRuntime>,
    pub pod_uid: Option<String>,
    pub namespace: Option<String>,
    pub cgroup_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionWorkspace {
    pub workspace_id: Option<String>,
    pub path: Option<String>,
    pub repo: Option<String>,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCoverage {
    pub process: Option<CoverageLevel>,
    pub filesystem: Option<CoverageLevel>,
    pub network: Option<CoverageLevel>,
    pub secret: Option<CoverageLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub agent_id: String,
    pub initiator_id: Option<String>,
    pub display_name: Option<String>,
    pub status: SessionStatus,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub workspace: Option<SessionWorkspace>,
    pub runtime: SessionRuntime,
    pub placement: Option<SessionPlacement>,
    pub policy_bundle_version: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub risk_tier: Option<Severity>,
    pub coverage: Option<SessionCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub rule_id: String,
    pub severity: Option<Severity>,
    pub reason: Option<String>,
    pub scope: Option<ApprovalScope>,
    pub ttl_seconds: Option<u32>,
    pub reviewer_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequestAction {
    pub action_class: ActionClass,
    pub action_verb: String,
    pub target: Option<String>,
    pub summary: Option<String>,
    #[serde(default)]
    pub attributes: JsonMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequesterContext {
    pub agent_reason: Option<String>,
    pub human_request: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecisionRecord {
    pub reviewer_id: Option<String>,
    pub reviewer_note: Option<String>,
    pub outcome: Option<ApprovalStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub status: ApprovalStatus,
    pub requested_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub session_id: String,
    pub event_id: Option<String>,
    pub request: ApprovalRequestAction,
    pub policy: ApprovalPolicy,
    pub requester_context: Option<RequesterContext>,
    pub decision: Option<ApprovalDecisionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: PolicyDecisionKind,
    pub rule_id: Option<String>,
    pub severity: Option<Severity>,
    pub reason: Option<String>,
    pub approval: Option<ApprovalConstraint>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalConstraint {
    pub scope: Option<ApprovalScope>,
    pub ttl_seconds: Option<u32>,
    pub reviewer_hint: Option<String>,
}

impl EventEnvelope {
    pub fn new(
        event_id: impl Into<String>,
        event_type: EventType,
        session: SessionRef,
        actor: Actor,
        action: Action,
        result: ResultInfo,
        source: SourceInfo,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            timestamp: Utc::now(),
            event_type,
            session,
            actor,
            action,
            result,
            policy: None,
            source,
            integrity: None,
        }
    }
}

impl SessionRecord {
    pub fn placeholder(agent_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            agent_id: agent_id.into(),
            initiator_id: None,
            display_name: Some("placeholder session".to_owned()),
            status: SessionStatus::Starting,
            started_at: Utc::now(),
            ended_at: None,
            workspace: None,
            runtime: SessionRuntime {
                kind: RuntimeKind::Openclaw,
                version: None,
                session_key: None,
            },
            placement: None,
            policy_bundle_version: None,
            labels: vec!["bootstrap".to_owned()],
            risk_tier: Some(Severity::Medium),
            coverage: Some(SessionCoverage {
                process: Some(CoverageLevel::Observe),
                filesystem: Some(CoverageLevel::Observe),
                network: Some(CoverageLevel::Observe),
                secret: Some(CoverageLevel::Partial),
            }),
        }
    }
}
