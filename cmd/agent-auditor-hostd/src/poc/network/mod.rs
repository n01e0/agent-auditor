pub mod classify;
pub mod contract;
pub mod emit;
pub mod observe;
pub mod persist;

use self::{classify::ClassifyPlan, emit::EmitPlan, observe::ObservePlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPocPlan {
    pub observe: ObservePlan,
    pub classify: ClassifyPlan,
    pub emit: EmitPlan,
}

impl NetworkPocPlan {
    pub fn bootstrap() -> Self {
        let observe = ObservePlan::default();
        let classify = ClassifyPlan::from_observe_boundary(observe.handoff());
        let emit = EmitPlan::from_classification_boundary(classify.handoff());

        Self {
            observe,
            classify,
            emit,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::{
        ActionClass, ApprovalScope, ApprovalStatus, CollectorKind, PolicyDecisionKind,
        ResultStatus, SessionRecord, Severity,
    };
    use agenta_policy::{
        PolicyCoverageContext, PolicyEvaluator, PolicyInput, RegoPolicyEvaluator,
        apply_decision_to_event, approval_request_from_decision,
    };

    use super::{
        NetworkPocPlan,
        contract::{ClassifiedNetworkConnect, DestinationScope, NetworkCollector},
        observe::{AddressFamily, ConnectEvent, TransportProtocol},
        persist::NetworkPocStore,
    };

    #[test]
    fn bootstrap_plan_keeps_observe_classify_and_emit_responsibilities_separate() {
        let plan = NetworkPocPlan::bootstrap();

        assert!(
            plan.observe
                .responsibilities
                .iter()
                .any(|item| item.contains("kernel-facing lifecycle"))
        );
        assert!(
            plan.observe
                .responsibilities
                .iter()
                .all(|item| !item.contains("domain attribution"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .any(|item| item.contains("domain attribution"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .all(|item| !item.contains("control-plane sinks"))
        );
        assert!(
            plan.emit
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-core event shapes"))
        );
        assert!(
            plan.emit
                .responsibilities
                .iter()
                .all(|item| !item.contains("socket-connect tuples"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_ebpf_contracts_across_the_pipeline() {
        let plan = NetworkPocPlan::bootstrap();

        assert_eq!(plan.observe.collector, NetworkCollector::Ebpf);
        assert_eq!(plan.classify.collector, NetworkCollector::Ebpf);
        assert_eq!(plan.emit.collector, NetworkCollector::Ebpf);
        assert_eq!(
            plan.classify.input_fields,
            vec![
                "pid",
                "sock_fd",
                "address_family",
                "transport",
                "destination_addr",
                "destination_port",
            ]
        );
        assert_eq!(
            plan.emit.semantic_fields,
            vec![
                "destination_ip",
                "destination_port",
                "transport",
                "address_family",
                "destination_scope",
                "domain_candidate",
                "domain_attribution_source",
            ]
        );
        assert_eq!(plan.observe.handoff().raw_connect_kinds, vec!["connect"]);
        assert_eq!(
            plan.observe.handoff().address_families,
            vec!["inet", "inet6"]
        );
        assert_eq!(plan.classify.handoff().emitted_verbs, vec!["connect"]);
    }

    #[test]
    fn ebpf_pipeline_evaluates_destination_policy_for_normalized_connects() {
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = NetworkPocPlan::bootstrap();
        let delivered = plan
            .observe
            .preview_connect_delivery()
            .expect("fixture connect delivery should succeed");
        let classified = plan.classify.classify_connect(&delivered.event);
        let event = plan
            .emit
            .normalize_classified_connect(&classified, &session);
        let input = PolicyInput::from_event(&event);

        assert_eq!(event.source.collector, CollectorKind::Ebpf);
        assert_eq!(
            input.context.coverage,
            Some(PolicyCoverageContext {
                collector: Some("ebpf".to_owned()),
                enforce_capable: false,
            })
        );

        let decision = RegoPolicyEvaluator::network_destination_example()
            .evaluate(&input)
            .expect("network rego should evaluate");
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("net.public.allowlisted_tls_domain")
        );
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(
            decision.reason.as_deref(),
            Some("allowlisted public TLS destination")
        );
        assert_eq!(enriched.result.status, ResultStatus::Allowed);
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::Allow)
        );
        assert!(approval_request_from_decision(&enriched, &decision).is_none());
    }

    #[test]
    fn allow_decision_is_reflected_in_network_event_metadata() {
        let (event, decision, approval_request) = preview_network_policy(sample_allowlisted_tls());
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(enriched.result.status, ResultStatus::Allowed);
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::Allow)
        );
        assert!(approval_request.is_none());
    }

    #[test]
    fn require_approval_decision_is_reflected_in_network_event_metadata() {
        let (event, decision, approval_request) =
            preview_network_policy(sample_public_unknown_destination());
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::RequireApproval)
        );
        assert!(approval_request.is_some());
    }

    #[test]
    fn require_approval_pipeline_generates_pending_network_approval_request() {
        let (observed, enriched, decision, approval_request) = preview_network_policy_from_connect(
            sample_connect_event(Ipv4Addr::new(203, 0, 113, 10), 443, 5252, 8),
        );
        let request = approval_request.expect("require_approval should yield approval request");

        assert_eq!(observed.result.status, ResultStatus::Observed);
        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            enriched
                .policy
                .as_ref()
                .and_then(|policy| policy.rule_id.as_deref()),
            Some("net.public.unallowlisted.requires_approval")
        );
        assert_eq!(request.approval_id, "apr_poc_network_connect_5252_8_tcp");
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(
            request.event_id.as_deref(),
            Some("poc_network_connect_5252_8_tcp")
        );
        assert_eq!(request.request.action_class, ActionClass::Network);
        assert_eq!(request.request.action_verb, "connect");
        assert_eq!(request.request.target.as_deref(), Some("203.0.113.10:443"));
        assert_eq!(
            request.request.summary.as_deref(),
            Some("public destination without allowlisted domain requires approval")
        );
        assert_eq!(
            request.policy.rule_id,
            "net.public.unallowlisted.requires_approval"
        );
        assert_eq!(request.policy.scope, Some(ApprovalScope::SingleAction));
        assert_eq!(request.policy.ttl_seconds, Some(900));
        assert_eq!(
            request.policy.reviewer_hint.as_deref(),
            Some("security-oncall")
        );
        assert_eq!(
            request
                .requester_context
                .as_ref()
                .and_then(|context| context.agent_reason.as_deref()),
            Some("public destination without allowlisted domain requires approval")
        );
        assert!(request.expires_at.is_some());
    }

    #[test]
    fn require_approval_network_audit_record_persists_enriched_policy_metadata() {
        let (_, enriched, decision, approval_request) = preview_network_policy_from_connect(
            sample_connect_event(Ipv4Addr::new(203, 0, 113, 10), 443, 5252, 8),
        );
        let store = NetworkPocStore::fresh(unique_test_root()).expect("store should init");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert!(approval_request.is_some());

        store
            .append_audit_record(&enriched)
            .expect("approval-required audit record should append");

        let persisted = store
            .latest_audit_record()
            .expect("approval-required audit record should read")
            .expect("approval-required audit record should exist");

        assert_eq!(persisted, enriched);
        assert_eq!(persisted.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            persisted.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::RequireApproval)
        );
        assert_eq!(
            persisted
                .policy
                .as_ref()
                .and_then(|policy| policy.rule_id.as_deref()),
            Some("net.public.unallowlisted.requires_approval")
        );
    }

    #[test]
    fn deny_decision_is_reflected_in_network_event_metadata() {
        let (event, decision, approval_request) = preview_network_policy(sample_denied_smtp());
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(enriched.result.status, ResultStatus::Denied);
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::Deny)
        );
        assert!(approval_request.is_none());
    }

    fn preview_network_policy(
        classified: ClassifiedNetworkConnect,
    ) -> (
        agenta_core::EventEnvelope,
        agenta_core::PolicyDecision,
        Option<agenta_core::ApprovalRequest>,
    ) {
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = NetworkPocPlan::bootstrap();
        let event = plan
            .emit
            .normalize_classified_connect(&classified, &session);
        let decision = RegoPolicyEvaluator::network_destination_example()
            .evaluate(&PolicyInput::from_event(&event))
            .expect("network rego should evaluate");
        let approval_request = approval_request_from_decision(&event, &decision);

        (event, decision, approval_request)
    }

    fn preview_network_policy_from_connect(
        connect: ConnectEvent,
    ) -> (
        agenta_core::EventEnvelope,
        agenta_core::EventEnvelope,
        agenta_core::PolicyDecision,
        Option<agenta_core::ApprovalRequest>,
    ) {
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = NetworkPocPlan::bootstrap();
        let classified = plan.classify.classify_connect(&connect);
        let observed = plan
            .emit
            .normalize_classified_connect(&classified, &session);
        let decision = RegoPolicyEvaluator::network_destination_example()
            .evaluate(&PolicyInput::from_event(&observed))
            .expect("network rego should evaluate");
        let enriched = apply_decision_to_event(&observed, &decision);
        let approval_request = approval_request_from_decision(&enriched, &decision);

        (observed, enriched, decision, approval_request)
    }

    fn sample_allowlisted_tls() -> ClassifiedNetworkConnect {
        ClassifiedNetworkConnect {
            pid: 4242,
            sock_fd: 7,
            destination_ip: "93.184.216.34".to_owned(),
            destination_port: 443,
            transport: "tcp".to_owned(),
            address_family: "inet".to_owned(),
            destination_scope: DestinationScope::Public,
            domain_candidate: Some("example.com".to_owned()),
            domain_attribution_source: Some("dns_answer_cache_exact_ip".to_owned()),
        }
    }

    fn sample_public_unknown_destination() -> ClassifiedNetworkConnect {
        ClassifiedNetworkConnect {
            pid: 5252,
            sock_fd: 8,
            destination_ip: "203.0.113.10".to_owned(),
            destination_port: 443,
            transport: "tcp".to_owned(),
            address_family: "inet".to_owned(),
            destination_scope: DestinationScope::Public,
            domain_candidate: None,
            domain_attribution_source: None,
        }
    }

    fn sample_denied_smtp() -> ClassifiedNetworkConnect {
        ClassifiedNetworkConnect {
            pid: 6262,
            sock_fd: 9,
            destination_ip: "198.51.100.25".to_owned(),
            destination_port: 25,
            transport: "tcp".to_owned(),
            address_family: "inet".to_owned(),
            destination_scope: DestinationScope::Public,
            domain_candidate: None,
            domain_attribution_source: None,
        }
    }

    fn sample_connect_event(
        destination_ip: Ipv4Addr,
        destination_port: u16,
        pid: u32,
        sock_fd: u32,
    ) -> ConnectEvent {
        ConnectEvent {
            pid,
            sock_fd,
            address_family: AddressFamily::Inet,
            transport: TransportProtocol::Tcp,
            destination: SocketAddr::new(IpAddr::V4(destination_ip), destination_port),
        }
    }

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!("agent-auditor-hostd-network-mod-test-{nonce}"))
    }
}
