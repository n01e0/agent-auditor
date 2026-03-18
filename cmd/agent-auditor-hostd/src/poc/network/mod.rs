pub mod classify;
pub mod contract;
pub mod emit;
pub mod observe;

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
    use super::{NetworkPocPlan, contract::NetworkCollector};

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
            ]
        );
        assert_eq!(plan.observe.handoff().raw_connect_kinds, vec!["connect"]);
        assert_eq!(
            plan.observe.handoff().address_families,
            vec!["inet", "inet6"]
        );
        assert_eq!(plan.classify.handoff().emitted_verbs, vec!["connect"]);
    }
}
