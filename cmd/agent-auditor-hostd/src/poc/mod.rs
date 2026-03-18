pub mod contract;
pub mod event_path;
pub mod filesystem;
pub mod loader;
pub mod network;
pub mod secret;

use self::{
    event_path::EventPathPlan, filesystem::FilesystemPocPlan, loader::LoaderPlan,
    network::NetworkPocPlan, secret::SecretAccessPocPlan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostdPocPlan {
    pub loader: LoaderPlan,
    pub event_path: EventPathPlan,
    pub filesystem: FilesystemPocPlan,
    pub network: NetworkPocPlan,
    pub secret: SecretAccessPocPlan,
}

impl HostdPocPlan {
    pub fn bootstrap() -> Self {
        let loader = LoaderPlan::default();
        let event_path = EventPathPlan::from_loader_boundary(loader.handoff());
        let filesystem = FilesystemPocPlan::bootstrap();
        let network = NetworkPocPlan::bootstrap();
        let secret = SecretAccessPocPlan::bootstrap();

        Self {
            loader,
            event_path,
            filesystem,
            network,
            secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HostdPocPlan, contract::EventTransport};
    use crate::poc::secret::contract::SecretSignalSource;

    #[test]
    fn bootstrap_plan_keeps_loader_and_event_path_responsibilities_separate() {
        let plan = HostdPocPlan::bootstrap();

        assert!(
            plan.loader
                .responsibilities
                .iter()
                .any(|item| item.contains("load the eBPF object"))
        );
        assert!(
            plan.loader
                .responsibilities
                .iter()
                .all(|item| !item.contains("normalize"))
        );
        assert!(
            plan.event_path
                .responsibilities
                .iter()
                .any(|item| item.contains("normalize records"))
        );
        assert!(
            plan.event_path
                .responsibilities
                .iter()
                .all(|item| !item.contains("attach kernel hooks"))
        );
    }

    #[test]
    fn bootstrap_plan_carries_the_loader_transport_into_event_path() {
        let plan = HostdPocPlan::bootstrap();

        assert_eq!(plan.loader.handoff().transport, EventTransport::RingBuffer);
        assert_eq!(plan.event_path.transport, EventTransport::RingBuffer);
        assert_eq!(plan.event_path.raw_event_types, vec!["exec", "exit"]);
    }

    #[test]
    fn bootstrap_plan_includes_secret_access_pipeline() {
        let plan = HostdPocPlan::bootstrap();

        assert_eq!(
            plan.secret.classify.sources,
            vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter
            ]
        );
        assert_eq!(
            plan.secret.record.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
    }
}
