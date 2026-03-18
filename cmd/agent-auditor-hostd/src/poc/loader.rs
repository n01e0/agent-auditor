use agent_auditor_hostd_ebpf as poc_ebpf;
use aya::{Ebpf, EbpfError};

use super::contract::LoaderBoundary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderPlan {
    pub artifact_crate: String,
    pub artifact_filename: String,
    pub artifact_source: String,
    pub aya_stack: String,
    pub attach_points: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    handoff: LoaderBoundary,
}

impl Default for LoaderPlan {
    fn default() -> Self {
        Self {
            artifact_crate: poc_ebpf::CRATE_NAME.to_owned(),
            artifact_filename: poc_ebpf::OBJECT_FILENAME.to_owned(),
            artifact_source: "embedded_build_artifact".to_owned(),
            aya_stack: std::any::type_name::<aya::Ebpf>().to_owned(),
            attach_points: poc_ebpf::PROGRAMS
                .iter()
                .map(|program| program.attach_point)
                .collect(),
            responsibilities: vec![
                "choose and load the eBPF object",
                "attach kernel hooks for exec / exit collection",
                "own the low-level aya program lifecycle",
                "expose a raw event transport boundary to userspace",
            ],
            handoff: LoaderBoundary::exec_exit_ring_buffer(),
        }
    }
}

impl LoaderPlan {
    pub fn handoff(&self) -> LoaderBoundary {
        self.handoff.clone()
    }

    pub fn load_embedded_object(&self) -> Result<LoadedPoc, EbpfError> {
        let bytes = poc_ebpf::object_bytes();
        let ebpf = Ebpf::load(bytes)?;

        Ok(LoadedPoc {
            artifact_filename: poc_ebpf::OBJECT_FILENAME,
            byte_len: bytes.len(),
            ebpf,
        })
    }

    pub fn summary(&self) -> String {
        format!(
            "artifact={}/{} source={} aya_stack={} transport={} hooks={}",
            self.artifact_crate,
            self.artifact_filename,
            self.artifact_source,
            self.aya_stack,
            self.handoff.transport,
            self.attach_points.join(",")
        )
    }
}

pub struct LoadedPoc {
    artifact_filename: &'static str,
    byte_len: usize,
    ebpf: Ebpf,
}

impl LoadedPoc {
    pub fn as_ebpf(&self) -> &Ebpf {
        &self.ebpf
    }

    pub fn map_count(&self) -> usize {
        self.ebpf.maps().count()
    }

    pub fn program_count(&self) -> usize {
        self.ebpf.programs().count()
    }

    pub fn program_names(&self) -> Vec<&str> {
        let mut names: Vec<_> = self.ebpf.programs().map(|(name, _)| name).collect();
        names.sort_unstable();
        names
    }

    pub fn summary(&self) -> String {
        format!(
            "artifact={} bytes={} programs={} maps={}",
            self.artifact_filename,
            self.byte_len,
            self.program_names().join(","),
            self.map_count()
        )
    }
}

#[cfg(test)]
mod tests {
    use agent_auditor_hostd_ebpf as poc_ebpf;

    use super::LoaderPlan;

    #[test]
    fn summary_mentions_the_embedded_artifact() {
        let summary = LoaderPlan::default().summary();

        assert!(summary.contains(poc_ebpf::CRATE_NAME));
        assert!(summary.contains(poc_ebpf::OBJECT_FILENAME));
        assert!(summary.contains("embedded_build_artifact"));
    }

    #[test]
    fn embedded_object_is_loadable_by_aya_without_attaching() {
        let loaded = LoaderPlan::default()
            .load_embedded_object()
            .expect("embedded eBPF object should parse");
        let expected_programs: Vec<_> = poc_ebpf::PROGRAMS
            .iter()
            .map(|program| program.name)
            .collect();

        assert_eq!(loaded.program_names(), expected_programs);
        assert_eq!(loaded.program_count(), poc_ebpf::PROGRAMS.len());
        assert_eq!(loaded.map_count(), 0);
        assert_eq!(loaded.as_ebpf().maps().count(), 0);
    }
}
