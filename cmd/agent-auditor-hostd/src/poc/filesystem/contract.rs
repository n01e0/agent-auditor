use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemCollector {
    Fanotify,
}

impl fmt::Display for FilesystemCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Fanotify => "fanotify",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitivePathKind {
    SshMaterial,
    EnvFile,
    MountedSecret,
}

impl SensitivePathKind {
    pub fn tag(self) -> &'static str {
        match self {
            Self::SshMaterial => "ssh",
            Self::EnvFile => "env_file",
            Self::MountedSecret => "mounted_secret",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::SshMaterial => "path is inside a .ssh directory",
            Self::EnvFile => "path targets a .env file or variant",
            Self::MountedSecret => "path is inside a mounted secret directory",
        }
    }
}

impl fmt::Display for SensitivePathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePathMatch {
    pub kind: SensitivePathKind,
    pub tag: &'static str,
    pub reason: &'static str,
}

impl SensitivePathMatch {
    pub fn new(kind: SensitivePathKind) -> Self {
        Self {
            kind,
            tag: kind.tag(),
            reason: kind.reason(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePathClassification {
    pub path: String,
    pub matches: Vec<SensitivePathMatch>,
}

impl SensitivePathClassification {
    pub fn is_sensitive(&self) -> bool {
        !self.matches.is_empty()
    }

    pub fn tags(&self) -> Vec<&'static str> {
        self.matches.iter().map(|matched| matched.tag).collect()
    }

    pub fn reasons(&self) -> Vec<&'static str> {
        self.matches.iter().map(|matched| matched.reason).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchBoundary {
    pub collector: FilesystemCollector,
    pub raw_fields: Vec<&'static str>,
    pub raw_access_kinds: Vec<&'static str>,
}

impl WatchBoundary {
    pub fn fanotify_poc() -> Self {
        Self {
            collector: FilesystemCollector::Fanotify,
            raw_fields: vec!["pid", "fd_path", "access_mask", "mount_id"],
            raw_access_kinds: vec!["open", "access", "modify", "close_write"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationBoundary {
    pub collector: FilesystemCollector,
    pub semantic_fields: Vec<&'static str>,
    pub emitted_verbs: Vec<&'static str>,
}
