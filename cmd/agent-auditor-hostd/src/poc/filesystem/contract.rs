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
