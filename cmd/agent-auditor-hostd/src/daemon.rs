use std::{path::PathBuf, sync::mpsc, thread, time::Duration};

use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliConfig {
    pub mode: CliMode,
    pub state_dir: Option<PathBuf>,
}

impl CliConfig {
    pub fn parse<I>(args: I) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut args = args.into_iter().peekable();
        let mut mode = CliMode::Preview;
        let mut state_dir = None;

        if matches!(args.peek().map(String::as_str), Some("daemon")) {
            args.next();
            mode = CliMode::Daemon(ForegroundDaemonConfig::default());
        }

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--state-dir" => {
                    let value = args.next().ok_or(CliParseError::MissingStateDirValue)?;
                    state_dir = Some(PathBuf::from(value));
                }
                "--foreground" => {
                    if !matches!(mode, CliMode::Daemon(_)) {
                        return Err(CliParseError::FlagRequiresDaemon("--foreground".to_owned()));
                    }
                }
                "--poll-interval-ms" => {
                    if !matches!(mode, CliMode::Daemon(_)) {
                        return Err(CliParseError::FlagRequiresDaemon(
                            "--poll-interval-ms".to_owned(),
                        ));
                    }
                    let value = args.next().ok_or(CliParseError::MissingPollIntervalValue)?;
                    mode = CliMode::Daemon(ForegroundDaemonConfig {
                        poll_interval: parse_poll_interval_ms(&value)?,
                    });
                }
                unknown if unknown.starts_with('-') => {
                    return Err(CliParseError::UnknownFlag(unknown.to_owned()));
                }
                unknown => return Err(CliParseError::UnknownMode(unknown.to_owned())),
            }
        }

        Ok(Self { mode, state_dir })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliMode {
    Preview,
    Daemon(ForegroundDaemonConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForegroundDaemonConfig {
    pub poll_interval: Duration,
}

impl Default for ForegroundDaemonConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    SigInt,
    SigTerm,
}

impl ShutdownSignal {
    fn from_raw(signal: i32) -> Option<Self> {
        match signal {
            SIGINT => Some(Self::SigInt),
            SIGTERM => Some(Self::SigTerm),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::SigInt => "SIGINT",
            Self::SigTerm => "SIGTERM",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CliParseError {
    #[error(
        "unknown mode `{0}`; use no args for preview or `daemon [--foreground] [--poll-interval-ms <ms>] [--state-dir <path>]`"
    )]
    UnknownMode(String),
    #[error("unknown daemon flag `{0}`")]
    UnknownFlag(String),
    #[error("flag `{0}` requires the `daemon` subcommand")]
    FlagRequiresDaemon(String),
    #[error("missing value for `--poll-interval-ms`")]
    MissingPollIntervalValue,
    #[error("missing value for `--state-dir`")]
    MissingStateDirValue,
    #[error("invalid `--poll-interval-ms` value `{value}`: {reason}")]
    InvalidPollIntervalValue { value: String, reason: String },
}

#[derive(Debug, Error)]
pub enum DaemonRunError {
    #[error("failed to register signal handlers: {0}")]
    SignalRegistration(#[source] std::io::Error),
    #[error("signal listener stopped before delivering a shutdown request")]
    SignalListenerStopped,
    #[error("unsupported shutdown signal `{0}`")]
    UnsupportedSignal(i32),
}

pub fn run_foreground_daemon<F>(
    config: ForegroundDaemonConfig,
    bootstrap: F,
) -> Result<(), DaemonRunError>
where
    F: FnOnce(),
{
    bootstrap();

    let mut signals =
        Signals::new([SIGINT, SIGTERM]).map_err(DaemonRunError::SignalRegistration)?;
    let handle = signals.handle();
    let (signal_tx, signal_rx) = mpsc::channel();

    let listener = thread::spawn(move || {
        if let Some(signal) = signals.forever().next() {
            let _ = signal_tx.send(signal);
        }
    });

    println!("daemon_mode=foreground");
    println!("daemon_pid={}", std::process::id());
    println!(
        "daemon_poll_interval_ms={}",
        config.poll_interval.as_millis()
    );
    println!("daemon_state=running");

    let signal = loop {
        match signal_rx.recv_timeout(config.poll_interval) {
            Ok(signal) => break signal,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                handle.close();
                let _ = listener.join();
                return Err(DaemonRunError::SignalListenerStopped);
            }
        }
    };

    handle.close();
    let _ = listener.join();

    let signal =
        ShutdownSignal::from_raw(signal).ok_or(DaemonRunError::UnsupportedSignal(signal))?;

    println!("daemon_shutdown_signal={}", signal.name());
    println!("daemon_shutdown=graceful");

    Ok(())
}

fn parse_poll_interval_ms(value: &str) -> Result<Duration, CliParseError> {
    let millis: u64 = value.parse().map_err(|error: std::num::ParseIntError| {
        CliParseError::InvalidPollIntervalValue {
            value: value.to_owned(),
            reason: error.to_string(),
        }
    })?;

    if millis == 0 {
        return Err(CliParseError::InvalidPollIntervalValue {
            value: value.to_owned(),
            reason: "must be greater than zero".to_owned(),
        });
    }

    Ok(Duration::from_millis(millis))
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use super::{CliConfig, CliMode, CliParseError, ForegroundDaemonConfig};

    #[test]
    fn parse_defaults_to_preview_without_args() {
        assert_eq!(
            CliConfig::parse(Vec::<String>::new()).unwrap(),
            CliConfig {
                mode: CliMode::Preview,
                state_dir: None,
            }
        );
    }

    #[test]
    fn parse_accepts_preview_state_dir() {
        assert_eq!(
            CliConfig::parse(vec![
                "--state-dir".to_owned(),
                "/tmp/hostd-state".to_owned(),
            ])
            .unwrap(),
            CliConfig {
                mode: CliMode::Preview,
                state_dir: Some(PathBuf::from("/tmp/hostd-state")),
            }
        );
    }

    #[test]
    fn parse_accepts_daemon_subcommand() {
        assert_eq!(
            CliConfig::parse(vec!["daemon".to_owned()]).unwrap(),
            CliConfig {
                mode: CliMode::Daemon(ForegroundDaemonConfig::default()),
                state_dir: None,
            }
        );
    }

    #[test]
    fn parse_accepts_daemon_state_dir_and_custom_poll_interval() {
        assert_eq!(
            CliConfig::parse(vec![
                "daemon".to_owned(),
                "--foreground".to_owned(),
                "--state-dir".to_owned(),
                "/tmp/hostd-state".to_owned(),
                "--poll-interval-ms".to_owned(),
                "25".to_owned(),
            ])
            .unwrap(),
            CliConfig {
                mode: CliMode::Daemon(ForegroundDaemonConfig {
                    poll_interval: Duration::from_millis(25),
                }),
                state_dir: Some(PathBuf::from("/tmp/hostd-state")),
            }
        );
    }

    #[test]
    fn parse_rejects_unknown_mode() {
        assert_eq!(
            CliConfig::parse(vec!["weird".to_owned()]).unwrap_err(),
            CliParseError::UnknownMode("weird".to_owned())
        );
    }

    #[test]
    fn parse_rejects_daemon_only_flag_without_subcommand() {
        assert_eq!(
            CliConfig::parse(vec!["--foreground".to_owned()]).unwrap_err(),
            CliParseError::FlagRequiresDaemon("--foreground".to_owned())
        );
    }

    #[test]
    fn parse_rejects_invalid_poll_interval() {
        assert_eq!(
            CliConfig::parse(vec![
                "daemon".to_owned(),
                "--poll-interval-ms".to_owned(),
                "0".to_owned(),
            ])
            .unwrap_err(),
            CliParseError::InvalidPollIntervalValue {
                value: "0".to_owned(),
                reason: "must be greater than zero".to_owned(),
            }
        );
    }
}
