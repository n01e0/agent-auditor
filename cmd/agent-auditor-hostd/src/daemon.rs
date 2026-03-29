use std::{sync::mpsc, thread, time::Duration};

use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliMode {
    Preview,
    Daemon(ForegroundDaemonConfig),
}

impl CliMode {
    pub fn parse<I>(args: I) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut args = args.into_iter();
        let Some(first) = args.next() else {
            return Ok(Self::Preview);
        };

        if first != "daemon" {
            return Err(CliParseError::UnknownMode(first));
        }

        let mut config = ForegroundDaemonConfig::default();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--foreground" => {}
                "--poll-interval-ms" => {
                    let value = args.next().ok_or(CliParseError::MissingPollIntervalValue)?;
                    config = ForegroundDaemonConfig {
                        poll_interval: parse_poll_interval_ms(&value)?,
                    };
                }
                unknown => return Err(CliParseError::UnknownFlag(unknown.to_owned())),
            }
        }

        Ok(Self::Daemon(config))
    }
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
        "unknown mode `{0}`; use no args for preview or `daemon [--foreground] [--poll-interval-ms <ms>]`"
    )]
    UnknownMode(String),
    #[error("unknown daemon flag `{0}`")]
    UnknownFlag(String),
    #[error("missing value for `--poll-interval-ms`")]
    MissingPollIntervalValue,
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
    use std::time::Duration;

    use super::{CliMode, CliParseError, ForegroundDaemonConfig};

    #[test]
    fn parse_defaults_to_preview_without_args() {
        assert_eq!(
            CliMode::parse(Vec::<String>::new()).unwrap(),
            CliMode::Preview
        );
    }

    #[test]
    fn parse_accepts_daemon_subcommand() {
        assert_eq!(
            CliMode::parse(vec!["daemon".to_owned()]).unwrap(),
            CliMode::Daemon(ForegroundDaemonConfig::default())
        );
    }

    #[test]
    fn parse_accepts_foreground_and_custom_poll_interval() {
        assert_eq!(
            CliMode::parse(vec![
                "daemon".to_owned(),
                "--foreground".to_owned(),
                "--poll-interval-ms".to_owned(),
                "25".to_owned(),
            ])
            .unwrap(),
            CliMode::Daemon(ForegroundDaemonConfig {
                poll_interval: Duration::from_millis(25),
            })
        );
    }

    #[test]
    fn parse_rejects_unknown_mode() {
        assert_eq!(
            CliMode::parse(vec!["weird".to_owned()]).unwrap_err(),
            CliParseError::UnknownMode("weird".to_owned())
        );
    }

    #[test]
    fn parse_rejects_invalid_poll_interval() {
        assert_eq!(
            CliMode::parse(vec![
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
