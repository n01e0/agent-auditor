#![cfg(unix)]

use std::{
    io::{BufRead, BufReader, Read},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
fn hostd_daemon_mode_handles_sigterm_with_graceful_shutdown() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-auditor-hostd"))
        .args(["daemon", "--foreground", "--poll-interval-ms", "25"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hostd daemon mode should start");

    let stdout = child.stdout.take().expect("daemon stdout should be piped");
    let stderr = child.stderr.take().expect("daemon stderr should be piped");
    let mut stdout_reader = BufReader::new(stdout);
    let mut stderr_reader = BufReader::new(stderr);
    let mut stdout_text = String::new();

    wait_for_stdout_line(&mut stdout_reader, &mut stdout_text, "daemon_state=running");

    let kill_result = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(kill_result, 0, "SIGTERM should be delivered to the daemon");

    let status = wait_for_exit(&mut child, Duration::from_secs(5));
    stdout_reader
        .read_to_string(&mut stdout_text)
        .expect("remaining daemon stdout should be readable");
    let mut stderr_text = String::new();
    stderr_reader
        .read_to_string(&mut stderr_text)
        .expect("daemon stderr should be readable");

    assert!(
        status.success(),
        "daemon exit status should be success: {status}"
    );
    assert!(stdout_text.contains("daemon_mode=foreground"));
    assert!(stdout_text.contains("daemon_poll_interval_ms=25"));
    assert!(stdout_text.contains("daemon_shutdown_signal=SIGTERM"));
    assert!(stdout_text.contains("daemon_shutdown=graceful"));
    assert!(
        stderr_text.is_empty(),
        "stderr should stay empty: {stderr_text}"
    );
}

fn wait_for_stdout_line(reader: &mut BufReader<impl Read>, output: &mut String, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .expect("daemon stdout should stay readable");
        assert!(
            read > 0,
            "daemon exited before emitting `{needle}`\nstdout:\n{output}"
        );
        output.push_str(&line);
        if line.trim_end() == needle {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for `{needle}`\nstdout:\n{output}"
        );
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;

    loop {
        if let Some(status) = child.try_wait().expect("child wait should succeed") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not exit within {timeout:?}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}
