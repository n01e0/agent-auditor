#!/usr/bin/env python3
from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO_ROOT / "deploy"

PROXY_CA_DIR = "/home/mitmproxy/.mitmproxy"
PROXY_CA_CERT = f"{PROXY_CA_DIR}/mitmproxy-ca-cert.pem"
RUNTIME_CA_CERT = "/opt/agent-auditor/certs/mitmproxy-ca-cert.pem"
HOSTD_PATH = "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def run(*args: str) -> str:
    print(f"+ {shlex.join(args)}", file=sys.stderr)
    completed = subprocess.run(
        args,
        cwd=REPO_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout


def render_config(*compose_args: str) -> dict:
    output = run("docker", "compose", *compose_args, "config", "--format", "json")
    return json.loads(output)


def py_compile() -> None:
    run("python3", "-m", "py_compile", "deploy/proxy/mitmproxy-live-proxy.py")


def service(config: dict, name: str) -> dict:
    try:
        return config["services"][name]
    except KeyError as exc:
        raise AssertionError(f"missing service `{name}` in rendered config") from exc


def env(service_config: dict) -> dict[str, str]:
    return service_config.get("environment", {})


def find_volume(service_config: dict, target: str) -> dict:
    for volume in service_config.get("volumes", []):
        if volume.get("target") == target:
            return volume
    raise AssertionError(f"missing volume targeting `{target}`")


def assert_hostd(config: dict) -> None:
    hostd = service(config, "hostd")
    hostd_env = env(hostd)
    assert hostd["image"] == "rust:1.93-bookworm", hostd["image"]
    assert hostd_env["CARGO_HOME"] == "/usr/local/cargo"
    assert hostd_env["RUSTUP_HOME"] == "/usr/local/rustup"
    assert hostd_env["PATH"] == HOSTD_PATH


def assert_proxy_service(
    config: dict,
    *,
    name: str,
    ca_volume: str,
    session_id: str,
    agent_id: str,
    workspace_id: str,
    expect_port: bool,
    network_mode: str | None = None,
) -> None:
    proxy = service(config, name)
    proxy_env = env(proxy)
    assert proxy["image"] == "mitmproxy/mitmproxy:11.0.2"
    assert proxy_env["HOME"] == "/home/mitmproxy"
    assert proxy_env["AGENT_AUDITOR_PROXY_CA_DIR"] == PROXY_CA_DIR
    assert proxy_env["AGENT_AUDITOR_PROXY_CA_CERT"] == PROXY_CA_CERT
    assert proxy_env["AUDITOR_MODE"] == "enforce_preview"
    assert proxy_env["AUDITOR_AGENT_ID"] == agent_id
    assert proxy_env["AUDITOR_SESSION_ID"] == session_id
    assert proxy_env["AUDITOR_WORKSPACE_ID"] == workspace_id
    if "AUDITOR_REMOTE_INGRESS_ADDR" in proxy_env:
        assert proxy_env["AUDITOR_REMOTE_INGRESS_ADDR"] == "hostd:19090"
        assert proxy_env["AUDITOR_REMOTE_INGRESS_TIMEOUT_SEC"] == "2"
    if network_mode is not None:
        assert proxy["network_mode"] == network_mode
    ca_mount = find_volume(proxy, PROXY_CA_DIR)
    assert ca_mount["type"] == "volume"
    assert ca_mount["source"] == ca_volume
    script_mount = find_volume(proxy, "/opt/agent-auditor/mitmproxy-live-proxy.py")
    assert script_mount["type"] == "bind"
    assert script_mount["source"].endswith("/deploy/proxy/mitmproxy-live-proxy.py")
    if expect_port:
        ports = proxy.get("ports", [])
        assert ports, f"expected `{name}` to publish a port"
    else:
        assert "ports" not in proxy, f"did not expect `{name}` to publish ports"


def assert_runtime_service(
    config: dict,
    *,
    name: str,
    image: str,
    http_proxy: str,
    https_proxy: str,
    no_proxy: str,
    ca_source_suffix: str,
    profile: str | None = None,
    network_mode: str | None = None,
) -> None:
    runtime = service(config, name)
    runtime_env = env(runtime)
    assert runtime["image"] == image
    assert runtime_env["HTTP_PROXY"] == http_proxy
    assert runtime_env["HTTPS_PROXY"] == https_proxy
    assert runtime_env["NO_PROXY"] == no_proxy
    assert runtime_env["AGENT_AUDITOR_PROXY_CA_CERT"] == RUNTIME_CA_CERT
    ca_mount = find_volume(runtime, RUNTIME_CA_CERT)
    assert ca_mount["type"] == "bind"
    assert ca_mount["source"].endswith(ca_source_suffix), ca_mount["source"]
    if profile is not None:
        assert runtime.get("profiles") == [profile]
    if network_mode is not None:
        assert runtime["network_mode"] == network_mode


def main() -> int:
    py_compile()

    base = render_config("-f", "deploy/compose.yaml", "--env-file", "deploy/compose.env.sample")
    assert_hostd(base)
    assert_proxy_service(
        base,
        name="openclaw-forward-proxy",
        ca_volume="openclaw-mitmproxy-ca",
        session_id="sess_openclaw_forward_proxy",
        agent_id="openclaw-main",
        workspace_id="agent-auditor",
        expect_port=True,
    )
    assert_proxy_service(
        base,
        name="hermes-forward-proxy",
        ca_volume="hermes-mitmproxy-ca",
        session_id="sess_hermes_forward_proxy",
        agent_id="hermes-main",
        workspace_id="agent-auditor",
        expect_port=True,
    )

    sidecar = render_config(
        "-f",
        "deploy/compose.yaml",
        "--env-file",
        "deploy/compose.env.sample",
        "--profile",
        "sidecar",
    )
    assert_hostd(sidecar)
    assert_proxy_service(
        sidecar,
        name="openclaw-proxy-sidecar",
        ca_volume="openclaw-mitmproxy-ca",
        session_id="sess_openclaw_sidecar_proxy",
        agent_id="openclaw-main",
        workspace_id="agent-auditor",
        expect_port=False,
        network_mode="service:openclaw-runtime-sidecar",
    )
    assert_proxy_service(
        sidecar,
        name="hermes-proxy-sidecar",
        ca_volume="hermes-mitmproxy-ca",
        session_id="sess_hermes_sidecar_proxy",
        agent_id="hermes-main",
        workspace_id="agent-auditor",
        expect_port=False,
        network_mode="service:hermes-runtime-sidecar",
    )

    openclaw_forward = render_config(
        "-f",
        "deploy/compose.yaml",
        "-f",
        "deploy/compose.openclaw-forward-proxy.override.yaml",
        "--env-file",
        "deploy/openclaw-forward-proxy.env.sample",
    )
    assert_hostd(openclaw_forward)
    assert_proxy_service(
        openclaw_forward,
        name="openclaw-forward-proxy",
        ca_volume="openclaw-mitmproxy-ca",
        session_id="sess_openclaw_forward_proxy",
        agent_id="openclaw-main",
        workspace_id="agent-auditor",
        expect_port=True,
    )
    assert_runtime_service(
        openclaw_forward,
        name="openclaw-runtime-real",
        image="ghcr.io/openclaw/openclaw:latest",
        http_proxy="http://openclaw-forward-proxy:8080",
        https_proxy="http://openclaw-forward-proxy:8080",
        no_proxy="hostd,localhost,127.0.0.1",
        ca_source_suffix="/deploy/local/mitmproxy-ca/openclaw/mitmproxy-ca-cert.pem",
    )

    openclaw_sidecar = render_config(
        "-f",
        "deploy/compose.yaml",
        "-f",
        "deploy/compose.openclaw-sidecar.override.yaml",
        "--env-file",
        "deploy/openclaw-sidecar.env.sample",
        "--profile",
        "sidecar",
    )
    assert_hostd(openclaw_sidecar)
    assert_runtime_service(
        openclaw_sidecar,
        name="openclaw-runtime-real-sidecar",
        image="ghcr.io/openclaw/openclaw:latest",
        http_proxy="http://127.0.0.1:8080",
        https_proxy="http://127.0.0.1:8080",
        no_proxy="hostd,localhost,127.0.0.1",
        ca_source_suffix="/deploy/local/mitmproxy-ca/openclaw/mitmproxy-ca-cert.pem",
        profile="sidecar",
    )
    assert_proxy_service(
        openclaw_sidecar,
        name="openclaw-proxy-real-sidecar",
        ca_volume="openclaw-mitmproxy-ca",
        session_id="sess_openclaw_sidecar_proxy",
        agent_id="openclaw-main",
        workspace_id="agent-auditor",
        expect_port=False,
        network_mode="service:openclaw-runtime-real-sidecar",
    )

    hermes_forward = render_config(
        "-f",
        "deploy/compose.yaml",
        "-f",
        "deploy/compose.hermes-forward-proxy.override.yaml",
        "--env-file",
        "deploy/hermes-forward-proxy.env.sample",
    )
    assert_hostd(hermes_forward)
    assert_proxy_service(
        hermes_forward,
        name="hermes-forward-proxy",
        ca_volume="hermes-mitmproxy-ca",
        session_id="sess_hermes_forward_proxy",
        agent_id="hermes-main",
        workspace_id="agent-auditor",
        expect_port=True,
    )
    assert_runtime_service(
        hermes_forward,
        name="hermes-runtime-real",
        image="ghcr.io/hermes/hermes:latest",
        http_proxy="http://hermes-forward-proxy:8080",
        https_proxy="http://hermes-forward-proxy:8080",
        no_proxy="hostd,localhost,127.0.0.1",
        ca_source_suffix="/deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem",
    )

    hermes_sidecar = render_config(
        "-f",
        "deploy/compose.yaml",
        "-f",
        "deploy/compose.hermes-sidecar.override.yaml",
        "--env-file",
        "deploy/hermes-sidecar.env.sample",
        "--profile",
        "sidecar",
    )
    assert_hostd(hermes_sidecar)
    assert_runtime_service(
        hermes_sidecar,
        name="hermes-runtime-real-sidecar",
        image="ghcr.io/hermes/hermes:latest",
        http_proxy="http://127.0.0.1:8080",
        https_proxy="http://127.0.0.1:8080",
        no_proxy="hostd,localhost,127.0.0.1",
        ca_source_suffix="/deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem",
        profile="sidecar",
    )
    assert_proxy_service(
        hermes_sidecar,
        name="hermes-proxy-real-sidecar",
        ca_volume="hermes-mitmproxy-ca",
        session_id="sess_hermes_sidecar_proxy",
        agent_id="hermes-main",
        workspace_id="agent-auditor",
        expect_port=False,
        network_mode="service:hermes-runtime-real-sidecar",
    )

    print("real-runtime preflight render checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
