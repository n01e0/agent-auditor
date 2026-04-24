#!/usr/bin/env python3
import json
import os
import socket
import time
import uuid
from pathlib import Path
from typing import Iterable, Optional

from mitmproxy import http


def sanitize(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value)


def env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


class AgentAuditorLiveProxy:
    def __init__(self) -> None:
        self.session_id = env("AUDITOR_SESSION_ID")
        self.agent_id = env("AUDITOR_AGENT_ID")
        self.workspace_id = os.getenv("AUDITOR_WORKSPACE_ID")
        self.mode = env("AUDITOR_MODE", "enforce_preview")
        self.remote_ingress_addr = os.getenv("AUDITOR_REMOTE_INGRESS_ADDR")
        self.remote_ingress_timeout_sec = float(
            os.getenv("AUDITOR_REMOTE_INGRESS_TIMEOUT_SEC", "2")
        )
        self.remote_session_bootstrapped = False

        state_dir = os.getenv("AUDITOR_STATE_DIR")
        self.state_dir = Path(state_dir) if state_dir else None
        self.sessions_root = None
        self.session_root = None
        self.metadata_path = None
        self.requests_path = None

        if self.remote_ingress_addr:
            self.bootstrap_remote_session()
        elif self.state_dir is not None:
            self.sessions_root = (
                self.state_dir
                / "agent-auditor-hostd-live-proxy-observed-runtime"
                / "sessions"
            )
            self.session_root = self.sessions_root / self.session_dir_name()
            self.metadata_path = self.session_root / "session.json"
            self.requests_path = self.session_root / "requests.jsonl"
            self.sessions_root.mkdir(parents=True, exist_ok=True)
            self.session_root.mkdir(parents=True, exist_ok=True)
            self.persist_local_metadata()
        else:
            raise RuntimeError(
                "either AUDITOR_REMOTE_INGRESS_ADDR or AUDITOR_STATE_DIR must be set"
            )

    def session_payload(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "workspace_id": self.workspace_id,
        }

    def session_dir_name(self) -> str:
        workspace = sanitize(self.workspace_id) if self.workspace_id else "workspace_none"
        return f"{sanitize(self.session_id)}__{sanitize(self.agent_id)}__{workspace}"

    def persist_local_metadata(self) -> None:
        if self.metadata_path is None:
            raise RuntimeError("local metadata path is not initialized")
        encoded = json.dumps(self.session_payload(), separators=(",", ":"))
        if self.metadata_path.exists():
            existing = self.metadata_path.read_text(encoding="utf-8").strip()
            if existing and existing != encoded:
                raise RuntimeError(
                    f"metadata mismatch for observed runtime path: {self.metadata_path}"
                )
            return
        self.metadata_path.write_text(encoded, encoding="utf-8")

    def bootstrap_remote_session(self) -> None:
        if self.remote_session_bootstrapped:
            return
        response = self.remote_round_trip(
            {
                "kind": "bootstrap_session",
                "session": self.session_payload(),
            }
        )
        if not response.get("accepted"):
            raise RuntimeError(
                f"remote ingress rejected session bootstrap: {response.get('message')}"
            )
        self.remote_session_bootstrapped = True

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.scheme not in {"http", "https"}:
            return

        envelope = {
            "source": os.getenv("AUDITOR_CAPTURE_SOURCE", "forward_proxy"),
            "request_id": self.request_id(flow),
            "correlation_id": self.correlation_id(flow),
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "workspace_id": self.workspace_id,
            "provider_hint": self.provider_hint(flow.request.host),
            "correlation_status": "confirmed",
            "live_surface": "http_request",
            "transport": flow.request.scheme,
            "method": flow.request.method.lower(),
            "authority": flow.request.host,
            "path": flow.request.path,
            "headers": self.header_classes(flow.request),
            "body_class": self.body_class(flow.request),
            "auth_hint": self.auth_hint(flow.request),
            "target_hint": self.target_hint(flow.request),
            "mode": self.mode,
            "content_retained": False,
        }
        self.append(envelope)

    def request_id(self, flow: http.HTTPFlow) -> str:
        explicit = flow.request.headers.get("x-agent-auditor-request-id")
        if explicit:
            return sanitize(explicit.lower())
        host = sanitize(flow.request.host.lower())
        path = sanitize(flow.request.path.lower())[:40] or "root"
        return f"req_{host}_{path}_{uuid.uuid4().hex[:12]}"

    def correlation_id(self, flow: http.HTTPFlow) -> str:
        explicit = flow.request.headers.get("x-agent-auditor-correlation-id")
        if explicit:
            return sanitize(explicit.lower())
        return f"corr_{int(time.time() * 1000)}_{uuid.uuid4().hex[:10]}"

    def append(self, payload: dict) -> None:
        if self.remote_ingress_addr:
            self.bootstrap_remote_session()
            response = self.remote_round_trip(
                {
                    "kind": "append_envelope",
                    "session": self.session_payload(),
                    "envelope": payload,
                }
            )
            if not response.get("accepted"):
                raise RuntimeError(
                    f"remote ingress rejected envelope append: {response.get('message')}"
                )
            return

        if self.requests_path is None:
            raise RuntimeError("local requests path is not initialized")
        with self.requests_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def remote_round_trip(self, payload: dict) -> dict:
        if not self.remote_ingress_addr:
            raise RuntimeError("remote ingress address is not configured")
        host, port = self.parse_remote_ingress_addr(self.remote_ingress_addr)
        with socket.create_connection(
            (host, port), timeout=self.remote_ingress_timeout_sec
        ) as sock:
            encoded = json.dumps(payload, separators=(",", ":")) + "\n"
            sock.sendall(encoded.encode("utf-8"))
            sock_file = sock.makefile("r", encoding="utf-8")
            response = sock_file.readline().strip()
            if not response:
                raise RuntimeError("remote ingress closed without a response")
            return json.loads(response)

    def parse_remote_ingress_addr(self, value: str) -> tuple[str, int]:
        host, sep, port = value.rpartition(":")
        if not sep or not host or not port:
            raise RuntimeError(
                "AUDITOR_REMOTE_INGRESS_ADDR must use the form <host>:<port>"
            )
        return host, int(port)

    def provider_hint(self, host: str) -> Optional[str]:
        host = host.lower()
        if host == "api.github.com" or host.endswith(".github.com"):
            return "github"
        if host.endswith("googleapis.com") or host.endswith("google.com"):
            return "gws"
        if host.endswith("slack.com"):
            return "slack"
        if host.endswith("discord.com") or host.endswith("discordapp.com"):
            return "discord"
        return None

    def header_classes(self, request: http.Request) -> list[str]:
        classes: set[str] = set()
        content_type = request.headers.get("content-type", "").lower()
        if request.headers.get("authorization"):
            classes.add("authorization")
        if request.headers.get("cookie"):
            classes.add("cookie")
        if request.headers.get("if-none-match") or request.headers.get("if-match"):
            classes.add("conditional")
        if request.headers.get("x-idempotency-key") or request.headers.get("idempotency-key"):
            classes.add("idempotency_key")
        if request.headers.get("sec-fetch-mode") or request.headers.get("sec-fetch-site"):
            classes.add("browser_fetch")
        if "application/json" in content_type:
            classes.add("content_json")
        if "application/x-www-form-urlencoded" in content_type:
            classes.add("content_form")
        if "multipart/form-data" in content_type:
            classes.add("file_upload_metadata")
        if request.headers.get("x-slack-user") or request.headers.get("x-discord-locale"):
            classes.add("message_metadata")
        return sorted(classes)

    def body_class(self, request: http.Request) -> str:
        content_type = request.headers.get("content-type", "").lower()
        if not request.content:
            return "none"
        if "application/json" in content_type:
            return "json"
        if "application/x-www-form-urlencoded" in content_type:
            return "form_urlencoded"
        if "multipart/form-data" in content_type:
            return "multipart_form_data"
        if content_type.startswith("text/"):
            return "text"
        if content_type:
            return "binary"
        return "unknown"

    def auth_hint(self, request: http.Request) -> str:
        authorization = request.headers.get("authorization", "")
        if not authorization:
            return "none"
        prefix = authorization.split(" ", 1)[0].lower()
        if prefix == "bearer":
            return "bearer"
        if prefix == "basic":
            return "basic"
        if prefix.startswith("token"):
            return "api_key"
        return "unknown"

    def target_hint(self, request: http.Request) -> Optional[str]:
        host = request.host.lower()
        path = request.path.split("?", 1)[0]
        segments = [segment for segment in path.split("/") if segment]
        if host == "api.github.com" and len(segments) >= 3 and segments[0] == "repos":
            owner = segments[1]
            repo = segments[2]
            if len(segments) == 3 and request.method.upper() == "PATCH":
                return f"repos/{owner}/{repo}/visibility"
            return "/".join(segments[:6])
        if host.endswith("googleapis.com"):
            if len(segments) >= 6 and segments[:4] == ["gmail", "v1", "users", segments[3]]:
                if segments[4:6] == ["messages", "send"]:
                    return f"gmail.users/{segments[3]}"
            return "/".join(segments[:6]) if segments else path
        if segments:
            return "/".join(segments[:6])
        return path or "/"


addons: Iterable[object] = [AgentAuditorLiveProxy()]
