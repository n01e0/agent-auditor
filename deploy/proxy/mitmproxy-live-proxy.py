#!/usr/bin/env python3
import json
import os
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
        self.state_dir = Path(env("AUDITOR_STATE_DIR", "/state"))
        self.session_id = env("AUDITOR_SESSION_ID")
        self.agent_id = env("AUDITOR_AGENT_ID")
        self.workspace_id = os.getenv("AUDITOR_WORKSPACE_ID")
        self.mode = env("AUDITOR_MODE", "enforce_preview")
        self.sessions_root = (
            self.state_dir
            / "agent-auditor-hostd-live-proxy-observed-runtime"
            / "sessions"
        )
        self.session_root = self.sessions_root / self.session_dir_name()
        self.metadata_path = self.session_root / "metadata.json"
        self.requests_path = self.session_root / "requests.jsonl"
        self.sessions_root.mkdir(parents=True, exist_ok=True)
        self.session_root.mkdir(parents=True, exist_ok=True)
        self.persist_metadata()

    def session_dir_name(self) -> str:
        workspace = sanitize(self.workspace_id) if self.workspace_id else "workspace_none"
        return f"{sanitize(self.session_id)}__{sanitize(self.agent_id)}__{workspace}"

    def persist_metadata(self) -> None:
        payload = {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "workspace_id": self.workspace_id,
        }
        encoded = json.dumps(payload, separators=(",", ":"))
        if self.metadata_path.exists():
            existing = self.metadata_path.read_text(encoding="utf-8").strip()
            if existing and existing != encoded:
                raise RuntimeError(
                    f"metadata mismatch for observed runtime path: {self.metadata_path}"
                )
            return
        self.metadata_path.write_text(encoded, encoding="utf-8")

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
            "live_surface": "http.request",
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
        with self.requests_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")

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
