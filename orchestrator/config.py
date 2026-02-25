from __future__ import annotations

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # GitHub
    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    github_owner: str = field(default_factory=lambda: os.getenv("GITHUB_OWNER", ""))
    github_repo: str = field(default_factory=lambda: os.getenv("GITHUB_REPO", ""))

    # Devin
    devin_api_key: str = field(default_factory=lambda: os.getenv("DEVIN_API_KEY", ""))
    devin_api_base: str = field(
        default_factory=lambda: os.getenv("DEVIN_API_BASE", "https://api.devin.ai/v1")
    )

    # Slack — separate webhooks per channel
    # #security: scan digests, needs-human-review, failed sessions
    # #engineering: PR review requests
    # #all: weekly burndown summary (management)
    slack_webhook_security: str = field(
        default_factory=lambda: os.getenv("SLACK_WEBHOOK_SECURITY", "")
    )
    slack_webhook_engineering: str = field(
        default_factory=lambda: os.getenv("SLACK_WEBHOOK_ENGINEERING", "")
    )
    slack_webhook_all: str = field(
        default_factory=lambda: os.getenv("SLACK_WEBHOOK_ALL", "")
    )
    # Fallback: if channel-specific webhooks aren't set, use this for everything
    slack_webhook_url: str = field(
        default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL", "")
    )

    # Rate limiting
    max_concurrent_sessions: int = field(
        default_factory=lambda: int(os.getenv("MAX_CONCURRENT_SESSIONS", "3"))
    )
    poll_interval: int = field(
        default_factory=lambda: int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
    )

    # Dashboard
    dashboard_port: int = field(
        default_factory=lambda: int(os.getenv("DASHBOARD_PORT", "8080"))
    )

    @property
    def github_api_base(self) -> str:
        return "https://api.github.com"

    @property
    def github_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    @property
    def devin_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.devin_api_key}",
            "Content-Type": "application/json",
        }
