"""Alert and detection finding models by Basil Saji Mathew (BSM)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .events import WindowsSecurityEvent


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_DISCORD_COLORS = {
    AlertSeverity.LOW: 5763719,
    AlertSeverity.MEDIUM: 15105570,
    AlertSeverity.HIGH: 16007990,
    AlertSeverity.CRITICAL: 13632027,
}


@dataclass(slots=True)
class DetectionFinding:
    """A normalized detection result emitted by a rule."""

    rule_name: str
    title: str
    severity: AlertSeverity
    description: str
    event: WindowsSecurityEvent
    dedupe_key: str
    metadata: dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_log_dict(self) -> dict[str, Any]:
        """Serialize finding details for JSON logging."""

        return {
            "rule_name": self.rule_name,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "dedupe_key": self.dedupe_key,
            "occurred_at": self.occurred_at.isoformat(),
            "metadata": self.metadata,
            "event": self.event.to_dict(),
        }

    def to_discord_payload(self, sender_name: str) -> dict[str, Any]:
        """Convert the finding into a Discord webhook payload."""

        attempts = self.metadata.get("attempts", "n/a")
        embed = {
            "title": self.title,
            "description": self.description,
            "color": _DISCORD_COLORS[self.severity],
            "timestamp": self.occurred_at.isoformat(),
            "fields": [
                {
                    "name": "IP",
                    "value": self.event.source_ip or "unknown",
                    "inline": True,
                },
                {
                    "name": "Username",
                    "value": self.event.username or "unknown",
                    "inline": True,
                },
                {
                    "name": "Attempts",
                    "value": str(attempts),
                    "inline": True,
                },
                {
                    "name": "Machine",
                    "value": self.event.machine_name,
                    "inline": True,
                },
                {
                    "name": "Status",
                    "value": self.event.login_status.value,
                    "inline": True,
                },
                {
                    "name": "Event Time",
                    "value": self.event.timestamp.isoformat(),
                    "inline": False,
                },
            ],
        }
        return {"username": sender_name, "embeds": [embed]}
