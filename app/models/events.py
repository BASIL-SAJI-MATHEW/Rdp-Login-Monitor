"""Structured event models for normalized Windows Security events by BSM."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LoginStatus(str, Enum):
    """Normalized login result values."""

    SUCCESS = "success"
    FAILURE = "failure"


@dataclass(slots=True)
class WindowsSecurityEvent:
    """Represents a normalized Windows Security login event."""

    record_id: int
    event_id: int
    timestamp: datetime
    username: str
    source_ip: str
    machine_name: str
    login_status: LoginStatus
    workstation_name: str | None = None
    logon_type: str | None = None
    status_code: str | None = None
    sub_status_code: str | None = None
    raw_event_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event for structured logging."""

        return {
            "record_id": self.record_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
            "source_ip": self.source_ip,
            "machine_name": self.machine_name,
            "workstation_name": self.workstation_name,
            "login_status": self.login_status.value,
            "logon_type": self.logon_type,
            "status_code": self.status_code,
            "sub_status_code": self.sub_status_code,
            "raw_event_data": self.raw_event_data,
        }
