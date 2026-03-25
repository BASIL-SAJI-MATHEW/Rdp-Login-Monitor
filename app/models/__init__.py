"""Shared data models used across the application by Basil Saji Mathew (BSM)."""

from .alerts import AlertSeverity, DetectionFinding
from .events import LoginStatus, WindowsSecurityEvent

__all__ = [
    "AlertSeverity",
    "DetectionFinding",
    "LoginStatus",
    "WindowsSecurityEvent",
]
