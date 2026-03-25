"""Stateful detection rules for RDP authentication monitoring by BSM."""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import ip_address
from typing import Iterable

from app.config import AppSettings
from app.core.state import SlidingEventWindow
from app.models import AlertSeverity, DetectionFinding, LoginStatus, WindowsSecurityEvent


class DetectionRule(ABC):
    """Base class for detection rules."""

    @abstractmethod
    def evaluate(self, event: WindowsSecurityEvent) -> list[DetectionFinding]:
        """Evaluate an event and return zero or more findings."""


class BruteForceRule(DetectionRule):
    """Detect bursts of failed RDP logins from the same source IP."""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings
        self._failed_attempts = SlidingEventWindow(
            settings.detection.brute_force_window_seconds
        )

    def evaluate(self, event: WindowsSecurityEvent) -> list[DetectionFinding]:
        if event.login_status is not LoginStatus.FAILURE:
            return []
        if event.source_ip in {"unknown", *self._settings.whitelist_ips}:
            return []

        recent = self._failed_attempts.append(event.source_ip, event)
        attempts = len(recent)
        if attempts < self._settings.detection.brute_force_attempts:
            return []

        usernames = sorted({item.username for item in recent if item.username})
        finding = DetectionFinding(
            rule_name="brute_force",
            title="Brute Force Detected",
            severity=AlertSeverity.HIGH,
            description=(
                f"Detected {attempts} failed RDP logins from {event.source_ip} within "
                f"{self._settings.detection.brute_force_window_seconds} seconds."
            ),
            event=event,
            dedupe_key=f"brute_force:{event.source_ip}",
            metadata={"attempts": attempts, "usernames": usernames},
        )
        return [finding]


class SuspiciousIpRule(DetectionRule):
    """Detect non-whitelisted source IP activity."""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings
        self._failed_attempts = SlidingEventWindow(
            settings.detection.suspicious_ip_window_seconds
        )

    def evaluate(self, event: WindowsSecurityEvent) -> list[DetectionFinding]:
        if event.source_ip == "unknown" or event.source_ip in self._settings.whitelist_ips:
            return []

        findings: list[DetectionFinding] = []
        is_public_ip = self._is_public_ip(event.source_ip)

        if event.login_status is LoginStatus.SUCCESS and self._settings.detection.alert_on_unknown_success:
            findings.append(
                DetectionFinding(
                    rule_name="suspicious_ip",
                    title="Suspicious IP Detected",
                    severity=AlertSeverity.CRITICAL if is_public_ip else AlertSeverity.MEDIUM,
                    description=(
                        f"Successful RDP login from non-whitelisted IP {event.source_ip} "
                        f"for user {event.username}."
                    ),
                    event=event,
                    dedupe_key=f"suspicious_ip:success:{event.source_ip}",
                    metadata={
                        "attempts": 1,
                        "ip_scope": "public" if is_public_ip else "private_or_reserved",
                    },
                )
            )

        if event.login_status is LoginStatus.FAILURE and self._settings.detection.alert_on_unknown_failure:
            recent = self._failed_attempts.append(event.source_ip, event)
            attempts = len(recent)
            if attempts >= self._settings.detection.suspicious_ip_failure_threshold:
                findings.append(
                    DetectionFinding(
                        rule_name="suspicious_ip",
                        title="Repeated Suspicious IP Failures",
                        severity=AlertSeverity.MEDIUM if is_public_ip else AlertSeverity.LOW,
                        description=(
                            f"Observed {attempts} failed RDP attempts from non-whitelisted "
                            f"IP {event.source_ip}."
                        ),
                        event=event,
                        dedupe_key=f"suspicious_ip:failure:{event.source_ip}",
                        metadata={
                            "attempts": attempts,
                            "ip_scope": "public"
                            if is_public_ip
                            else "private_or_reserved",
                        },
                    )
                )

        return findings

    def _is_public_ip(self, value: str) -> bool:
        try:
            candidate = ip_address(value)
        except ValueError:
            return False
        return not (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_reserved
            or candidate.is_link_local
            or candidate.is_multicast
        )


class RateAnomalyRule(DetectionRule):
    """Detect unusually high authentication velocity from a single IP."""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings
        self._event_rate = SlidingEventWindow(settings.detection.anomaly_window_seconds)

    def evaluate(self, event: WindowsSecurityEvent) -> list[DetectionFinding]:
        if event.source_ip == "unknown" or event.source_ip in self._settings.whitelist_ips:
            return []

        recent = self._event_rate.append(event.source_ip, event)
        rate = len(recent)
        threshold = self._settings.detection.anomaly_rate_threshold
        if rate < threshold:
            return []

        statuses = list(_compact_statuses(item.login_status.value for item in recent))
        finding = DetectionFinding(
            rule_name="rate_anomaly",
            title="Authentication Rate Anomaly",
            severity=AlertSeverity.HIGH if rate >= threshold * 2 else AlertSeverity.MEDIUM,
            description=(
                f"Observed {rate} RDP authentication events from {event.source_ip} within "
                f"{self._settings.detection.anomaly_window_seconds} seconds."
            ),
            event=event,
            dedupe_key=f"rate_anomaly:{event.source_ip}",
            metadata={"attempts": rate, "statuses": statuses},
        )
        return [finding]


def _compact_statuses(values: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen
