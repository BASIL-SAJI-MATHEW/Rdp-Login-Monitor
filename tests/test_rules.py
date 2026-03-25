"""Detection rule tests for the BSM RDP monitoring project."""

from datetime import datetime, timedelta, timezone

from app.config.settings import AppSettings, DetectionSettings
from app.core.rules import BruteForceRule, RateAnomalyRule
from app.models import LoginStatus, WindowsSecurityEvent


def _build_settings() -> AppSettings:
    settings = AppSettings()
    settings.detection = DetectionSettings(
        brute_force_attempts=3,
        brute_force_window_seconds=120,
        suspicious_ip_failure_threshold=2,
        suspicious_ip_window_seconds=120,
        anomaly_rate_threshold=4,
        anomaly_window_seconds=120,
        alert_cooldown_seconds=60,
        alert_on_unknown_success=True,
        alert_on_unknown_failure=True,
    )
    return settings


def _event(offset_seconds: int, status: LoginStatus) -> WindowsSecurityEvent:
    base_time = datetime(2026, 3, 25, 12, 0, tzinfo=timezone.utc)
    return WindowsSecurityEvent(
        record_id=offset_seconds + 1,
        event_id=4624 if status is LoginStatus.SUCCESS else 4625,
        timestamp=base_time + timedelta(seconds=offset_seconds),
        username="administrator",
        source_ip="203.0.113.21",
        machine_name="RDP-MONITORED-HOST",
        login_status=status,
        workstation_name="REMOTE-HOST",
        logon_type="10",
    )


def test_brute_force_rule_triggers_at_threshold() -> None:
    rule = BruteForceRule(_build_settings())

    findings = []
    findings.extend(rule.evaluate(_event(0, LoginStatus.FAILURE)))
    findings.extend(rule.evaluate(_event(30, LoginStatus.FAILURE)))
    findings.extend(rule.evaluate(_event(60, LoginStatus.FAILURE)))

    assert len(findings) == 1
    assert findings[0].rule_name == "brute_force"
    assert findings[0].metadata["attempts"] == 3


def test_rate_anomaly_rule_triggers_for_high_velocity() -> None:
    rule = RateAnomalyRule(_build_settings())

    findings = []
    findings.extend(rule.evaluate(_event(0, LoginStatus.FAILURE)))
    findings.extend(rule.evaluate(_event(10, LoginStatus.FAILURE)))
    findings.extend(rule.evaluate(_event(20, LoginStatus.SUCCESS)))
    findings.extend(rule.evaluate(_event(30, LoginStatus.FAILURE)))

    assert len(findings) == 1
    assert findings[0].rule_name == "rate_anomaly"
    assert findings[0].metadata["attempts"] == 4
