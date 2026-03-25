"""Application configuration loading and normalization by Basil Saji Mathew (BSM)."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class MonitorSettings:
    """Settings for Windows Event Log polling."""

    channel: str = "Security"
    poll_interval_seconds: float = 2.0
    batch_size: int = 64
    only_rdp_logons: bool = True
    start_from_latest: bool = True
    error_backoff_seconds: float = 5.0


@dataclass(slots=True)
class DetectionSettings:
    """Thresholds and tunables for the detection engine."""

    brute_force_attempts: int = 5
    brute_force_window_seconds: int = 120
    suspicious_ip_failure_threshold: int = 3
    suspicious_ip_window_seconds: int = 300
    anomaly_rate_threshold: int = 20
    anomaly_window_seconds: int = 300
    alert_cooldown_seconds: int = 300
    alert_on_unknown_success: bool = True
    alert_on_unknown_failure: bool = False


@dataclass(slots=True)
class LoggingSettings:
    """Settings for structured JSON logging."""

    directory: str = "logs"
    level: str = "INFO"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5


@dataclass(slots=True)
class DiscordSettings:
    """Settings for Discord webhook delivery."""

    enabled: bool = True
    webhook_url: str = ""
    timeout_seconds: float = 10.0
    retry_attempts: int = 3
    retry_backoff_seconds: float = 2.0
    username: str = "RDP Monitor"


@dataclass(slots=True)
class RuntimeSettings:
    """Settings for runtime process control files."""

    pid_file: str = "runtime/rdp-monitor.pid"
    stop_file: str = "runtime/rdp-monitor.stop"
    status_file: str = "runtime/rdp-monitor.status.json"
    background_stdout: str = "runtime/rdp-monitor.stdout.log"
    background_stderr: str = "runtime/rdp-monitor.stderr.log"


@dataclass(slots=True)
class AppSettings:
    """Root application settings."""

    environment: str = "production"
    machine_name: str = field(default_factory=socket.gethostname)
    whitelist_ips: list[str] = field(default_factory=list)
    whitelist_users: list[str] = field(default_factory=list)
    monitor: MonitorSettings = field(default_factory=MonitorSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    discord: DiscordSettings = field(default_factory=DiscordSettings)
    runtime: RuntimeSettings = field(default_factory=RuntimeSettings)
    base_path: Path = field(default_factory=lambda: Path.cwd())

    def resolve_path(self, value: str) -> Path:
        """Resolve a config path relative to the project base path."""

        candidate = Path(value)
        if candidate.is_absolute():
            return candidate
        return (self.base_path / candidate).resolve()


def load_settings(config_path: str | Path | None = None) -> AppSettings:
    """Load settings from .env, YAML, and defaults."""

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "PyYAML is required to load configuration files. "
            "Install dependencies from requirements.txt first."
        ) from exc

    try:
        from dotenv import load_dotenv
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "python-dotenv is required to load .env configuration. "
            "Install dependencies from requirements.txt first."
        ) from exc

    load_dotenv()
    base_path = Path.cwd().resolve()
    source_path = Path(config_path).resolve() if config_path else None

    if source_path and not source_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {source_path}")

    file_payload: dict[str, Any] = {}
    if source_path:
        with source_path.open("r", encoding="utf-8") as handle:
            file_payload = yaml.safe_load(handle) or {}

    merged = _deep_merge(file_payload, _environment_overrides())

    settings = AppSettings(
        environment=str(merged.get("environment", "production")),
        machine_name=str(merged.get("machine_name", socket.gethostname())),
        whitelist_ips=_as_list(merged.get("whitelist_ips", [])),
        whitelist_users=_as_list(merged.get("whitelist_users", [])),
        monitor=_build_monitor_settings(merged.get("monitor", {})),
        detection=_build_detection_settings(merged.get("detection", {})),
        logging=_build_logging_settings(merged.get("logging", {})),
        discord=_build_discord_settings(merged.get("discord", {})),
        runtime=_build_runtime_settings(merged.get("runtime", {})),
        base_path=base_path,
    )
    return settings


def _build_monitor_settings(payload: dict[str, Any]) -> MonitorSettings:
    return MonitorSettings(
        channel=str(payload.get("channel", "Security")),
        poll_interval_seconds=float(payload.get("poll_interval_seconds", 2.0)),
        batch_size=int(payload.get("batch_size", 64)),
        only_rdp_logons=bool(payload.get("only_rdp_logons", True)),
        start_from_latest=bool(payload.get("start_from_latest", True)),
        error_backoff_seconds=float(payload.get("error_backoff_seconds", 5.0)),
    )


def _build_detection_settings(payload: dict[str, Any]) -> DetectionSettings:
    return DetectionSettings(
        brute_force_attempts=int(payload.get("brute_force_attempts", 5)),
        brute_force_window_seconds=int(payload.get("brute_force_window_seconds", 120)),
        suspicious_ip_failure_threshold=int(
            payload.get("suspicious_ip_failure_threshold", 3)
        ),
        suspicious_ip_window_seconds=int(payload.get("suspicious_ip_window_seconds", 300)),
        anomaly_rate_threshold=int(payload.get("anomaly_rate_threshold", 20)),
        anomaly_window_seconds=int(payload.get("anomaly_window_seconds", 300)),
        alert_cooldown_seconds=int(payload.get("alert_cooldown_seconds", 300)),
        alert_on_unknown_success=bool(payload.get("alert_on_unknown_success", True)),
        alert_on_unknown_failure=bool(payload.get("alert_on_unknown_failure", False)),
    )


def _build_logging_settings(payload: dict[str, Any]) -> LoggingSettings:
    return LoggingSettings(
        directory=str(payload.get("directory", "logs")),
        level=str(payload.get("level", "INFO")).upper(),
        max_bytes=int(payload.get("max_bytes", 10 * 1024 * 1024)),
        backup_count=int(payload.get("backup_count", 5)),
    )


def _build_discord_settings(payload: dict[str, Any]) -> DiscordSettings:
    return DiscordSettings(
        enabled=bool(payload.get("enabled", True)),
        webhook_url=str(payload.get("webhook_url", "")),
        timeout_seconds=float(payload.get("timeout_seconds", 10.0)),
        retry_attempts=int(payload.get("retry_attempts", 3)),
        retry_backoff_seconds=float(payload.get("retry_backoff_seconds", 2.0)),
        username=str(payload.get("username", "RDP Monitor")),
    )


def _build_runtime_settings(payload: dict[str, Any]) -> RuntimeSettings:
    return RuntimeSettings(
        pid_file=str(payload.get("pid_file", "runtime/rdp-monitor.pid")),
        stop_file=str(payload.get("stop_file", "runtime/rdp-monitor.stop")),
        status_file=str(payload.get("status_file", "runtime/rdp-monitor.status.json")),
        background_stdout=str(
            payload.get("background_stdout", "runtime/rdp-monitor.stdout.log")
        ),
        background_stderr=str(
            payload.get("background_stderr", "runtime/rdp-monitor.stderr.log")
        ),
    )


def _environment_overrides() -> dict[str, Any]:
    """Translate environment variables into nested config payloads."""

    mapping: dict[str, tuple[str, ...]] = {
        "RDP_MONITOR_ENVIRONMENT": ("environment",),
        "RDP_MONITOR_MACHINE_NAME": ("machine_name",),
        "RDP_MONITOR_WHITELIST_IPS": ("whitelist_ips",),
        "RDP_MONITOR_WHITELIST_USERS": ("whitelist_users",),
        "RDP_MONITOR_POLL_INTERVAL_SECONDS": ("monitor", "poll_interval_seconds"),
        "RDP_MONITOR_BATCH_SIZE": ("monitor", "batch_size"),
        "RDP_MONITOR_ONLY_RDP_LOGONS": ("monitor", "only_rdp_logons"),
        "RDP_MONITOR_START_FROM_LATEST": ("monitor", "start_from_latest"),
        "RDP_MONITOR_ERROR_BACKOFF_SECONDS": ("monitor", "error_backoff_seconds"),
        "RDP_MONITOR_BRUTE_FORCE_ATTEMPTS": ("detection", "brute_force_attempts"),
        "RDP_MONITOR_BRUTE_FORCE_WINDOW_SECONDS": (
            "detection",
            "brute_force_window_seconds",
        ),
        "RDP_MONITOR_SUSPICIOUS_IP_FAILURE_THRESHOLD": (
            "detection",
            "suspicious_ip_failure_threshold",
        ),
        "RDP_MONITOR_SUSPICIOUS_IP_WINDOW_SECONDS": (
            "detection",
            "suspicious_ip_window_seconds",
        ),
        "RDP_MONITOR_ANOMALY_RATE_THRESHOLD": (
            "detection",
            "anomaly_rate_threshold",
        ),
        "RDP_MONITOR_ANOMALY_WINDOW_SECONDS": ("detection", "anomaly_window_seconds"),
        "RDP_MONITOR_ALERT_COOLDOWN_SECONDS": ("detection", "alert_cooldown_seconds"),
        "RDP_MONITOR_ALERT_ON_UNKNOWN_SUCCESS": (
            "detection",
            "alert_on_unknown_success",
        ),
        "RDP_MONITOR_ALERT_ON_UNKNOWN_FAILURE": (
            "detection",
            "alert_on_unknown_failure",
        ),
        "RDP_MONITOR_LOG_DIR": ("logging", "directory"),
        "RDP_MONITOR_LOG_LEVEL": ("logging", "level"),
        "RDP_MONITOR_LOG_MAX_BYTES": ("logging", "max_bytes"),
        "RDP_MONITOR_LOG_BACKUP_COUNT": ("logging", "backup_count"),
        "RDP_MONITOR_WEBHOOK_ENABLED": ("discord", "enabled"),
        "RDP_MONITOR_WEBHOOK_URL": ("discord", "webhook_url"),
        "RDP_MONITOR_WEBHOOK_TIMEOUT_SECONDS": ("discord", "timeout_seconds"),
        "RDP_MONITOR_WEBHOOK_RETRY_ATTEMPTS": ("discord", "retry_attempts"),
        "RDP_MONITOR_WEBHOOK_RETRY_BACKOFF_SECONDS": (
            "discord",
            "retry_backoff_seconds",
        ),
        "RDP_MONITOR_WEBHOOK_USERNAME": ("discord", "username"),
    }

    payload: dict[str, Any] = {}
    for env_name, path in mapping.items():
        value = os.getenv(env_name)
        if value is None:
            continue
        _set_nested(payload, path, _coerce_env_value(env_name, value))
    return payload


def _coerce_env_value(env_name: str, value: str) -> Any:
    if env_name.endswith("_IPS") or env_name.endswith("_USERS"):
        return _as_list(value)
    if env_name.endswith("_ENABLED") or env_name.endswith("_LOGONS"):
        return _as_bool(value)
    if env_name.endswith("_SUCCESS") or env_name.endswith("_FAILURE"):
        return _as_bool(value)
    if env_name.endswith("_SECONDS"):
        return float(value) if "." in value else int(value)
    if env_name.endswith("_BYTES") or env_name.endswith("_COUNT") or env_name.endswith(
        "_ATTEMPTS"
    ) or env_name.endswith("_THRESHOLD") or env_name.endswith("_SIZE"):
        return int(value)
    return value


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(value).strip()]


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _set_nested(payload: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor = payload
    for key in path[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[path[-1]] = value
