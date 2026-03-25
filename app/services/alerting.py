"""Alert delivery and throttling services."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

import requests

from app.config import AppSettings
from app.models import DetectionFinding


class AlertThrottler:
    """Prevent duplicate alerts from spamming downstream systems."""

    def __init__(self, cooldown_seconds: int) -> None:
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._last_sent: dict[str, datetime] = {}

    def allow(self, finding: DetectionFinding) -> bool:
        now = datetime.now(timezone.utc)
        last_sent = self._last_sent.get(finding.dedupe_key)
        if last_sent and now - last_sent < self._cooldown:
            return False
        self._last_sent[finding.dedupe_key] = now
        return True


class DiscordWebhookClient:
    """Send alerts to Discord using a webhook with retry/backoff."""

    def __init__(self, settings: AppSettings, logger: logging.Logger) -> None:
        self._settings = settings
        self._logger = logger
        self._session = requests.Session()

    def send(self, finding: DetectionFinding) -> bool:
        if not self._settings.discord.enabled:
            self._logger.info(
                "Discord delivery disabled",
                extra={"payload": {"rule_name": finding.rule_name}},
            )
            return False

        if not self._settings.discord.webhook_url:
            self._logger.warning(
                "Discord webhook URL is empty; skipping alert delivery",
                extra={"payload": {"rule_name": finding.rule_name}},
            )
            return False

        payload = finding.to_discord_payload(self._settings.discord.username)
        max_attempts = max(1, self._settings.discord.retry_attempts)

        for attempt in range(1, max_attempts + 1):
            try:
                response = self._session.post(
                    self._settings.discord.webhook_url,
                    json=payload,
                    timeout=self._settings.discord.timeout_seconds,
                )
                if 200 <= response.status_code < 300:
                    return True

                should_retry = response.status_code in {429, 500, 502, 503, 504}
                if should_retry and attempt < max_attempts:
                    time.sleep(self._retry_delay(attempt, response))
                    continue

                self._logger.error(
                    "Discord webhook rejected alert",
                    extra={
                        "payload": {
                            "rule_name": finding.rule_name,
                            "status_code": response.status_code,
                            "response_body": response.text[:300],
                        }
                    },
                )
                return False
            except requests.RequestException:
                if attempt < max_attempts:
                    time.sleep(self._retry_delay(attempt))
                    continue
                self._logger.exception(
                    "Discord webhook delivery failed",
                    extra={
                        "payload": {
                            "rule_name": finding.rule_name,
                            "attempt": attempt,
                        }
                    },
                )
                return False

        return False

    def _retry_delay(self, attempt: int, response: requests.Response | None = None) -> float:
        retry_after = response.headers.get("Retry-After") if response is not None else None
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return self._settings.discord.retry_backoff_seconds * attempt


class AlertService:
    """Throttle, log, and deliver detection findings."""

    def __init__(
        self,
        client: DiscordWebhookClient,
        throttler: AlertThrottler,
        alert_logger: logging.Logger,
    ) -> None:
        self._client = client
        self._throttler = throttler
        self._alert_logger = alert_logger

    def dispatch(self, findings: list[DetectionFinding]) -> int:
        delivered = 0
        for finding in findings:
            if not self._throttler.allow(finding):
                self._alert_logger.info(
                    "Alert throttled",
                    extra={"payload": finding.to_log_dict()},
                )
                continue

            sent = self._client.send(finding)
            self._alert_logger.info(
                "Alert processed",
                extra={
                    "payload": {
                        **finding.to_log_dict(),
                        "delivery_success": sent,
                    }
                },
            )
            if sent:
                delivered += 1
        return delivered

