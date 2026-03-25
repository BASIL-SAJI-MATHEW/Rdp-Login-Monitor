"""Detection engine orchestration by Basil Saji Mathew (BSM)."""

from __future__ import annotations

import logging

from app.models import DetectionFinding, WindowsSecurityEvent

from .rules import DetectionRule


class DetectionEngine:
    """Evaluate normalized events against a pipeline of detection rules."""

    def __init__(self, rules: list[DetectionRule], logger: logging.Logger) -> None:
        self._rules = rules
        self._logger = logger

    def process(self, event: WindowsSecurityEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for rule in self._rules:
            try:
                findings.extend(rule.evaluate(event))
            except Exception:
                self._logger.exception(
                    "Detection rule failed",
                    extra={
                        "payload": {
                            "rule_name": rule.__class__.__name__,
                            "record_id": event.record_id,
                        }
                    },
                )
        return findings
