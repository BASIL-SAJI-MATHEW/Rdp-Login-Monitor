"""Top-level monitoring application orchestration."""

from __future__ import annotations

import time

from app.config import AppSettings
from app.core import DetectionEngine
from app.monitor import WindowsSecurityEventReader
from app.services.alerting import AlertService
from app.services.logging_service import ApplicationLoggers
from app.services.runtime import RuntimeController


class MonitoringApplication:
    """Coordinate ingestion, detection, alerting, and runtime status."""

    def __init__(
        self,
        settings: AppSettings,
        reader: WindowsSecurityEventReader,
        detection_engine: DetectionEngine,
        alert_service: AlertService,
        runtime_controller: RuntimeController,
        loggers: ApplicationLoggers,
    ) -> None:
        self._settings = settings
        self._reader = reader
        self._detection_engine = detection_engine
        self._alert_service = alert_service
        self._runtime = runtime_controller
        self._loggers = loggers

    def run(self) -> None:
        processed_events = 0
        alerts_sent = 0
        self._runtime.prepare()
        self._runtime.write_pid()
        self._runtime.write_status(
            state="starting",
            processed_events=processed_events,
            alerts_sent=alerts_sent,
        )
        self._loggers.app.info(
            "RDP monitoring service started",
            extra={
                "payload": {
                    "environment": self._settings.environment,
                    "machine_name": self._settings.machine_name,
                }
            },
        )

        try:
            while not self._runtime.stop_requested():
                try:
                    events = self._reader.poll()
                    for event in events:
                        processed_events += 1
                        self._loggers.raw_events.info(
                            "Security event processed",
                            extra={"payload": event.to_dict()},
                        )
                        findings = self._detection_engine.process(event)
                        alerts_sent += self._alert_service.dispatch(findings)

                    self._runtime.write_status(
                        state="running",
                        processed_events=processed_events,
                        alerts_sent=alerts_sent,
                        last_error=None,
                    )
                    time.sleep(self._settings.monitor.poll_interval_seconds)
                except KeyboardInterrupt:
                    self._loggers.app.info("Keyboard interrupt received; shutting down")
                    break
                except Exception as exc:
                    self._loggers.errors.exception(
                        "Monitoring loop failure",
                        extra={
                            "payload": {
                                "error_type": exc.__class__.__name__,
                                "error_message": str(exc),
                            }
                        },
                    )
                    self._runtime.write_status(
                        state="degraded",
                        processed_events=processed_events,
                        alerts_sent=alerts_sent,
                        last_error=str(exc),
                    )
                    time.sleep(self._settings.monitor.error_backoff_seconds)
        finally:
            self._runtime.write_status(
                state="stopped",
                processed_events=processed_events,
                alerts_sent=alerts_sent,
            )
            self._runtime.clear_pid()
            self._runtime.clear_stop_request()
            self._loggers.app.info(
                "RDP monitoring service stopped",
                extra={
                    "payload": {
                        "processed_events": processed_events,
                        "alerts_sent": alerts_sent,
                    }
                },
            )
