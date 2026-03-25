"""CLI entry point for the RDP Login Monitoring & Alert System."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.config import AppSettings, load_settings
from app.core import BruteForceRule, DetectionEngine, RateAnomalyRule, SuspiciousIpRule
from app.monitor import WindowsEventXmlParser, WindowsSecurityEventReader
from app.services import (
    AlertService,
    AlertThrottler,
    DiscordWebhookClient,
    MonitoringApplication,
    RuntimeController,
    configure_logging,
)


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the service CLI."""

    parser = argparse.ArgumentParser(description="RDP Login Monitoring & Alert System")
    parser.add_argument(
        "--config",
        default="config/settings.yaml",
        help="Path to the YAML configuration file.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start", help="Start the monitoring service.")
    start_parser.add_argument(
        "--foreground",
        action="store_true",
        help="Run in the current terminal instead of spawning a background process.",
    )

    subparsers.add_parser("run", help="Internal command used by the background process.")
    subparsers.add_parser("stop", help="Request a graceful service stop.")
    subparsers.add_parser("status", help="Show runtime status.")
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()
    config_path = Path(args.config).resolve()
    settings = load_settings(config_path)
    loggers = configure_logging(settings)
    runtime = RuntimeController(settings, loggers.app)

    if args.command == "start":
        return command_start(settings, runtime, config_path, run_in_foreground=args.foreground)
    if args.command == "run":
        return command_run(settings, runtime)
    if args.command == "stop":
        return command_stop(runtime)
    if args.command == "status":
        return command_status(runtime)

    parser.print_help()
    return 1


def command_start(
    settings: AppSettings,
    runtime: RuntimeController,
    config_path: Path,
    *,
    run_in_foreground: bool,
) -> int:
    running, pid = runtime.has_active_process()
    if running:
        print(f"Service is already running with PID {pid}.")
        return 1

    if run_in_foreground:
        return command_run(settings, runtime)

    background_pid = runtime.spawn_background(config_path)
    print(f"Service start requested. Background PID: {background_pid}")
    return 0


def command_run(settings: AppSettings, runtime: RuntimeController) -> int:
    application = build_application(settings, runtime)
    application.run()
    return 0


def command_stop(runtime: RuntimeController) -> int:
    running, pid = runtime.has_active_process()
    if not running:
        print("Service is not running.")
        return 0

    runtime.request_stop()
    stopped = runtime.wait_for_stop()
    if stopped:
        print(f"Service with PID {pid} stopped successfully.")
        return 0

    print(f"Stop signal written for PID {pid}. Waiting for shutdown timed out.")
    return 1


def command_status(runtime: RuntimeController) -> int:
    running, pid = runtime.has_active_process()
    status = runtime.read_status()
    payload = {
        "running": running,
        "pid": pid,
        "status": status,
    }
    print(json.dumps(payload, indent=2))
    return 0


def build_application(
    settings: AppSettings,
    runtime: RuntimeController,
) -> MonitoringApplication:
    loggers = configure_logging(settings)
    parser = WindowsEventXmlParser()
    reader = WindowsSecurityEventReader(settings, parser, loggers.app)
    engine = DetectionEngine(
        rules=[
            BruteForceRule(settings),
            SuspiciousIpRule(settings),
            RateAnomalyRule(settings),
        ],
        logger=loggers.errors,
    )
    alert_service = AlertService(
        client=DiscordWebhookClient(settings, loggers.app),
        throttler=AlertThrottler(settings.detection.alert_cooldown_seconds),
        alert_logger=loggers.alerts,
    )
    return MonitoringApplication(
        settings=settings,
        reader=reader,
        detection_engine=engine,
        alert_service=alert_service,
        runtime_controller=runtime,
        loggers=loggers,
    )


if __name__ == "__main__":
    raise SystemExit(main())
