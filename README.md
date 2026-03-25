# RDP Login Monitoring & Alert System

Production-style Python backend service for near real-time monitoring of Windows Security Event Logs and detection of suspicious RDP authentication activity.

## Features

- Continuous monitoring of Windows Security logs for Event IDs `4624` and `4625`
- RDP-focused filtering using `LogonType` (`10` and `7`)
- Normalized event pipeline with typed domain models
- Detection engine for:
  - Brute-force login bursts
  - Suspicious non-whitelisted IP activity
  - Authentication rate anomalies
- Discord webhook alerting with retry and backoff
- Alert throttling to reduce noisy duplicates
- Structured JSON logging with rotating log files
- Environment variable and YAML-based configuration
- CLI lifecycle commands for `start`, `stop`, and `status`
- Unit tests for parser and detection logic

## Architecture

The service follows a layered backend structure so ingestion, domain logic, and infrastructure stay loosely coupled:

- `app/monitor/` handles Windows Event Log querying and XML parsing.
- `app/models/` contains normalized event and alert objects.
- `app/core/` contains detection rules and sliding-window state management.
- `app/services/` contains logging, runtime orchestration, and Discord alert delivery.
- `app/config/` centralizes YAML and `.env` configuration loading.
- `app/main.py` is the CLI and service bootstrap entry point.

## Project Structure

```text
Rdp-Login-Monitor/
├── app/
│   ├── main.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── rules.py
│   │   └── state.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── alerts.py
│   │   └── events.py
│   ├── monitor/
│   │   ├── __init__.py
│   │   ├── parser.py
│   │   └── reader.py
│   └── services/
│       ├── __init__.py
│       ├── alerting.py
│       ├── application.py
│       ├── logging_service.py
│       └── runtime.py
├── config/
│   └── settings.yaml
├── tests/
│   ├── test_parser.py
│   └── test_rules.py
├── .env.example
├── .gitignore
├── README.md
└── requirements.txt
```

## Event Flow

1. `WindowsSecurityEventReader` polls the `Security` channel using `EvtQuery`.
2. `WindowsEventXmlParser` normalizes XML into `WindowsSecurityEvent` objects.
3. `DetectionEngine` sends events through stateful rules.
4. `AlertService` throttles and dispatches findings to Discord.
5. JSON logs are written to rotating log files for raw events, alerts, and errors.

## Detection Logic

### Brute Force Detection

Tracks failed RDP attempts per source IP over a sliding window and raises an alert once the configured threshold is reached.

Default: `5` failed attempts within `120` seconds.

### Suspicious IP Detection

Detects successful logins from non-whitelisted IP addresses and can optionally escalate repeated failed attempts from unknown sources.

### Rate Anomaly Detection

Tracks the volume of authentication activity from a single IP and flags spikes above the configured threshold.

Default: `20` events within `300` seconds.

## Logging

The service emits structured JSON logs with rotation support:

- `logs/service.log`
- `logs/raw_events.log`
- `logs/alerts.log`
- `logs/errors.log`

Example raw event:

```json
{
  "timestamp": "2026-03-25T12:15:14.804697+00:00",
  "level": "INFO",
  "logger": "rdp_monitor.raw_events",
  "message": "Security event processed",
  "context": {
    "payload": {
      "record_id": 944108,
      "event_id": 4625,
      "timestamp": "2026-03-25T12:15:13.342000+00:00",
      "username": "administrator",
      "source_ip": "203.0.113.21",
      "machine_name": "RDP-MONITORED-HOST",
      "login_status": "failure",
      "logon_type": "10"
    }
  }
}
```

Example alert:

```json
{
  "timestamp": "2026-03-25T12:15:20.422921+00:00",
  "level": "INFO",
  "logger": "rdp_monitor.alerts",
  "message": "Alert processed",
  "context": {
    "payload": {
      "rule_name": "brute_force",
      "title": "Brute Force Detected",
      "severity": "high",
      "delivery_success": true
    }
  }
}
```

## Requirements

- Windows host with access to the Security Event Log
- Python `3.11+`
- Administrative or equivalent permissions to read Windows Security logs
- Discord webhook URL if alerting is enabled

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Update `config/settings.yaml` and `.env` with your environment-specific values.

## Running the Service

Start in the background:

```powershell
python -m app.main --config config/settings.yaml start
```

Start in the foreground:

```powershell
python -m app.main --config config/settings.yaml start --foreground
```

Check status:

```powershell
python -m app.main --config config/settings.yaml status
```

Request graceful shutdown:

```powershell
python -m app.main --config config/settings.yaml stop
```

## Example Status Output

```json
{
  "running": true,
  "pid": 18540,
  "status": {
    "pid": 18540,
    "state": "running",
    "machine_name": "RDP-MONITORED-HOST",
    "processed_events": 118,
    "alerts_sent": 3,
    "last_error": null,
    "updated_at": "2026-03-25T12:20:35.418746+00:00"
  }
}
```

## Testing

```powershell
pytest
```

## Security Notes

- The service is intentionally scoped to RDP-relevant Windows Security logins.
- Whitelisted IPs suppress noisy alerts from known infrastructure.
- Alert throttling prevents repeated webhook floods for the same detection key.
- Discord delivery failures are retried with incremental backoff and recorded in logs.
- Run the service with least privilege required to read the Security log and write local logs.

