"""Runtime state, PID files, and background process management by BSM."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import sleep
from typing import Any

from app.config import AppSettings


class RuntimeController:
    """Manage runtime files and service lifecycle coordination."""

    def __init__(self, settings: AppSettings, logger: logging.Logger) -> None:
        self._settings = settings
        self._logger = logger

    @property
    def pid_path(self) -> Path:
        return self._settings.resolve_path(self._settings.runtime.pid_file)

    @property
    def stop_path(self) -> Path:
        return self._settings.resolve_path(self._settings.runtime.stop_file)

    @property
    def status_path(self) -> Path:
        return self._settings.resolve_path(self._settings.runtime.status_file)

    @property
    def stdout_path(self) -> Path:
        return self._settings.resolve_path(self._settings.runtime.background_stdout)

    @property
    def stderr_path(self) -> Path:
        return self._settings.resolve_path(self._settings.runtime.background_stderr)

    def prepare(self) -> None:
        """Ensure runtime directories exist and stale files are cleaned up."""

        for path in [
            self.pid_path,
            self.stop_path,
            self.status_path,
            self.stdout_path,
            self.stderr_path,
        ]:
            path.parent.mkdir(parents=True, exist_ok=True)

        self.clear_stop_request()
        running, _ = self.has_active_process()
        if not running and self.pid_path.exists():
            self.pid_path.unlink(missing_ok=True)

    def write_pid(self, pid: int | None = None) -> None:
        target_pid = pid or os.getpid()
        self.pid_path.write_text(str(target_pid), encoding="utf-8")

    def clear_pid(self) -> None:
        self.pid_path.unlink(missing_ok=True)

    def read_pid(self) -> int | None:
        if not self.pid_path.exists():
            return None
        try:
            return int(self.pid_path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return None

    def has_active_process(self) -> tuple[bool, int | None]:
        pid = self.read_pid()
        if pid is None:
            return False, None
        return self._is_process_running(pid), pid

    def request_stop(self) -> None:
        self.stop_path.write_text("stop", encoding="utf-8")

    def clear_stop_request(self) -> None:
        self.stop_path.unlink(missing_ok=True)

    def stop_requested(self) -> bool:
        return self.stop_path.exists()

    def write_status(
        self,
        *,
        state: str,
        processed_events: int,
        alerts_sent: int,
        last_error: str | None = None,
    ) -> None:
        payload = {
            "pid": self.read_pid(),
            "state": state,
            "machine_name": self._settings.machine_name,
            "processed_events": processed_events,
            "alerts_sent": alerts_sent,
            "last_error": last_error,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        temp_path = self.status_path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temp_path.replace(self.status_path)

    def read_status(self) -> dict[str, Any]:
        if not self.status_path.exists():
            return {"state": "unknown"}
        try:
            return json.loads(self.status_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"state": "invalid_status_file"}

    def spawn_background(self, config_path: Path) -> int:
        self.prepare()
        command = [sys.executable, "-m", "app.main", "--config", str(config_path), "run"]
        creationflags = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )

        with self.stdout_path.open("a", encoding="utf-8") as stdout_handle, self.stderr_path.open(
            "a", encoding="utf-8"
        ) as stderr_handle:
            process = subprocess.Popen(
                command,
                cwd=str(self._settings.base_path),
                stdout=stdout_handle,
                stderr=stderr_handle,
                creationflags=creationflags,
                close_fds=True,
            )
        self._logger.info(
            "Spawned background monitoring process",
            extra={"payload": {"pid": process.pid, "command": command}},
        )
        return process.pid

    def wait_for_stop(self, timeout_seconds: int = 15) -> bool:
        deadline = timeout_seconds
        elapsed = 0
        while elapsed < deadline:
            running, _ = self.has_active_process()
            if not running:
                return True
            sleep(1)
            elapsed += 1
        return False

    def _is_process_running(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True
