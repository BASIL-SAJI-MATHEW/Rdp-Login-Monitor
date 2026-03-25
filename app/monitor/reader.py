"""Windows Security Event Log reader by Basil Saji Mathew (BSM)."""

from __future__ import annotations

import logging
from typing import Any

from app.config import AppSettings
from app.models import WindowsSecurityEvent
from app.monitor.parser import WindowsEventXmlParser

try:
    import pywintypes
    import win32evtlog
except ImportError:  # pragma: no cover - platform specific import
    pywintypes = None
    win32evtlog = None


NO_MORE_ITEMS_ERROR = 259


class WindowsSecurityEventReader:
    """Poll the Windows Security log for RDP authentication activity."""

    def __init__(
        self,
        settings: AppSettings,
        parser: WindowsEventXmlParser,
        logger: logging.Logger,
    ) -> None:
        self._settings = settings
        self._parser = parser
        self._logger = logger
        self._last_record_id: int | None = None

    def poll(self) -> list[WindowsSecurityEvent]:
        """Fetch new security events since the last successful poll."""

        self._ensure_windows_dependencies()

        if self._last_record_id is None and self._settings.monitor.start_from_latest:
            self._last_record_id = self._get_latest_record_id()
            self._logger.info(
                "Initialized event reader cursor",
                extra={"payload": {"record_id": self._last_record_id}},
            )
            return []

        query_handle = None
        results: list[WindowsSecurityEvent] = []
        query = self._build_query(self._last_record_id)
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

        try:
            query_handle = win32evtlog.EvtQuery(self._settings.monitor.channel, flags, query)
            while True:
                event_handles = self._safe_evt_next(query_handle)
                if not event_handles:
                    break
                for event_handle in event_handles:
                    try:
                        xml_payload = win32evtlog.EvtRender(
                            event_handle, win32evtlog.EvtRenderEventXml
                        )
                        event = self._parser.parse(xml_payload)
                        if event is None:
                            continue
                        if (
                            self._settings.monitor.only_rdp_logons
                            and event.logon_type not in {"10", "7"}
                        ):
                            continue
                        results.append(event)
                        self._last_record_id = max(self._last_record_id or 0, event.record_id)
                    finally:
                        self._safe_close(event_handle)
        finally:
            self._safe_close(query_handle)

        results.sort(key=lambda item: item.record_id)
        return results

    def _build_query(self, last_record_id: int | None) -> str:
        predicate = "(EventID=4624 or EventID=4625)"
        if last_record_id is not None:
            predicate = f"{predicate} and EventRecordID > {last_record_id}"
        return f"*[System[{predicate}]]"

    def _get_latest_record_id(self) -> int:
        query_handle = None
        try:
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            query_handle = win32evtlog.EvtQuery(
                self._settings.monitor.channel,
                flags,
                "*[System[(EventID=4624 or EventID=4625)]]",
            )
            handles = self._safe_evt_next(query_handle, count=1)
            if not handles:
                return 0
            try:
                xml_payload = win32evtlog.EvtRender(handles[0], win32evtlog.EvtRenderEventXml)
                event = self._parser.parse(xml_payload)
                return event.record_id if event else 0
            finally:
                for handle in handles:
                    self._safe_close(handle)
        finally:
            self._safe_close(query_handle)

    def _safe_evt_next(self, query_handle: Any, count: int | None = None) -> list[Any]:
        desired_count = count or self._settings.monitor.batch_size
        try:
            handles = win32evtlog.EvtNext(query_handle, desired_count)
            return list(handles or [])
        except pywintypes.error as exc:
            if getattr(exc, "winerror", None) == NO_MORE_ITEMS_ERROR:
                return []
            raise

    def _safe_close(self, handle: Any) -> None:
        if handle is None:
            return
        try:
            win32evtlog.EvtClose(handle)
        except Exception:
            pass

    def _ensure_windows_dependencies(self) -> None:
        if win32evtlog is None or pywintypes is None:
            raise RuntimeError(
                "pywin32 is required to monitor Windows Event Logs. "
                "Install dependencies on a Windows host and rerun the service."
            )
