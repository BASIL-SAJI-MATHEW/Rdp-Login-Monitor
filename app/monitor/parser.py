"""Parsers for Windows Event Log XML payloads."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from xml.etree import ElementTree as ET

from app.models import LoginStatus, WindowsSecurityEvent


EVENT_NAMESPACE = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}


class WindowsEventXmlParser:
    """Parse raw Windows Event Log XML into normalized domain objects."""

    def parse(self, xml_payload: str) -> WindowsSecurityEvent | None:
        """Convert XML into a structured security event."""

        root = ET.fromstring(xml_payload)

        system = root.find("evt:System", EVENT_NAMESPACE)
        if system is None:
            return None

        event_id = int(system.findtext("evt:EventID", default="0", namespaces=EVENT_NAMESPACE))
        if event_id not in {4624, 4625}:
            return None

        record_id = int(
            system.findtext("evt:EventRecordID", default="0", namespaces=EVENT_NAMESPACE)
        )
        computer = system.findtext("evt:Computer", default="unknown", namespaces=EVENT_NAMESPACE)
        time_node = system.find("evt:TimeCreated", EVENT_NAMESPACE)
        system_time = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
        timestamp = self._parse_timestamp(system_time)

        event_data = self._extract_event_data(root)
        username = (
            event_data.get("TargetUserName")
            or event_data.get("SubjectUserName")
            or event_data.get("AccountName")
            or "unknown"
        )
        source_ip = self._normalize_ip(event_data.get("IpAddress"))

        return WindowsSecurityEvent(
            record_id=record_id,
            event_id=event_id,
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            machine_name=computer,
            workstation_name=event_data.get("WorkstationName"),
            login_status=LoginStatus.SUCCESS if event_id == 4624 else LoginStatus.FAILURE,
            logon_type=event_data.get("LogonType"),
            status_code=event_data.get("Status"),
            sub_status_code=event_data.get("SubStatus"),
            raw_event_data=event_data,
        )

    def _extract_event_data(self, root: ET.Element) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for data_node in root.findall("evt:EventData/evt:Data", EVENT_NAMESPACE):
            name = data_node.attrib.get("Name")
            if not name:
                continue
            payload[name] = (data_node.text or "").strip()
        return payload

    def _normalize_ip(self, value: str | None) -> str:
        if not value or value == "-":
            return "unknown"
        normalized = value.strip()
        if normalized.startswith("::ffff:"):
            normalized = normalized.split("::ffff:", maxsplit=1)[1]
        try:
            return str(ip_address(normalized))
        except ValueError:
            return normalized

    def _parse_timestamp(self, raw_value: str) -> datetime:
        if not raw_value:
            return datetime.now(timezone.utc)
        if raw_value.endswith("Z"):
            raw_value = raw_value.replace("Z", "+00:00")
        return datetime.fromisoformat(raw_value)
