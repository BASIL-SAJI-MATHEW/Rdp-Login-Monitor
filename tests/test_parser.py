from app.monitor.parser import WindowsEventXmlParser


def test_parser_normalizes_failed_rdp_event() -> None:
    parser = WindowsEventXmlParser()
    xml_payload = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4625</EventID>
        <EventRecordID>1001</EventRecordID>
        <TimeCreated SystemTime="2026-03-25T12:15:13.3420000Z" />
        <Computer>RDP-MONITORED-HOST</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">administrator</Data>
        <Data Name="IpAddress">::ffff:203.0.113.21</Data>
        <Data Name="WorkstationName">ATTACKER-HOST</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="Status">0xC000006D</Data>
        <Data Name="SubStatus">0xC000006A</Data>
      </EventData>
    </Event>
    """

    event = parser.parse(xml_payload)

    assert event is not None
    assert event.event_id == 4625
    assert event.username == "administrator"
    assert event.source_ip == "203.0.113.21"
    assert event.machine_name == "RDP-MONITORED-HOST"
    assert event.logon_type == "10"
    assert event.login_status.value == "failure"

