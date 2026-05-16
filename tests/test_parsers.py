"""Smoke tests for NmapParser and NucleiParser."""

import json
import textwrap

import pytest

from redsec.models.event import EventType, Severity, ToolName
from redsec.parsers.nmap import NmapParser
from redsec.parsers.nuclei import NucleiParser

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

MINIMAL_NMAP_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94" xmloutputversion="1.05">
      <host>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache" version="2.4"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="filtered"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

MINIMAL_NUCLEI_JSONL = json.dumps({
    "template-id": "test-xss",
    "info": {
        "name": "Reflected XSS",
        "severity": "high",
        "tags": ["xss", "web"],
        "classification": {"cve-id": None, "cwe-id": ["cwe-79"]},
    },
    "type": "http",
    "host": "192.168.1.1",
    "matched-at": "http://192.168.1.1/search?q=test",
    "timestamp": "2024-01-15T10:00:00Z",
    "matcher-status": True,
})


# ---------------------------------------------------------------------------
# NmapParser
# ---------------------------------------------------------------------------

class TestNmapParser:
    def test_parse_open_port_returns_event(self, tmp_path):
        f = tmp_path / "scan.xml"
        f.write_text(MINIMAL_NMAP_XML, encoding="utf-8")
        events = NmapParser().parse(str(f))
        assert len(events) == 1

    def test_event_tool_and_type(self, tmp_path):
        f = tmp_path / "scan.xml"
        f.write_text(MINIMAL_NMAP_XML, encoding="utf-8")
        event = NmapParser().parse(str(f))[0]
        assert event.tool == ToolName.nmap.value
        assert event.event_type == EventType.port_scan.value

    def test_event_target_and_port(self, tmp_path):
        f = tmp_path / "scan.xml"
        f.write_text(MINIMAL_NMAP_XML, encoding="utf-8")
        event = NmapParser().parse(str(f))[0]
        assert event.target == "192.168.1.1"
        assert event.port == 80
        assert event.protocol == "tcp"

    def test_event_mitre_mapping(self, tmp_path):
        f = tmp_path / "scan.xml"
        f.write_text(MINIMAL_NMAP_XML, encoding="utf-8")
        event = NmapParser().parse(str(f))[0]
        assert event.mitre_technique == "T1046"
        assert event.mitre_tactic == "Discovery"

    def test_filtered_port_skipped(self, tmp_path):
        f = tmp_path / "scan.xml"
        f.write_text(MINIMAL_NMAP_XML, encoding="utf-8")
        events = NmapParser().parse(str(f))
        ports = [e.port for e in events]
        assert 443 not in ports

    def test_description_contains_target_and_port(self, tmp_path):
        f = tmp_path / "scan.xml"
        f.write_text(MINIMAL_NMAP_XML, encoding="utf-8")
        event = NmapParser().parse(str(f))[0]
        assert "192.168.1.1" in event.description
        assert "80" in event.description

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            NmapParser().parse("/nonexistent/path/scan.xml")

    def test_invalid_xml_raises(self, tmp_path):
        f = tmp_path / "bad.xml"
        f.write_text("not xml at all <<<", encoding="utf-8")
        with pytest.raises(ValueError):
            NmapParser().parse(str(f))

    def test_wrong_root_tag_raises(self, tmp_path):
        f = tmp_path / "wrong.xml"
        f.write_text("<root><host/></root>", encoding="utf-8")
        with pytest.raises(ValueError, match="nmaprun"):
            NmapParser().parse(str(f))

    def test_empty_scan_returns_no_events(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <nmaprun scanner="nmap" start="1700000000" version="7.94" xmloutputversion="1.05">
            </nmaprun>
        """)
        f = tmp_path / "empty.xml"
        f.write_text(xml, encoding="utf-8")
        assert NmapParser().parse(str(f)) == []


# ---------------------------------------------------------------------------
# NucleiParser
# ---------------------------------------------------------------------------

class TestNucleiParser:
    def test_parse_finding_returns_event(self, tmp_path):
        f = tmp_path / "findings.jsonl"
        f.write_text(MINIMAL_NUCLEI_JSONL + "\n", encoding="utf-8")
        events = NucleiParser().parse(str(f))
        assert len(events) == 1

    def test_event_tool_and_type(self, tmp_path):
        f = tmp_path / "findings.jsonl"
        f.write_text(MINIMAL_NUCLEI_JSONL + "\n", encoding="utf-8")
        event = NucleiParser().parse(str(f))[0]
        assert event.tool == ToolName.nuclei.value
        assert event.event_type == EventType.vuln_found.value

    def test_event_severity_mapping(self, tmp_path):
        f = tmp_path / "findings.jsonl"
        f.write_text(MINIMAL_NUCLEI_JSONL + "\n", encoding="utf-8")
        event = NucleiParser().parse(str(f))[0]
        assert event.severity == Severity.high.value

    def test_event_target_extracted(self, tmp_path):
        f = tmp_path / "findings.jsonl"
        f.write_text(MINIMAL_NUCLEI_JSONL + "\n", encoding="utf-8")
        event = NucleiParser().parse(str(f))[0]
        assert event.target == "192.168.1.1"

    def test_event_mitre_http_mapping(self, tmp_path):
        f = tmp_path / "findings.jsonl"
        f.write_text(MINIMAL_NUCLEI_JSONL + "\n", encoding="utf-8")
        event = NucleiParser().parse(str(f))[0]
        assert event.mitre_technique == "T1190"
        assert event.mitre_tactic == "Initial Access"

    def test_tags_include_severity_and_nuclei(self, tmp_path):
        f = tmp_path / "findings.jsonl"
        f.write_text(MINIMAL_NUCLEI_JSONL + "\n", encoding="utf-8")
        event = NucleiParser().parse(str(f))[0]
        assert "nuclei" in event.tags
        assert "high" in event.tags

    def test_malformed_json_lines_skipped(self, tmp_path):
        content = "\n".join([
            "not json at all",
            MINIMAL_NUCLEI_JSONL,
            "{broken",
        ]) + "\n"
        f = tmp_path / "mixed.jsonl"
        f.write_text(content, encoding="utf-8")
        events = NucleiParser().parse(str(f))
        assert len(events) == 1

    def test_comment_lines_skipped(self, tmp_path):
        content = "# this is a comment\n" + MINIMAL_NUCLEI_JSONL + "\n"
        f = tmp_path / "comments.jsonl"
        f.write_text(content, encoding="utf-8")
        events = NucleiParser().parse(str(f))
        assert len(events) == 1

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            NucleiParser().parse("/nonexistent/findings.jsonl")

    def test_empty_file_returns_no_events(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("", encoding="utf-8")
        assert NucleiParser().parse(str(f)) == []
