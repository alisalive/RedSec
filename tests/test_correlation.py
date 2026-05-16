"""Basic tests for CorrelationEngine using the default rules."""

import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from redsec.correlation.engine import CorrelationEngine
from redsec.models.event import EventType, RedSecEvent, Severity, ToolName

RULES_DIR = str(pathlib.Path(__file__).parent.parent / "redsec" / "correlation" / "rules")


def make_event(event_type: EventType, offset_seconds: int = 0) -> RedSecEvent:
    """Return a minimal RedSecEvent with the given type and timestamp offset."""
    base = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return RedSecEvent(
        tool=ToolName.nmap,
        event_type=event_type,
        severity=Severity.info,
        timestamp=base + timedelta(seconds=offset_seconds),
        target="192.168.1.1",
        description="test event",
    )


class TestCorrelationEngine:
    def test_loads_default_rules(self):
        engine = CorrelationEngine(RULES_DIR)
        assert len(engine._rules) > 0

    def test_empty_event_list_returns_no_chains(self):
        engine = CorrelationEngine(RULES_DIR)
        assert engine.correlate([]) == []

    def test_single_event_returns_no_chains(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [make_event(EventType.port_scan)]
        assert engine.correlate(events) == []

    def test_recon_chain_matched(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.port_scan, offset_seconds=0),
            make_event(EventType.dir_found, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Recon Chain" in names

    def test_web_attack_chain_matched(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.dir_found, offset_seconds=0),
            make_event(EventType.vuln_found, offset_seconds=120),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Web Attack Chain" in names

    def test_credential_attack_chain_matched(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.login_failed, offset_seconds=0),
            make_event(EventType.login_success, offset_seconds=30),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Credential Attack" in names

    def test_events_outside_window_no_match(self):
        engine = CorrelationEngine(RULES_DIR)
        # Default window is 86400s; place events 2 days apart.
        events = [
            make_event(EventType.port_scan, offset_seconds=0),
            make_event(EventType.dir_found, offset_seconds=86400 * 2),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Recon Chain" not in names

    def test_chain_contains_matched_events(self):
        engine = CorrelationEngine(RULES_DIR)
        e1 = make_event(EventType.port_scan, offset_seconds=0)
        e2 = make_event(EventType.dir_found, offset_seconds=60)
        chains = engine.correlate([e1, e2])
        recon = next(c for c in chains if c.name == "Recon Chain")
        assert len(recon.events) == 2

    def test_chain_severity_set(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.port_scan, offset_seconds=0),
            make_event(EventType.dir_found, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        recon = next(c for c in chains if c.name == "Recon Chain")
        assert recon.severity == Severity.low.value

    def test_invalid_rules_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            CorrelationEngine("/nonexistent/rules/dir")
