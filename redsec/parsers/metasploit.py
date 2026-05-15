"""Metasploit JSON output parser for RedSEC.

Parses Metasploit Framework JSON exports containing a ``modules`` array.
Each module entry represents one exploitation attempt; whether a session
was opened determines the event type and severity.
"""

import json
import os
from typing import Optional
from urllib.parse import urlparse

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser


class MetasploitParser(AbstractParser):
    """Parse Metasploit JSON export output into RedSecEvent instances.

    Each entry in the ``modules`` array produces one event:

    * ``session_opened == true``  → ``exploit_success``, ``Severity.critical``
    * ``session_opened == false`` → ``vuln_found``,       ``Severity.high``

    MITRE ATT&CK mapping:
        Technique: T1190 — Exploit Public-Facing Application
        Tactic:    Initial Access
    """

    MITRE_TECHNIQUE = "T1190"
    MITRE_TACTIC = "Initial Access"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse a Metasploit JSON export file and return one event per module run.

        Args:
            file_path: Path to the Metasploit JSON output file.

        Returns:
            List of RedSecEvent instances, one per module entry.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the file is not valid JSON or missing ``modules``.
        """
        self.validate_file(file_path)
        abs_path = os.path.abspath(file_path)

        with open(file_path, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Malformed JSON in Metasploit output: {file_path}"
                ) from exc

        if not isinstance(data, dict) or "modules" not in data:
            raise ValueError(
                f"Missing 'modules' key in Metasploit output: {file_path}"
            )

        events: list[RedSecEvent] = []
        for entry in data["modules"]:
            if not isinstance(entry, dict):
                continue
            event = self._module_to_event(entry, abs_path)
            if event is not None:
                events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _module_to_event(self, entry: dict, source_file: str) -> Optional[RedSecEvent]:
        """Convert a single Metasploit module entry to a RedSecEvent.

        Args:
            entry: One item from the ``modules`` array.
            source_file: Absolute path to the source file, stored in raw.

        Returns:
            A RedSecEvent, or None if the entry lacks a target.
        """
        target_raw: Optional[str] = entry.get("target") or entry.get("rhost")
        if not target_raw:
            return None

        target, port = self._parse_target(target_raw)
        module_name: str = entry.get("name", entry.get("module", "unknown"))
        session_opened: bool = bool(entry.get("session_opened", False))
        session_id: Optional[str] = str(entry.get("session_id", "")) or None
        payload: Optional[str] = entry.get("payload")

        if session_opened:
            event_type = EventType.exploit_success
            severity = Severity.critical
            outcome = "session opened"
            if session_id:
                outcome += f" (session {session_id})"
        else:
            event_type = EventType.vuln_found
            severity = Severity.high
            outcome = "no session"

        description = f"[{module_name}] {outcome} against {target}"
        if port:
            description += f":{port}"
        if payload:
            description += f" | payload: {payload}"

        raw: dict = {
            "module": module_name,
            "target": target_raw,
            "session_opened": session_opened,
            "session_id": session_id,
            "payload": payload,
            "source_file": source_file,
        }

        tags = ["exploitation", "metasploit"]
        if session_opened:
            tags.append("session")

        return RedSecEvent(
            tool=ToolName.metasploit,
            event_type=event_type,
            severity=severity,
            target=target,
            port=port,
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=tags,
        )

    def _parse_target(self, target: str) -> tuple[str, Optional[int]]:
        """Extract host and port from a target string or URL.

        Handles bare IPs (``"192.168.1.1"``), host:port pairs
        (``"192.168.1.1:445"``), and full URLs.

        Args:
            target: Target string from the module entry.

        Returns:
            Tuple of (host_string, port_int_or_None).
        """
        if "://" in target:
            try:
                parsed = urlparse(target)
                return parsed.hostname or target, parsed.port
            except Exception:
                return target, None

        if ":" in target:
            parts = target.rsplit(":", 1)
            if parts[1].isdigit():
                return parts[0], int(parts[1])

        return target, None
