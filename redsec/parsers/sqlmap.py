"""Sqlmap JSON output parser for RedSEC.

Parses sqlmap's results.json file produced under --output-dir.
The format is a JSON array where each element represents one
vulnerable URL with injection details.
"""

import json
import os
from typing import Optional
from urllib.parse import urlparse

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser


class SqlmapParser(AbstractParser):
    """Parse sqlmap results.json output into RedSecEvent instances.

    Each element in the results array that describes a confirmed SQL
    injection produces one event.

    MITRE ATT&CK mapping:
        Technique: T1190 — Exploit Public-Facing Application
        Tactic:    Initial Access
    """

    MITRE_TECHNIQUE = "T1190"
    MITRE_TACTIC = "Initial Access"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse a sqlmap results.json file and return one event per finding.

        Args:
            file_path: Path to the sqlmap results.json file.

        Returns:
            List of RedSecEvent instances, one per SQL injection finding.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the file is not valid JSON or not a list.
        """
        self.validate_file(file_path)
        abs_path = os.path.abspath(file_path)

        with open(file_path, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in sqlmap output: {file_path}") from exc

        if not isinstance(data, list):
            raise ValueError(
                f"Expected a JSON array in sqlmap results file: {file_path}"
            )

        events: list[RedSecEvent] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            event = self._entry_to_event(entry, abs_path)
            if event is not None:
                events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _entry_to_event(self, entry: dict, source_file: str) -> Optional[RedSecEvent]:
        """Convert a single sqlmap result dict into a RedSecEvent.

        Args:
            entry: One element from the sqlmap results array.
            source_file: Absolute path to the source file, stored in raw.

        Returns:
            A RedSecEvent, or None if the entry lacks a URL.
        """
        url: Optional[str] = entry.get("url")
        if not url:
            return None

        dbms: str = entry.get("dbms", "unknown")
        data: str = str(entry.get("data", ""))
        techniques: list = entry.get("techniques", [])
        place: str = entry.get("place", "")
        parameter: str = entry.get("parameter", "")

        target, port = self._parse_url(url)

        desc_parts = [f"SQL injection confirmed on {url}"]
        if dbms and dbms != "unknown":
            desc_parts.append(f"DBMS: {dbms}")
        if place and parameter:
            desc_parts.append(f"parameter: {parameter} ({place})")
        if techniques:
            desc_parts.append(f"techniques: {', '.join(techniques)}")
        description = " | ".join(desc_parts)

        raw: dict = {
            "url": url,
            "dbms": dbms,
            "data": data,
            "techniques": techniques,
            "place": place,
            "parameter": parameter,
            "source_file": source_file,
        }

        return RedSecEvent(
            tool=ToolName.sqlmap,
            event_type=EventType.sqli_found,
            severity=Severity.high,
            target=target,
            port=port,
            protocol="http",
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=["sqli", "web-exploit"],
        )

    def _parse_url(self, url: str) -> tuple[str, Optional[int]]:
        """Extract host and port from a URL string.

        Args:
            url: Full URL string.

        Returns:
            Tuple of (hostname, port_int_or_None).
        """
        try:
            parsed = urlparse(url)
            return parsed.hostname or url, parsed.port
        except Exception:
            return url, None
