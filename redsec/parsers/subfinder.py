"""Subfinder JSON output parser for RedSEC.

Parses files produced by subfinder's -oJ flag.
Each line is a JSON object representing one discovered subdomain.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser


class SubfinderParser(AbstractParser):
    """Parse subfinder JSONL output (-oJ) into RedSecEvent instances.

    Each line containing a valid subdomain JSON object produces one event.
    Non-JSON lines and lines missing the ``host`` field are silently skipped.

    MITRE ATT&CK mapping:
        Technique: T1595 — Active Scanning
        Tactic:    Reconnaissance
    """

    MITRE_TECHNIQUE = "T1595"
    MITRE_TACTIC = "Reconnaissance"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse a subfinder -oJ output file and return one event per subdomain.

        Args:
            file_path: Path to the subfinder JSON output file.

        Returns:
            List of RedSecEvent instances, one per discovered subdomain.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
        """
        self.validate_file(file_path)
        abs_path = os.path.abspath(file_path)
        events: list[RedSecEvent] = []

        with open(file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                event = self._entry_to_event(obj, abs_path)
                if event is not None:
                    events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _entry_to_event(self, obj: dict, source_file: str) -> Optional[RedSecEvent]:
        """Convert a single subfinder JSON object into a RedSecEvent.

        Args:
            obj: Parsed JSON dict for one subdomain discovery.
            source_file: Absolute path to the source file, stored in raw.

        Returns:
            A RedSecEvent, or None if the required ``host`` field is absent.
        """
        host: Optional[str] = obj.get("host")
        if not host:
            return None

        input_domain: str = obj.get("input", "")
        sources: list = obj.get("source", obj.get("sources", []))
        ip: Optional[str] = obj.get("ip")

        target = input_domain if input_domain else host
        description = f"Subdomain discovered: {host}"
        if input_domain:
            description += f" (root: {input_domain})"
        if sources:
            description += f" via {', '.join(sources)}"

        raw: dict = {
            "host": host,
            "input": input_domain,
            "sources": sources,
            "ip": ip,
            "source_file": source_file,
        }

        return RedSecEvent(
            tool=ToolName.subfinder,
            event_type=EventType.subdomain_found,
            severity=Severity.info,
            target=target,
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=["recon", "subdomain", "passive"],
        )
