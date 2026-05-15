"""Feroxbuster JSON output parser for RedSEC.

Parses files produced by feroxbuster's --output flag.
Output is JSONL; only lines where ``type == "response"`` are parsed.
"""

import json
import os
from typing import Optional
from urllib.parse import urlparse

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser

_STATUS_SEVERITY: dict[int, Severity] = {
    200: Severity.low,
    201: Severity.low,
    204: Severity.low,
    301: Severity.info,
    302: Severity.info,
    401: Severity.medium,
    403: Severity.medium,
    500: Severity.medium,
}
_DEFAULT_SEVERITY = Severity.info


class FeroxbusterParser(AbstractParser):
    """Parse feroxbuster JSONL output (--output) into RedSecEvent instances.

    Only lines whose ``type`` field equals ``"response"`` are processed;
    status and statistics lines are silently skipped.  Severity follows
    the same HTTP status mapping used by FfufParser.

    MITRE ATT&CK mapping:
        Technique: T1083 — File and Directory Discovery
        Tactic:    Discovery
    """

    MITRE_TECHNIQUE = "T1083"
    MITRE_TACTIC = "Discovery"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse a feroxbuster --output JSONL file and return one event per response.

        Args:
            file_path: Path to the feroxbuster output file.

        Returns:
            List of RedSecEvent instances, one per ``type=response`` line.

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
                if not isinstance(obj, dict) or obj.get("type") != "response":
                    continue
                event = self._response_to_event(obj, abs_path)
                if event is not None:
                    events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _response_to_event(self, obj: dict, source_file: str) -> Optional[RedSecEvent]:
        """Convert a single feroxbuster response line into a RedSecEvent.

        Args:
            obj: Parsed JSON dict for one response line.
            source_file: Absolute source file path, stored in raw.

        Returns:
            A RedSecEvent, or None if the entry lacks a URL.
        """
        url: Optional[str] = obj.get("url")
        if not url:
            return None

        status: int = int(obj.get("status", 0))
        content_length: int = int(obj.get("content_length", obj.get("size", 0)))
        word_count: int = int(obj.get("word_count", obj.get("words", 0)))
        method: str = obj.get("method", "GET")

        target, port = self._parse_url(url)
        severity = _STATUS_SEVERITY.get(status, _DEFAULT_SEVERITY)

        description = f"[{status}] {method} {url} (length={content_length})"

        raw: dict = {
            "url": url,
            "status": status,
            "content_length": content_length,
            "word_count": word_count,
            "method": method,
            "line_count": obj.get("line_count"),
            "source_file": source_file,
        }

        return RedSecEvent(
            tool=ToolName.feroxbuster,
            event_type=EventType.dir_found,
            severity=severity,
            target=target,
            port=port,
            protocol="http",
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=["web-fuzz", "dir-brute"],
        )

    def _parse_url(self, url: str) -> tuple[str, Optional[int]]:
        """Extract the host and port from a URL string.

        Args:
            url: Full URL string (e.g. ``"https://example.com/admin"``).

        Returns:
            Tuple of (hostname, port_int_or_None).
        """
        try:
            parsed = urlparse(url)
            host = parsed.hostname or url
            port = parsed.port
        except Exception:
            host = url
            port = None
        return host, port
