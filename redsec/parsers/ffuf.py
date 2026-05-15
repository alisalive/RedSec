"""Ffuf JSON output parser for RedSEC.

Parses files produced by ffuf's -o flag with -of json.
The top-level format is a JSON object containing a ``results`` array.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser

# HTTP status codes that escalate severity beyond the default.
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


class FfufParser(AbstractParser):
    """Parse ffuf JSON output (-o/-of json) into RedSecEvent instances.

    Each entry in the ``results`` array produces one event.  Severity is
    derived from the HTTP status code: 200-range responses are ``low``
    (confirmed path), 401/403 are ``medium`` (access-controlled resource),
    and all others default to ``info``.

    MITRE ATT&CK mapping:
        Technique: T1083 — File and Directory Discovery
        Tactic:    Discovery
    """

    MITRE_TECHNIQUE = "T1083"
    MITRE_TACTIC = "Discovery"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse an ffuf JSON output file and return one event per result.

        Args:
            file_path: Path to the ffuf -o (json) output file.

        Returns:
            List of RedSecEvent instances, one per fuzzing result.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the file is not valid JSON or missing ``results``.
        """
        self.validate_file(file_path)
        abs_path = os.path.abspath(file_path)

        with open(file_path, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in ffuf output: {file_path}") from exc

        if not isinstance(data, dict) or "results" not in data:
            raise ValueError(f"Missing 'results' key in ffuf output: {file_path}")

        events: list[RedSecEvent] = []
        for entry in data["results"]:
            if not isinstance(entry, dict):
                continue
            event = self._result_to_event(entry, abs_path)
            if event is not None:
                events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _result_to_event(self, entry: dict, source_file: str) -> Optional[RedSecEvent]:
        """Convert a single ffuf result dict into a RedSecEvent.

        Args:
            entry: One item from the ffuf ``results`` array.
            source_file: Absolute source file path, stored in raw.

        Returns:
            A RedSecEvent, or None if the entry lacks a URL.
        """
        url: Optional[str] = entry.get("url") or entry.get("input", {}).get("FUZZ")
        if not url:
            return None

        status: int = int(entry.get("status", 0))
        length: int = int(entry.get("length", 0))
        words: int = int(entry.get("words", 0))

        target, port = self._parse_url(url)
        severity = _STATUS_SEVERITY.get(status, _DEFAULT_SEVERITY)

        description = f"[{status}] {url} (length={length}, words={words})"

        raw: dict = {
            "url": url,
            "status": status,
            "length": length,
            "words": words,
            "lines": entry.get("lines"),
            "duration": entry.get("duration"),
            "source_file": source_file,
        }

        return RedSecEvent(
            tool=ToolName.ffuf,
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
            url: Full URL string (e.g. ``"http://example.com:8080/admin"``).

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
