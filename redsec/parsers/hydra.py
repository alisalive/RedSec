"""Hydra text output parser for RedSEC.

Parses hydra's plain-text output produced by the -o flag.
Hydra emits one line per credential found in the format:

    [PORT][SERVICE] host: HOST   login: USER   password: PASS

Failed-attempt summary lines are also detected and emitted as
login_failed events when present.
"""

import os
import re
from datetime import datetime, timezone
from typing import Optional

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser

# Matches successful credential lines:
# [22][ssh] host: 192.168.1.1   login: admin   password: secret
_SUCCESS_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+"
    r"host:\s+(?P<host>\S+)\s+"
    r"login:\s+(?P<login>\S+)\s+"
    r"password:\s+(?P<password>\S+)"
)

# Matches hydra's "STATUS" or failure lines, e.g.:
# [STATUS] 64 tasks, ... 0 valid passwords found
_FAILED_RE = re.compile(
    r"\[STATUS\].*?(\d+)\s+valid\s+password",
    re.IGNORECASE,
)


class HydraParser(AbstractParser):
    """Parse hydra plain-text output (-o) into RedSecEvent instances.

    Successful credential lines produce ``login_success`` events with
    ``Severity.critical``.  If the file contains a STATUS line reporting
    zero valid passwords, one ``login_failed`` event is emitted to record
    the attempted brute-force.

    MITRE ATT&CK mapping:
        Technique: T1110 — Brute Force
        Tactic:    Credential Access
    """

    MITRE_TECHNIQUE = "T1110"
    MITRE_TACTIC = "Credential Access"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse a hydra -o output file and return credential events.

        Args:
            file_path: Path to the hydra plain-text output file.

        Returns:
            List of RedSecEvent instances (login_success and/or login_failed).

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
        """
        self.validate_file(file_path)
        abs_path = os.path.abspath(file_path)
        events: list[RedSecEvent] = []
        found_success = False
        timestamp = datetime.now(timezone.utc)

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                success = _SUCCESS_RE.search(line)
                if success:
                    event = self._success_to_event(success, abs_path, timestamp)
                    events.append(event)
                    found_success = True
                    continue

                failed = _FAILED_RE.search(line)
                if failed and int(failed.group(1)) == 0:
                    # No valid passwords found — emit a failed attempt event
                    # if we haven't already seen success events.
                    if not found_success:
                        event = self._failed_event(line, abs_path, timestamp)
                        if event is not None:
                            events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _success_to_event(
        self,
        match: re.Match,
        source_file: str,
        timestamp: datetime,
    ) -> RedSecEvent:
        """Build a login_success event from a hydra credential line match.

        Args:
            match: Regex match object from ``_SUCCESS_RE``.
            source_file: Absolute path to the source file.
            timestamp: Fallback UTC timestamp (hydra output has no timestamps).

        Returns:
            A RedSecEvent with event_type ``login_success``.
        """
        host: str = match.group("host")
        port: int = int(match.group("port"))
        service: str = match.group("service")
        login: str = match.group("login")
        password: str = match.group("password")

        description = (
            f"Valid credential found on {host}:{port} [{service}]"
            f" — login: {login}"
        )

        raw: dict = {
            "host": host,
            "port": port,
            "service": service,
            "login": login,
            "password": password,
            "source_file": source_file,
        }

        return RedSecEvent(
            tool=ToolName.hydra,
            event_type=EventType.login_success,
            severity=Severity.critical,
            timestamp=timestamp,
            target=host,
            port=port,
            protocol=service,
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=["brute-force", "credential-access", service],
        )

    def _failed_event(
        self,
        line: str,
        source_file: str,
        timestamp: datetime,
    ) -> Optional[RedSecEvent]:
        """Build a login_failed event from a hydra STATUS line.

        Attempts to extract the target host from the STATUS line.
        Falls back to ``"unknown"`` if no host can be parsed.

        Args:
            line: The raw STATUS line from hydra output.
            source_file: Absolute path to the source file.
            timestamp: UTC timestamp to assign to the event.

        Returns:
            A RedSecEvent with event_type ``login_failed``, or None if the
            line carries no useful information.
        """
        # Try to extract a host from the status line.
        host_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[\w.-]+\.[\w]+)", line)
        host = host_match.group(1) if host_match else "unknown"

        description = f"Brute-force attempt recorded (no valid credentials found) on {host}"

        raw: dict = {
            "status_line": line,
            "source_file": source_file,
        }

        return RedSecEvent(
            tool=ToolName.hydra,
            event_type=EventType.login_failed,
            severity=Severity.low,
            timestamp=timestamp,
            target=host,
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=["brute-force", "credential-access"],
        )
