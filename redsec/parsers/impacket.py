"""Impacket text output parser for RedSEC.

Parses plain-text output from Impacket tools, primarily secretsdump.
secretsdump emits credential hashes one per line in the format:

    Domain\\Username:RID:LM_HASH:NT_HASH:::
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Machine account lines (ending in ``$``) and blank/comment lines are
silently skipped.
"""

import os
import re
from datetime import datetime, timezone
from typing import Optional

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser

# Matches secretsdump NTLM hash lines:
#   [DOMAIN\]Username:RID:LM:NT:::
# Optionally prefixed with a domain component (backslash-separated).
_HASH_RE = re.compile(
    r"^(?:[\w.-]+\\)?(?P<username>[^$:]+)"   # username (no $ machine accounts)
    r":(?P<rid>\d+)"                           # RID
    r":(?P<lm>[a-fA-F0-9]{32})"               # LM hash
    r":(?P<nt>[a-fA-F0-9]{32})"               # NT hash
    r":::"                                     # trailing separators
)

# Matches Kerberos / cleartext lines emitted by secretsdump in some modes:
#   $KRBT$18$..., dpapi_masterkey, etc. — ignored.
_SKIP_PREFIXES = ("$", "[*]", "[+]", "[-]", "#", "Impacket")


class ImpacketParser(AbstractParser):
    """Parse Impacket secretsdump plain-text output into RedSecEvent instances.

    Each NTLM hash line matching the secretsdump format produces one
    ``credential_dumped`` event.  Machine accounts (usernames ending in
    ``$``) and informational lines are skipped.

    MITRE ATT&CK mapping:
        Technique: T1003 — OS Credential Dumping
        Tactic:    Credential Access
    """

    MITRE_TECHNIQUE = "T1003"
    MITRE_TACTIC = "Credential Access"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse an Impacket secretsdump output file.

        Args:
            file_path: Path to the Impacket plain-text output file.

        Returns:
            List of RedSecEvent instances, one per dumped credential.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
        """
        self.validate_file(file_path)
        abs_path = os.path.abspath(file_path)
        timestamp = datetime.now(timezone.utc)
        events: list[RedSecEvent] = []

        # Attempt to infer the target host from the filename
        # (secretsdump often writes <host>.txt or <host>_hashes.txt).
        target = self._infer_target(file_path)

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if any(line.startswith(p) for p in _SKIP_PREFIXES):
                    continue

                match = _HASH_RE.match(line)
                if match:
                    event = self._hash_to_event(match, target, timestamp, abs_path)
                    events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _hash_to_event(
        self,
        match: re.Match,
        target: str,
        timestamp: datetime,
        source_file: str,
    ) -> RedSecEvent:
        """Build a credential_dumped event from a secretsdump hash line.

        Args:
            match: Regex match object from ``_HASH_RE``.
            target: Inferred or placeholder target host string.
            timestamp: UTC timestamp to assign (secretsdump has no timestamps).
            source_file: Absolute path to the source file.

        Returns:
            A RedSecEvent with event_type ``credential_dumped``.
        """
        username: str = match.group("username")
        rid: str = match.group("rid")
        lm_hash: str = match.group("lm")
        nt_hash: str = match.group("nt")

        # Mask hashes in the description to avoid storing them in plain text
        # in the description field; they remain accessible via raw.
        description = (
            f"NTLM hash dumped for account '{username}' (RID {rid}) on {target}"
        )

        raw: dict = {
            "username": username,
            "rid": rid,
            "lm_hash": lm_hash,
            "nt_hash": nt_hash,
            "target": target,
            "source_file": source_file,
        }

        return RedSecEvent(
            tool=ToolName.impacket,
            event_type=EventType.credential_dumped,
            severity=Severity.critical,
            timestamp=timestamp,
            target=target,
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=["credential-dump", "ntlm", "post-exploitation"],
        )

    def _infer_target(self, file_path: str) -> str:
        """Attempt to derive a target host from the output file name.

        secretsdump commonly writes files named after the target host,
        e.g. ``192.168.1.1.txt`` or ``DC01_hashes.txt``.

        Args:
            file_path: Path to the output file.

        Returns:
            Best-guess target string, or ``"unknown"`` if not determinable.
        """
        basename = os.path.splitext(os.path.basename(file_path))[0]
        # Remove common suffixes like _hashes, _dump, _secrets.
        clean = re.sub(r"[_-]?(hashes?|dump|secrets?|output)$", "", basename, flags=re.IGNORECASE)
        return clean if clean else "unknown"
