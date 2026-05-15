# RedSEC — CLAUDE.md

## About
RedSEC is a red team log aggregation and correlation tool. It collects logs from offensive security tools (nmap, subfinder, ffuf, feroxbuster, nuclei, sqlmap, hydra, metasploit, impacket), correlates events into attack chains, maps them to MITRE ATT&CK techniques, calculates detection risk heuristics, and exports to Risto Vaarandi's SEC (Simple Event Correlator) format.

## Goals
- Portfolio project for TalTech Cyber Security Engineering application
- SEC tool integration — core unique feature (GitHub: https://github.com/simple-evcorr/sec)
- Cross-platform: Windows, Linux, macOS

## Environment
- Python 3.13.3
- Development OS: Windows 11
- Target runtime: Windows, Linux, macOS
- Always use os.path — never hardcode path separators

## Project Structure
redsec/
├── redsec/
│   ├── __init__.py
│   ├── parsers/
│   │   ├── base.py          # AbstractParser interface
│   │   ├── nmap.py          # Port scan (XML)
│   │   ├── subfinder.py     # Subdomain recon (JSON)
│   │   ├── ffuf.py          # Web fuzzing (JSON)
│   │   ├── feroxbuster.py   # Directory fuzzing (JSON)
│   │   ├── nuclei.py        # Vuln scan (JSON)
│   │   ├── sqlmap.py        # SQLi exploitation (JSON/text)
│   │   ├── hydra.py         # Brute force (text)
│   │   ├── metasploit.py    # Exploitation/Post-ex (JSON)
│   │   └── impacket.py      # AD/Post-exploitation (text)
│   ├── models/
│   │   ├── event.py         # Normalized event schema (Pydantic) — build first
│   │   └── chain.py         # Attack chain model
│   ├── correlation/
│   │   ├── engine.py        # Rule evaluator
│   │   └── rules/           # YAML rule files
│   ├── mitre/
│   │   ├── mapper.py        # MITRE ATT&CK mapping
│   │   └── data/            # ATT&CK data
│   ├── scoring/
│   │   └── detection.py     # Detection risk heuristic (NOT "evasion score")
│   ├── exporters/
│   │   ├── sec.py           # SEC format export — most important
│   │   ├── html.py          # HTML report with attack chain visualization
│   │   └── json.py
│   └── cli.py
├── tests/
├── rules/                   # Default YAML rules
├── docs/
│   └── THEORETICAL_BACKGROUND.md
├── CLAUDE.md
├── README.md
└── pyproject.toml

## Tool Coverage (Attack Phases)
| Tool         | Phase                    | Output Format |
|--------------|--------------------------|---------------|
| nmap         | Port scan                | XML           |
| subfinder    | Subdomain recon          | JSON          |
| ffuf         | Web fuzzing              | JSON          |
| feroxbuster  | Directory fuzzing        | JSON          |
| nuclei       | Vulnerability scan       | JSON          |
| sqlmap       | SQLi exploitation        | JSON/text     |
| hydra        | Brute force              | text          |
| metasploit   | Exploitation/Post-ex     | JSON          |
| impacket     | AD/Post-exploitation     | text          |

## Development Order
1. models/event.py — Pydantic event schema — FIRST AND MOST IMPORTANT
2. parsers/base.py — AbstractParser
3. parsers/nmap.py — first parser (XML format)
4. parsers/nuclei.py — second parser (JSON format)
5. mitre/mapper.py — MITRE ATT&CK mapping
6. correlation/engine.py — correlation MVP
7. exporters/sec.py — SEC export (Vaarandi integration) — CRITICAL
8. exporters/html.py — HTML report
9. scoring/detection.py — detection risk heuristic
10. remaining parsers (subfinder, ffuf, feroxbuster, sqlmap, hydra, metasploit, impacket)

## Rules
- Every function must have docstring and type hints
- Use os.path everywhere — never hardcode slashes
- Every parser needs test fixtures (real tool output samples)
- SEC export must follow Vaarandi's original format exactly
- Term: "detection risk heuristic" — never "evasion score"
- No unnecessary dependencies — keep it lightweight

## SEC Integration
SEC (Simple Event Correlator) by Risto Vaarandi is the core integration target.
RedSEC converts offensive tool logs into SEC-compatible format.
This is the primary unique feature that differentiates RedSEC from other tools.
Reference: https://github.com/simple-evcorr/sec

## Dependencies
- pydantic — event schema validation
- pyyaml — YAML rule parsing
- jinja2 — HTML report generation
- click — CLI interface
