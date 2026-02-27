#!/usr/bin/env python3
"""
HexStrike AI - Obsidian Integration
Converts HexStrike scan results and findings into Obsidian vault notes.

Usage:
    # Save a scan result from the CLI
    python3 obsidian_integration.py --result result.json --type scan --target 192.168.1.1

    # Or import as a module
    from obsidian_integration import ObsidianIntegration
    obs = ObsidianIntegration()
    obs.save_scan_result(result_dict, target="192.168.1.1", tool="nmap")

Vault structure created:
    <vault>/
    ├── HexStrike/
    │   ├── Engagements/
    │   │   └── <engagement>/
    │   │       ├── _Overview.md
    │   │       ├── Targets/
    │   │       │   └── <target>.md
    │   │       └── Findings/
    │   │           └── <YYYY-MM-DD>-<tool>-<target>.md
    │   └── Dashboard.md

Environment variables:
    OBSIDIAN_VAULT_PATH   Override the default vault path (default: ~/ObsidianVault)
    HEXSTRIKE_SERVER      HexStrike server URL (default: http://127.0.0.1:8888)
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_VAULT_PATH = os.environ.get("OBSIDIAN_VAULT_PATH", "~/ObsidianVault")
HEXSTRIKE_SERVER = os.environ.get("HEXSTRIKE_SERVER", "http://127.0.0.1:8888")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

SEVERITY_TAG = {
    "critical": "severity/critical",
    "high":     "severity/high",
    "medium":   "severity/medium",
    "low":      "severity/low",
    "info":     "severity/info",
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _safe_filename(name: str) -> str:
    """Strip characters that are unsafe in filenames / Obsidian note titles."""
    name = re.sub(r'[\\/:*?"<>|]', "_", name)
    return name.strip(". ")


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _yaml_list(items: List[str]) -> str:
    """Format a Python list as a YAML inline list string."""
    if not items:
        return "[]"
    escaped = [f'"{i}"' for i in items]
    return "[" + ", ".join(escaped) + "]"


# ─── Core class ───────────────────────────────────────────────────────────────

class ObsidianIntegration:
    """
    Writes HexStrike results to an Obsidian vault as Markdown notes.

    Every public method returns the Path of the note that was written.
    """

    def __init__(
        self,
        vault_path: str = DEFAULT_VAULT_PATH,
        engagement: str = "Default",
    ):
        self.vault = Path(vault_path).expanduser().resolve()
        self.engagement = engagement
        self._ensure_structure()

    # ── Vault structure ───────────────────────────────────────────────────────

    def _ensure_structure(self) -> None:
        """Create the HexStrike directory tree inside the vault if needed."""
        for d in [
            self.vault / "HexStrike" / "Engagements" / _safe_filename(self.engagement) / "Targets",
            self.vault / "HexStrike" / "Engagements" / _safe_filename(self.engagement) / "Findings",
        ]:
            d.mkdir(parents=True, exist_ok=True)

    @property
    def _engagement_dir(self) -> Path:
        return self.vault / "HexStrike" / "Engagements" / _safe_filename(self.engagement)

    # ── Public API ────────────────────────────────────────────────────────────

    def save_scan_result(
        self,
        result: Dict[str, Any],
        target: str,
        tool: str,
        tags: Optional[List[str]] = None,
    ) -> Path:
        """
        Save a raw tool result as a timestamped Finding note.

        Parameters
        ----------
        result : dict
            The JSON response from HexStrike's /api/command or similar endpoint.
        target : str
            The target host / domain / IP.
        tool : str
            Name of the tool that produced the result (e.g. "nmap", "nuclei").
        tags : list[str], optional
            Extra Obsidian tags to attach to the note.
        """
        tags = tags or []
        date_str = _today()
        slug = _safe_filename(f"{date_str}-{tool}-{target}")
        note_path = self._engagement_dir / "Findings" / f"{slug}.md"

        stdout = result.get("output") or result.get("stdout") or ""
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", result.get("returncode", "?"))
        command = result.get("command", "")

        severity = _detect_severity(stdout)
        emoji = SEVERITY_EMOJI.get(severity, "⚪")
        all_tags = ["hexstrike", f"tool/{tool}", f"target/{_safe_filename(target)}"]
        if severity:
            all_tags.append(SEVERITY_TAG[severity])
        all_tags += tags

        content = f"""\
---
title: "{emoji} {tool} — {target}"
date: "{_now_iso()}"
target: "{target}"
tool: "{tool}"
severity: "{severity}"
exit_code: {exit_code}
engagement: "{self.engagement}"
tags: {_yaml_list(all_tags)}
---

# {emoji} {tool} — `{target}`

> **Engagement:** [[{_safe_filename(self.engagement)}/_Overview|{self.engagement}]]
> **Target:** [[{_safe_filename(target)}]]
> **Date:** {_now_iso()}
> **Severity:** `{severity.upper()}`

## Command

```bash
{command}
```

## Output

```
{stdout.strip()}
```
"""

        if stderr.strip():
            content += f"""
## Stderr

```
{stderr.strip()}
```
"""

        if result.get("vulnerabilities"):
            content += "\n## Vulnerabilities Found\n\n"
            for vuln in result["vulnerabilities"]:
                v_sev = vuln.get("severity", "info").lower()
                v_emoji = SEVERITY_EMOJI.get(v_sev, "⚪")
                content += f"- {v_emoji} **{vuln.get('name', 'Unknown')}**"
                if vuln.get("description"):
                    content += f" — {vuln['description']}"
                content += "\n"

        note_path.write_text(content, encoding="utf-8")
        self._update_target_note(target)
        self._update_dashboard()
        return note_path

    def save_vulnerability(
        self,
        name: str,
        target: str,
        severity: str,
        description: str = "",
        evidence: str = "",
        cve: str = "",
        remediation: str = "",
        tags: Optional[List[str]] = None,
    ) -> Path:
        """
        Save a structured vulnerability finding note.
        """
        tags = tags or []
        slug = _safe_filename(f"{_today()}-{name}-{target}")
        note_path = self._engagement_dir / "Findings" / f"{slug}.md"

        severity = severity.lower()
        emoji = SEVERITY_EMOJI.get(severity, "⚪")
        all_tags = [
            "hexstrike",
            "finding",
            f"target/{_safe_filename(target)}",
            SEVERITY_TAG.get(severity, "severity/info"),
        ]
        if cve:
            all_tags.append(f"cve/{cve}")
        all_tags += tags

        content = f"""\
---
title: "{emoji} {name}"
date: "{_now_iso()}"
target: "{target}"
severity: "{severity}"
cve: "{cve}"
status: "open"
engagement: "{self.engagement}"
tags: {_yaml_list(all_tags)}
---

# {emoji} {name}

> **Engagement:** [[{_safe_filename(self.engagement)}/_Overview|{self.engagement}]]
> **Target:** [[{_safe_filename(target)}]]
> **Severity:** `{severity.upper()}`
> **CVE:** {cve or "N/A"}
> **Status:** 🔓 Open

## Description

{description or "_No description provided._"}

## Evidence

```
{evidence or "_No evidence provided._"}
```

## Remediation

{remediation or "_No remediation notes yet._"}

## Notes

<!-- Add manual notes here -->
"""

        note_path.write_text(content, encoding="utf-8")
        self._update_target_note(target)
        self._update_dashboard()
        return note_path

    def save_engagement_overview(
        self,
        scope: List[str] = None,
        objectives: str = "",
        notes: str = "",
    ) -> Path:
        """
        Create or update the engagement overview note.
        """
        scope = scope or []
        note_path = self._engagement_dir / "_Overview.md"

        if note_path.exists():
            # Don't overwrite an existing overview — append a status update instead
            existing = note_path.read_text(encoding="utf-8")
            update = f"\n\n---\n\n**Update {_now_iso()}**\n\n{notes}\n"
            note_path.write_text(existing + update, encoding="utf-8")
            return note_path

        scope_list = "\n".join(f"- `{s}`" for s in scope) if scope else "- _Not defined_"
        content = f"""\
---
title: "Engagement: {self.engagement}"
date: "{_now_iso()}"
engagement: "{self.engagement}"
status: "active"
tags: {_yaml_list(["hexstrike", "engagement"])}
---

# Engagement: {self.engagement}

> **Created:** {_now_iso()}
> **Status:** 🟢 Active

## Scope

{scope_list}

## Objectives

{objectives or "_Not defined._"}

## Notes

{notes or "_No notes yet._"}

## Targets

<!-- Auto-populated as scans run -->

## Findings Summary

<!-- Auto-populated as findings are saved -->
"""

        note_path.write_text(content, encoding="utf-8")
        return note_path

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _update_target_note(self, target: str) -> Path:
        """Create a target stub note if it doesn't exist yet."""
        note_path = self._engagement_dir / "Targets" / f"{_safe_filename(target)}.md"
        if not note_path.exists():
            content = f"""\
---
title: "Target: {target}"
date: "{_now_iso()}"
target: "{target}"
engagement: "{self.engagement}"
tags: {_yaml_list(["hexstrike", "target", f"target/{_safe_filename(target)}"])}
---

# Target: `{target}`

> **Engagement:** [[{_safe_filename(self.engagement)}/_Overview|{self.engagement}]]
> **First seen:** {_now_iso()}

## Notes

<!-- Manual notes about this target -->

## Linked Findings

```dataview
LIST
FROM "HexStrike/Engagements/{_safe_filename(self.engagement)}/Findings"
WHERE target = "{target}"
SORT date DESC
```
"""
            note_path.write_text(content, encoding="utf-8")
        return note_path

    def _update_dashboard(self) -> Path:
        """Regenerate the top-level HexStrike dashboard note."""
        dash_path = self.vault / "HexStrike" / "Dashboard.md"
        engagements_dir = self.vault / "HexStrike" / "Engagements"

        engagement_links = ""
        if engagements_dir.exists():
            for eng_dir in sorted(engagements_dir.iterdir()):
                if eng_dir.is_dir():
                    overview = eng_dir / "_Overview.md"
                    link_target = f"HexStrike/Engagements/{eng_dir.name}/_Overview"
                    engagement_links += f"- [[{link_target}|{eng_dir.name}]]\n"

        content = f"""\
---
title: "HexStrike Dashboard"
date_updated: "{_now_iso()}"
tags: ["hexstrike", "dashboard"]
---

# HexStrike AI — Dashboard

> Last updated: {_now_iso()}

## Engagements

{engagement_links or "_No engagements yet._"}

## All Findings (Dataview)

```dataview
TABLE target, severity, date
FROM "HexStrike/Engagements"
WHERE contains(tags, "finding")
SORT severity ASC, date DESC
```

## Critical & High Findings

```dataview
TABLE target, tool, date
FROM "HexStrike/Engagements"
WHERE severity = "critical" OR severity = "high"
SORT date DESC
```
"""

        dash_path.parent.mkdir(parents=True, exist_ok=True)
        dash_path.write_text(content, encoding="utf-8")
        return dash_path


# ─── Severity heuristic ───────────────────────────────────────────────────────

_CRITICAL_PATTERNS = re.compile(
    r"critical|rce|remote code exec|command injection|sql injection|"
    r"authentication bypass|privilege escalation",
    re.IGNORECASE,
)
_HIGH_PATTERNS = re.compile(
    r"\bhigh\b|xss|ssrf|xxe|idor|open redirect|path traversal|lfi|rfi",
    re.IGNORECASE,
)
_MEDIUM_PATTERNS = re.compile(
    r"\bmedium\b|csrf|information disclosure|directory listing|weak cipher",
    re.IGNORECASE,
)
_LOW_PATTERNS = re.compile(
    r"\blow\b|banner|version disclosure|clickjack|missing header",
    re.IGNORECASE,
)


def _detect_severity(text: str) -> str:
    """Heuristically assign a severity from scan output text."""
    if _CRITICAL_PATTERNS.search(text):
        return "critical"
    if _HIGH_PATTERNS.search(text):
        return "high"
    if _MEDIUM_PATTERNS.search(text):
        return "medium"
    if _LOW_PATTERNS.search(text):
        return "low"
    return "info"


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Save HexStrike results to an Obsidian vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--vault",
        default=DEFAULT_VAULT_PATH,
        help="Path to Obsidian vault (default: %(default)s, or $OBSIDIAN_VAULT_PATH)",
    )
    parser.add_argument(
        "--engagement",
        default="Default",
        help="Engagement / project name (default: %(default)s)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # scan sub-command
    scan_p = sub.add_parser("scan", help="Save a raw scan result")
    scan_p.add_argument("--target", required=True, help="Target host/IP/domain")
    scan_p.add_argument("--tool", required=True, help="Tool name (e.g. nmap)")
    scan_p.add_argument(
        "--result",
        help="Path to JSON result file (default: read from stdin)",
    )
    scan_p.add_argument("--tags", nargs="*", default=[], help="Extra tags")

    # vuln sub-command
    vuln_p = sub.add_parser("vuln", help="Save a structured vulnerability finding")
    vuln_p.add_argument("--target", required=True)
    vuln_p.add_argument("--name", required=True, help="Vulnerability name")
    vuln_p.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
    )
    vuln_p.add_argument("--description", default="")
    vuln_p.add_argument("--evidence", default="")
    vuln_p.add_argument("--cve", default="")
    vuln_p.add_argument("--remediation", default="")
    vuln_p.add_argument("--tags", nargs="*", default=[])

    # engagement sub-command
    eng_p = sub.add_parser("engagement", help="Create/update the engagement overview")
    eng_p.add_argument("--scope", nargs="*", default=[], help="In-scope targets")
    eng_p.add_argument("--objectives", default="")
    eng_p.add_argument("--notes", default="")

    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    obs = ObsidianIntegration(vault_path=args.vault, engagement=args.engagement)

    if args.command == "scan":
        if args.result:
            with open(args.result, encoding="utf-8") as f:
                result = json.load(f)
        else:
            result = json.load(sys.stdin)
        path = obs.save_scan_result(
            result=result,
            target=args.target,
            tool=args.tool,
            tags=args.tags,
        )
        print(f"Saved: {path}")

    elif args.command == "vuln":
        path = obs.save_vulnerability(
            name=args.name,
            target=args.target,
            severity=args.severity,
            description=args.description,
            evidence=args.evidence,
            cve=args.cve,
            remediation=args.remediation,
            tags=args.tags,
        )
        print(f"Saved: {path}")

    elif args.command == "engagement":
        path = obs.save_engagement_overview(
            scope=args.scope,
            objectives=args.objectives,
            notes=args.notes,
        )
        print(f"Saved: {path}")


if __name__ == "__main__":
    main()
