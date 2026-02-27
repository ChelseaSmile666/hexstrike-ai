#!/usr/bin/env python3
"""
HexStrike AI - Obsidian Integration (Rich Connection Style)
Writes HexStrike results to an Obsidian vault with a dense wikilink graph
so every note is a visible node connected to its engagement, target, tool,
CVE, and severity in the Obsidian graph view.

Vault structure
───────────────
<vault>/
└── HexStrike/
    ├── Dashboard.md              ← master hub, links everything
    ├── Tools/
    │   └── <toolname>.md         ← one hub note per tool used
    ├── CVEs/
    │   └── <CVE-ID>.md           ← one hub note per CVE referenced
    ├── Severity/
    │   ├── Critical.md
    │   ├── High.md
    │   ├── Medium.md
    │   ├── Low.md
    │   └── Info.md
    └── Engagements/
        └── <engagement>/
            ├── _Overview.md      ← engagement hub
            ├── Targets/
            │   └── <target>.md   ← target hub
            └── Findings/
                └── <date>-<tool>-<target>.md

Every finding note wikilinks to:
  Engagement → Target → Tool → Severity → CVE (if present)
Those hub notes link back via Dataview queries.
All links are visible in Obsidian Graph View.

CLI
───
  python3 obsidian_integration.py [--vault PATH] [--engagement NAME] <cmd>

  scan        --target HOST --tool TOOL [--result FILE] [--tags ...]
  vuln        --target HOST --name NAME --severity LEVEL [--cve ID] ...
  engagement  [--scope ...] [--objectives TEXT] [--notes TEXT]

Environment
───────────
  OBSIDIAN_VAULT_PATH   vault root  (default: ~/ObsidianVault)
  HEXSTRIKE_SERVER      server URL  (default: http://127.0.0.1:8888)
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ─── Config ───────────────────────────────────────────────────────────────────

DEFAULT_VAULT = os.environ.get("OBSIDIAN_VAULT_PATH", "~/ObsidianVault")
HEXSTRIKE_SERVER = os.environ.get("HEXSTRIKE_SERVER", "http://127.0.0.1:8888")

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}
SEV_TAG = {
    "critical": "severity/critical",
    "high":     "severity/high",
    "medium":   "severity/medium",
    "low":      "severity/low",
    "info":     "severity/info",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _fn(s: str) -> str:
    """Safe filename: strip path-unsafe characters."""
    return re.sub(r'[\\/:*?"<>|]', "_", s).strip(". ")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _yml(items: List[str]) -> str:
    return "[" + ", ".join(f'"{i}"' for i in items) + "]" if items else "[]"


def _wl(path: str, label: str = "") -> str:
    """Obsidian wikilink: [[path|label]] or [[path]]."""
    return f"[[{path}|{label}]]" if label else f"[[{path}]]"


# ─── Integration class ────────────────────────────────────────────────────────

class ObsidianIntegration:
    """
    Saves HexStrike results as richly connected Obsidian notes.
    Hub notes (Tool, Severity, CVE) are created on first reference and
    link back to all related findings via Dataview queries, making the
    Obsidian graph view show the full connection web.
    """

    def __init__(self, vault_path: str = DEFAULT_VAULT, engagement: str = "Default"):
        self.vault = Path(vault_path).expanduser().resolve()
        self.eng = engagement
        self._eng_dir = self.vault / "HexStrike" / "Engagements" / _fn(engagement)
        self._tools_dir = self.vault / "HexStrike" / "Tools"
        self._cves_dir = self.vault / "HexStrike" / "CVEs"
        self._sev_dir = self.vault / "HexStrike" / "Severity"
        self._init_dirs()

    # ── Vault init ────────────────────────────────────────────────────────────

    def _init_dirs(self) -> None:
        for d in [
            self._eng_dir / "Targets",
            self._eng_dir / "Findings",
            self._tools_dir,
            self._cves_dir,
            self._sev_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)
        self._init_severity_hubs()

    def _init_severity_hubs(self) -> None:
        for level, emoji in SEV_EMOJI.items():
            path = self._sev_dir / f"{level.capitalize()}.md"
            if path.exists():
                continue
            path.write_text(
                f"""\
---
title: "{emoji} {level.capitalize()} Severity"
tags: ["hexstrike", "severity", "{SEV_TAG[level]}"]
---

# {emoji} {level.capitalize()} Findings

{_wl("HexStrike/Dashboard", "← Dashboard")}

## All {level.capitalize()} Findings

```dataview
TABLE target, tool, engagement, date
FROM "HexStrike/Engagements"
WHERE severity = "{level}"
SORT date DESC
```
""",
                encoding="utf-8",
            )

    # ── Wikilink path builders ─────────────────────────────────────────────────

    def _eng_link(self) -> str:
        return _wl(f"HexStrike/Engagements/{_fn(self.eng)}/_Overview", self.eng)

    def _target_link(self, target: str) -> str:
        return _wl(
            f"HexStrike/Engagements/{_fn(self.eng)}/Targets/{_fn(target)}", target
        )

    def _tool_link(self, tool: str) -> str:
        return _wl(f"HexStrike/Tools/{_fn(tool)}", tool)

    def _sev_link(self, severity: str) -> str:
        emoji = SEV_EMOJI.get(severity, "⚪")
        return _wl(f"HexStrike/Severity/{severity.capitalize()}", f"{emoji} {severity.capitalize()}")

    def _cve_link(self, cve: str) -> str:
        return _wl(f"HexStrike/CVEs/{_fn(cve)}", cve) if cve else ""

    # ── Connection table ───────────────────────────────────────────────────────

    def _conn_table(
        self,
        target: str,
        tool: str,
        severity: str,
        cve: str = "",
        extra: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Render the Connections table that appears at the top of every note.
        Each cell is a wikilink → Obsidian graph edge.
        """
        rows = [
            ("Engagement", self._eng_link()),
            ("Target",     self._target_link(target)),
            ("Tool",       self._tool_link(tool)),
            ("Severity",   self._sev_link(severity)),
        ]
        if cve:
            rows.append(("CVE", self._cve_link(cve)))
        if extra:
            rows.extend(extra.items())

        header = "| Connection | Node |\n|---|---|\n"
        body = "".join(f"| **{k}** | {v} |\n" for k, v in rows)
        return f"## Connections\n\n{header}{body}"

    # ── Public API ────────────────────────────────────────────────────────────

    def save_scan_result(
        self,
        result: Dict[str, Any],
        target: str,
        tool: str,
        tags: Optional[List[str]] = None,
    ) -> Path:
        """Save a raw HexStrike tool result as a connected finding note."""
        tags = tags or []
        slug = _fn(f"{_today()}-{tool}-{target}")
        note_path = self._eng_dir / "Findings" / f"{slug}.md"

        stdout    = result.get("output") or result.get("stdout") or ""
        stderr    = result.get("stderr", "")
        exit_code = result.get("exit_code", result.get("returncode", "?"))
        command   = result.get("command", "")
        severity  = _detect_severity(stdout)
        emoji     = SEV_EMOJI.get(severity, "⚪")

        all_tags = [
            "hexstrike", "scan",
            f"tool/{_fn(tool)}",
            f"target/{_fn(target)}",
            SEV_TAG[severity],
        ] + tags

        content = f"""\
---
title: "{emoji} {tool} — {target}"
date: "{_now()}"
target: "{target}"
tool: "{tool}"
severity: "{severity}"
exit_code: {exit_code}
engagement: "{self.eng}"
tags: {_yml(all_tags)}
---

# {emoji} {tool} — `{target}`

{self._conn_table(target, tool, severity)}

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
            content += "\n## Vulnerabilities\n\n"
            for v in result["vulnerabilities"]:
                vs = v.get("severity", "info").lower()
                content += (
                    f"- {SEV_EMOJI.get(vs,'⚪')} **{v.get('name','Unknown')}**"
                    + (f" — {v['description']}" if v.get("description") else "")
                    + "\n"
                )

        note_path.write_text(content, encoding="utf-8")
        self._ensure_tool_hub(tool)
        self._ensure_target_note(target)
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
        """Save a structured vulnerability finding as a connected note."""
        tags = tags or []
        severity = severity.lower()
        slug = _fn(f"{_today()}-{name}-{target}")
        note_path = self._eng_dir / "Findings" / f"{slug}.md"
        emoji = SEV_EMOJI.get(severity, "⚪")

        all_tags = [
            "hexstrike", "finding",
            f"target/{_fn(target)}",
            SEV_TAG.get(severity, "severity/info"),
        ]
        if cve:
            all_tags.append(f"cve/{_fn(cve)}")
        all_tags += tags

        content = f"""\
---
title: "{emoji} {name}"
date: "{_now()}"
target: "{target}"
severity: "{severity}"
cve: "{cve}"
status: "open"
engagement: "{self.eng}"
tags: {_yml(all_tags)}
---

# {emoji} {name}

{self._conn_table(target, "manual", severity, cve)}

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
        if cve:
            self._ensure_cve_hub(cve)
        self._ensure_target_note(target)
        self._update_dashboard()
        return note_path

    def save_engagement_overview(
        self,
        scope: Optional[List[str]] = None,
        objectives: str = "",
        notes: str = "",
    ) -> Path:
        """Create or append to the engagement overview hub note."""
        scope = scope or []
        note_path = self._eng_dir / "_Overview.md"

        if note_path.exists():
            existing = note_path.read_text(encoding="utf-8")
            note_path.write_text(
                existing + f"\n\n---\n\n**Update {_now()}**\n\n{notes}\n",
                encoding="utf-8",
            )
            return note_path

        scope_lines = "\n".join(f"- `{s}`" for s in scope) if scope else "- _Not defined_"
        content = f"""\
---
title: "Engagement: {self.eng}"
date: "{_now()}"
engagement: "{self.eng}"
status: "active"
tags: {_yml(["hexstrike", "engagement"])}
---

# Engagement: {self.eng}

{_wl("HexStrike/Dashboard", "← Dashboard")}

> **Created:** {_now()} | **Status:** 🟢 Active

## Scope

{scope_lines}

## Objectives

{objectives or "_Not defined._"}

## Notes

{notes or "_No notes yet._"}

## Targets

```dataview
LIST
FROM "HexStrike/Engagements/{_fn(self.eng)}/Targets"
SORT file.name ASC
```

## Findings by Severity

```dataview
TABLE target, severity, tool, date
FROM "HexStrike/Engagements/{_fn(self.eng)}/Findings"
SORT severity ASC, date DESC
```
"""
        note_path.write_text(content, encoding="utf-8")
        return note_path

    # ── Hub note creation ─────────────────────────────────────────────────────

    def _ensure_tool_hub(self, tool: str) -> Path:
        path = self._tools_dir / f"{_fn(tool)}.md"
        if not path.exists():
            path.write_text(
                f"""\
---
title: "Tool: {tool}"
tool: "{tool}"
tags: ["hexstrike", "tool", "tool/{_fn(tool)}"]
---

# Tool: {tool}

{_wl("HexStrike/Dashboard", "← Dashboard")}

## All Scans with {tool}

```dataview
TABLE target, severity, engagement, date
FROM "HexStrike/Engagements"
WHERE tool = "{tool}"
SORT date DESC
```
""",
                encoding="utf-8",
            )
        return path

    def _ensure_cve_hub(self, cve: str) -> Path:
        path = self._cves_dir / f"{_fn(cve)}.md"
        if not path.exists():
            path.write_text(
                f"""\
---
title: "CVE: {cve}"
cve: "{cve}"
tags: ["hexstrike", "cve", "cve/{_fn(cve)}"]
---

# CVE: {cve}

{_wl("HexStrike/Dashboard", "← Dashboard")}

## Affected Findings

```dataview
TABLE target, severity, engagement, date
FROM "HexStrike/Engagements"
WHERE cve = "{cve}"
SORT date DESC
```
""",
                encoding="utf-8",
            )
        return path

    def _ensure_target_note(self, target: str) -> Path:
        path = self._eng_dir / "Targets" / f"{_fn(target)}.md"
        if not path.exists():
            path.write_text(
                f"""\
---
title: "Target: {target}"
date: "{_now()}"
target: "{target}"
engagement: "{self.eng}"
tags: {_yml(["hexstrike", "target", f"target/{_fn(target)}"])}
---

# Target: `{target}`

> **Engagement:** {self._eng_link()}
> **First seen:** {_now()}

## Findings

```dataview
TABLE severity, tool, date
FROM "HexStrike/Engagements/{_fn(self.eng)}/Findings"
WHERE target = "{target}"
SORT severity ASC, date DESC
```

## Notes

<!-- Manual notes about this target -->
""",
                encoding="utf-8",
            )
        return path

    # ── Dashboard ─────────────────────────────────────────────────────────────

    def _update_dashboard(self) -> Path:
        dash = self.vault / "HexStrike" / "Dashboard.md"
        eng_dir = self.vault / "HexStrike" / "Engagements"

        eng_links = ""
        if eng_dir.exists():
            for d in sorted(eng_dir.iterdir()):
                if d.is_dir():
                    eng_links += f"- {_wl(f'HexStrike/Engagements/{d.name}/_Overview', d.name)}\n"

        content = f"""\
---
title: "HexStrike Dashboard"
date_updated: "{_now()}"
tags: ["hexstrike", "dashboard"]
---

# HexStrike AI — Dashboard

> Updated: {_now()}

## Engagements

{eng_links or "_No engagements yet._"}

## Hubs

| Type | Index |
|---|---|
| Tools | {_wl("HexStrike/Tools")} |
| CVEs | {_wl("HexStrike/CVEs")} |
| Severity | {_wl("HexStrike/Severity")} |

## All Findings

```dataview
TABLE target, severity, tool, engagement, date
FROM "HexStrike/Engagements"
WHERE contains(tags, "hexstrike")
SORT severity ASC, date DESC
```

## Critical & High

```dataview
TABLE target, tool, date
FROM "HexStrike/Engagements"
WHERE severity = "critical" OR severity = "high"
SORT date DESC
```

## Open Vulnerabilities

```dataview
TABLE target, severity, cve, date
FROM "HexStrike/Engagements"
WHERE status = "open"
SORT severity ASC
```
"""
        dash.parent.mkdir(parents=True, exist_ok=True)
        dash.write_text(content, encoding="utf-8")
        return dash


# ─── Severity detection ───────────────────────────────────────────────────────

_RE_CRITICAL = re.compile(
    r"critical|rce|remote code exec|command injection|sql injection|"
    r"authentication bypass|privilege escalation",
    re.IGNORECASE,
)
_RE_HIGH   = re.compile(r"\bhigh\b|xss|ssrf|xxe|idor|open redirect|path traversal|lfi|rfi", re.IGNORECASE)
_RE_MEDIUM = re.compile(r"\bmedium\b|csrf|information disclosure|directory listing|weak cipher", re.IGNORECASE)
_RE_LOW    = re.compile(r"\blow\b|banner|version disclosure|clickjack|missing header", re.IGNORECASE)


def _detect_severity(text: str) -> str:
    if _RE_CRITICAL.search(text): return "critical"
    if _RE_HIGH.search(text):     return "high"
    if _RE_MEDIUM.search(text):   return "medium"
    if _RE_LOW.search(text):      return "low"
    return "info"


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Save HexStrike results to Obsidian with rich connections",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--vault", default=DEFAULT_VAULT,
                   help="Vault path (default: %(default)s or $OBSIDIAN_VAULT_PATH)")
    p.add_argument("--engagement", default="Default",
                   help="Engagement name (default: %(default)s)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="Save a raw tool result")
    sc.add_argument("--target", required=True)
    sc.add_argument("--tool",   required=True)
    sc.add_argument("--result", help="JSON file path (default: stdin)")
    sc.add_argument("--tags",   nargs="*", default=[])

    vp = sub.add_parser("vuln", help="Save a structured vulnerability")
    vp.add_argument("--target",      required=True)
    vp.add_argument("--name",        required=True)
    vp.add_argument("--severity",    choices=["critical","high","medium","low","info"], default="info")
    vp.add_argument("--description", default="")
    vp.add_argument("--evidence",    default="")
    vp.add_argument("--cve",         default="")
    vp.add_argument("--remediation", default="")
    vp.add_argument("--tags",        nargs="*", default=[])

    ep = sub.add_parser("engagement", help="Create/update engagement overview")
    ep.add_argument("--scope",      nargs="*", default=[])
    ep.add_argument("--objectives", default="")
    ep.add_argument("--notes",      default="")

    return p


def main() -> None:
    args = _build_parser().parse_args()
    obs = ObsidianIntegration(vault_path=args.vault, engagement=args.engagement)

    if args.cmd == "scan":
        src = open(args.result, encoding="utf-8") if args.result else sys.stdin
        with src:
            result = json.load(src)
        path = obs.save_scan_result(result, target=args.target, tool=args.tool, tags=args.tags)

    elif args.cmd == "vuln":
        path = obs.save_vulnerability(
            name=args.name, target=args.target, severity=args.severity,
            description=args.description, evidence=args.evidence,
            cve=args.cve, remediation=args.remediation, tags=args.tags,
        )

    elif args.cmd == "engagement":
        path = obs.save_engagement_overview(
            scope=args.scope, objectives=args.objectives, notes=args.notes,
        )

    print(f"Saved: {path}")


if __name__ == "__main__":
    main()
