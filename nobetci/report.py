"""Findings and how they are rendered.

An alert is read by a business owner, not by an engineer, so every finding
carries a plain sentence about what it means and what to do. A monitor that
says `TLS_EXPIRY_WARN: 12` teaches the reader to ignore it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

CRITICAL = "critical"
WARNING = "warning"
INFO = "info"

_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
_MARK = {CRITICAL: "!!", WARNING: " !", INFO: "  "}


@dataclass
class Finding:
    site: str
    kind: str
    severity: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    def sort_key(self) -> tuple[int, str]:
        return (_ORDER.get(self.severity, 9), self.site)


@dataclass
class Run:
    started: str
    findings: list[Finding] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    classifier: str = "heuristic"

    @classmethod
    def start(cls) -> Run:
        return cls(started=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == CRITICAL]

    @property
    def alarming(self) -> bool:
        return any(f.severity in (CRITICAL, WARNING) for f in self.findings)


def render_console(run: Run) -> str:
    lines: list[str] = []
    lines.append(f"Nöbetçi — {run.started}")
    lines.append(f"{len(run.checked)} site checked · classifier: {run.classifier}")
    lines.append("")

    if not run.findings:
        lines.append("  Nothing to report. Every site reachable, no changes worth flagging.")
        return "\n".join(lines)

    for finding in sorted(run.findings, key=Finding.sort_key):
        lines.append(f"{_MARK.get(finding.severity, '  ')} [{finding.site}] {finding.title}")
        lines.append(f"     {finding.detail}")
        for item in finding.evidence[:6]:
            lines.append(f"       · {item}")
        if len(finding.evidence) > 6:
            lines.append(f"       · … and {len(finding.evidence) - 6} more")
        lines.append("")

    counts = {
        level: sum(1 for f in run.findings if f.severity == level)
        for level in (CRITICAL, WARNING, INFO)
    }
    lines.append(
        f"  {counts[CRITICAL]} critical · {counts[WARNING]} warning · {counts[INFO]} info"
    )
    return "\n".join(lines)


def render_json(run: Run) -> str:
    return json.dumps(asdict(run), ensure_ascii=False, indent=2)


def render_markdown(run: Run) -> str:
    """For pasting into an email or a WhatsApp message to the client."""
    lines = [f"# Site kontrolü — {run.started[:10]}", ""]
    if not run.findings:
        lines.append("Bir sorun görünmüyor. Bütün siteler erişilebilir durumda.")
        return "\n".join(lines)

    for level, heading in ((CRITICAL, "Acil"), (WARNING, "Dikkat"), (INFO, "Bilgi")):
        group = [f for f in run.findings if f.severity == level]
        if not group:
            continue
        lines.append(f"## {heading}")
        lines.append("")
        for finding in group:
            lines.append(f"**{finding.site} — {finding.title}**")
            lines.append("")
            lines.append(finding.detail)
            lines.append("")
            for item in finding.evidence[:8]:
                lines.append(f"- `{item}`")
            lines.append("")
    return "\n".join(lines)
