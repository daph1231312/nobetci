"""Per-site snapshots, so a run can say what *changed* rather than what exists.

Kept as one JSON file per site under a state directory. Plain files on purpose:
the whole tool should be inspectable and repairable by hand at 2am, and a
monitoring tool that needs its own database server is a second thing to monitor.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

SAFE = re.compile(r"[^a-z0-9.-]+")


@dataclass
class Snapshot:
    site: str
    robots: str = ""
    robots_sitemaps: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    homepage_text: str = ""
    seen: bool = False
    """False until a first successful run has stored a baseline. Diff-based
    checks stay silent until this is True, otherwise every site screams on the
    day it is added and the operator learns to ignore the tool."""

    @classmethod
    def load(cls, directory: Path, site: str) -> Snapshot:
        path = _path(directory, site)
        if not path.exists():
            return cls(site=site)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls(site=site)
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        path = _path(directory, self.site)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)  # atomic: a killed run must not leave half a snapshot


def _path(directory: Path, site: str) -> Path:
    stem = SAFE.sub("_", site.lower().replace("https://", "").replace("http://", "").strip("/"))
    return directory / f"{stem}.json"


def added(previous: list[str], current: list[str]) -> list[str]:
    known = set(previous)
    return [item for item in current if item not in known]
