"""Command line entry point.

    python -m nobetci --sites sites.json
    python -m nobetci --sites sites.json --format markdown
    python -m nobetci --url https://example.com --once

Exit codes exist so this can be a cron job that only emails you when it matters:
    0 = nothing wrong · 1 = something needs attention · 2 = could not run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import report
from .classify import build
from .runner import run_all

DEFAULT_STATE = Path(".nobetci")


def load_sites(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    sites = data["sites"] if isinstance(data, dict) else data
    for site in sites:
        if "url" not in site:
            raise ValueError(f"site entry missing 'url': {site}")
    return sites


def main(argv: list[str] | None = None) -> int:
    # The Windows console defaults to cp1252, which cannot encode 'ı', 'ş' or
    # 'ğ'. Every message this tool prints is Turkish, so without this the whole
    # program dies on its own output.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

    parser = argparse.ArgumentParser(
        prog="nobetci",
        description="Watch client websites for hacks, expiry and breakage.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sites", type=Path, help="JSON file listing sites to watch")
    source.add_argument("--url", help="check a single URL without a config file")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE,
                        help="where snapshots are kept (default: .nobetci)")
    parser.add_argument("--format", choices=("console", "json", "markdown"), default="console")
    parser.add_argument("--shallow", action="store_true",
                        help="skip fetching sitemaps and new pages; faster, less thorough")
    parser.add_argument("--no-ai", action="store_true",
                        help="never call the API; term matching only")
    args = parser.parse_args(argv)

    try:
        sites = [{"url": args.url}] if args.url else load_sites(args.sites)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Could not read the site list: {exc}", file=sys.stderr)
        return 2

    # Only reach for the API if a key is actually present. Never prompt, never
    # fail because one is missing — the tool must be useful before it costs money.
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    classifier = build(use_claude=has_key and not args.no_ai)

    run = run_all(sites, state_dir=args.state, classifier=classifier, deep=not args.shallow)

    renderers = {
        "console": report.render_console,
        "json": report.render_json,
        "markdown": report.render_markdown,
    }
    print(renderers[args.format](run))
    return 1 if run.alarming else 0


if __name__ == "__main__":
    raise SystemExit(main())
