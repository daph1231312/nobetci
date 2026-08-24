"""Deciding whether new page content is hostile.

Two tiers:

  1. `heuristics.scan` settles the blatant cases for free.
  2. Anything ambiguous — new text with a single weak signal, or a lot of new
     text with no signal at all — is escalated to Claude, which can tell a
     casino landing page from a law firm's article about gambling regulation.

The Claude tier is optional. Nöbetçi runs and reports without an API key; it
just escalates nothing and says so in the output, rather than pretending the
ambiguous cases were checked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol

from . import heuristics

MODEL = "claude-opus-5"

# The tool's job is to read attacker-authored spam and report on it. That is
# exactly the shape of request a safety classifier may decline, and a declined
# request would otherwise surface as "no verdict" — i.e. a silent monitoring
# gap. Server-side fallbacks reroute those instead of dropping them.
FALLBACK_BETA = "server-side-fallback-2026-07-01"

SYSTEM = """You review text extracted from a web page belonging to a small business, to decide whether the page has been compromised and filled with injected spam.

Injected spam on hacked sites is usually gambling, betting, casino, pharmacy, adult, or SEO backlink content, and is usually unrelated to what the business actually does. Turkish gambling spam is the most common variety.

Be careful about legitimate exceptions. A law firm may discuss gambling regulation. A news site may report on betting. A pharmacy's own site legitimately lists medicines. Judge whether the content BELONGS on this business's site, not merely whether the topic appears.

Reply with a single JSON object and nothing else:
{"label": "hostile" | "benign" | "unclear", "confidence": 0.0-1.0, "reason": "<one sentence>"}"""


@dataclass
class Verdict:
    label: str  # "hostile" | "benign" | "unclear"
    confidence: float
    reason: str
    source: str  # "heuristic" | "claude" | "skipped"
    terms: list[str] = field(default_factory=list)

    @property
    def hostile(self) -> bool:
        return self.label == "hostile"


class Classifier(Protocol):
    def classify(self, *, business: str, url: str, text: str) -> Verdict: ...


class HeuristicClassifier:
    """Term matching only. Never escalates — used when no API key is configured."""

    def classify(self, *, business: str, url: str, text: str) -> Verdict:
        signals = heuristics.scan(text)
        best = heuristics.strongest(signals)
        if best and best.strong:
            return Verdict(
                "hostile",
                0.9,
                f"{len(best.terms)} {best.category} spam terms in page text",
                "heuristic",
                best.terms,
            )
        if best:
            return Verdict(
                "unclear",
                0.4,
                f"one {best.category} term found; needs a second opinion",
                "skipped",
                best.terms,
            )
        return Verdict("benign", 0.6, "no known spam terms", "heuristic")


class ClaudeClassifier:
    """Escalation tier. Imports the SDK lazily so the package keeps working
    with no dependencies installed and no key configured."""

    def __init__(self, model: str = MODEL) -> None:
        import anthropic  # noqa: PLC0415 - optional dependency, imported on use

        self._anthropic = anthropic
        self._client = anthropic.Anthropic()
        self._model = model

    def classify(self, *, business: str, url: str, text: str) -> Verdict:
        prompt = (
            f"Business: {business}\n"
            f"Page: {url}\n\n"
            f"Extracted text:\n{text[:6000]}"
        )
        try:
            response = self._client.beta.messages.create(
                model=self._model,
                max_tokens=256,
                system=SYSTEM,
                messages=[{"role": "user", "content": prompt}],
                output_config={"effort": "low"},
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
        except Exception as exc:  # noqa: BLE001 - an API failure is a gap, not a crash
            return Verdict("unclear", 0.0, f"classifier unavailable: {exc}", "skipped")

        if response.stop_reason == "refusal":
            return Verdict("unclear", 0.0, "model declined to classify this content", "skipped")

        raw = "".join(b.text for b in response.content if b.type == "text").strip()
        return _parse(raw)


def _parse(raw: str) -> Verdict:
    """Tolerant parse — a classifier that crashes on a stray code fence is worse
    than one that says 'unclear'."""
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw.split("\n", 1)[-1] if "\n" in raw else raw
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1:
        return Verdict("unclear", 0.0, "unparseable classifier reply", "skipped")
    try:
        data = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return Verdict("unclear", 0.0, "unparseable classifier reply", "skipped")

    label = str(data.get("label", "unclear")).lower()
    if label not in {"hostile", "benign", "unclear"}:
        label = "unclear"
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    return Verdict(label, confidence, str(data.get("reason", "")).strip(), "claude")


class TieredClassifier:
    """Heuristics first, Claude only for the cases heuristics cannot settle."""

    def __init__(self, escalate_to: Classifier | None) -> None:
        self._heuristic = HeuristicClassifier()
        self._escalation = escalate_to

    def classify(self, *, business: str, url: str, text: str) -> Verdict:
        verdict = self._heuristic.classify(business=business, url=url, text=text)
        if verdict.label != "unclear" and verdict.confidence >= 0.85:
            return verdict
        if self._escalation is None:
            return verdict
        escalated = self._escalation.classify(business=business, url=url, text=text)
        # Keep the terms the heuristic found — they are the evidence a human
        # reads first in the alert, regardless of who made the final call.
        escalated.terms = escalated.terms or verdict.terms
        return escalated


def build(*, use_claude: bool) -> Classifier:
    if not use_claude:
        return HeuristicClassifier()
    try:
        return TieredClassifier(ClaudeClassifier())
    except Exception:  # noqa: BLE001 - no SDK installed, or no credentials
        return HeuristicClassifier()
