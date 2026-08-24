"""Cheap first-pass detection of injected SEO spam.

This is not a fallback for the LLM — it is the first tier of a two-tier design.
Most injected spam is blatant and matching a term list costs nothing, so obvious
cases are settled here and never reach the API. Only genuinely ambiguous text
gets escalated. On a site checked every six hours that is the difference between
a few cents a month and a bill worth arguing about.

Turkish gambling spam dominates this category for Turkish sites, so the term
list leads with it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Terms are matched on a normalised (accent-folded, lowercased) copy of the text,
# so "bahis", "BAHİS" and "bahıs" all land on the same entry.
GAMBLING_TR = [
    "bahis", "bahis sitesi", "canli bahis", "iddaa", "kumar", "casino", "kasino",
    "slot oyunlari", "rulet", "poker", "deneme bonusu", "bonus veren siteler",
    "guvenilir bahis", "bets10", "jackpot", "kacak bahis", "giris adresi",
    "yatirim bonusu", "cevrimsiz bonus", "bahis siteleri",
]
GAMBLING_EN = [
    "online casino", "sports betting", "free spins", "no deposit bonus",
    "slot machine", "betting site", "gambling",
]
PHARMA = ["viagra", "cialis", "tadalafil", "sildenafil"]
OTHER_SPAM = ["escort", "replica watches", "porno", "hacklink", "backlink satisi"]

TERMS: dict[str, list[str]] = {
    "gambling": GAMBLING_TR + GAMBLING_EN,
    "pharma": PHARMA,
    "other": OTHER_SPAM,
}

# Two or more distinct hits is a strong signal; one may be legitimate (a news
# article about gambling regulation, a law firm listing gambling law).
STRONG_HIT_COUNT = 2


def normalise(text: str) -> str:
    """Lowercase and strip diacritics so Turkish spelling variants collapse.

    Turkish dotted/dotless i is handled explicitly: str.lower() maps 'İ' to 'i̇'
    (i + combining dot), and 'I' to 'i', neither of which NFKD alone resolves the
    way a reader would expect.
    """
    text = text.replace("İ", "i").replace("I", "i").replace("ı", "i")
    text = text.lower()
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


@dataclass
class Signal:
    category: str
    terms: list[str]

    @property
    def strong(self) -> bool:
        return len(self.terms) >= STRONG_HIT_COUNT


def scan(text: str) -> list[Signal]:
    """Return one Signal per category that matched at least once."""
    hay = normalise(text)
    signals: list[Signal] = []
    for category, terms in TERMS.items():
        found = sorted({t for t in terms if re.search(rf"\b{re.escape(normalise(t))}", hay)})
        if found:
            signals.append(Signal(category, found))
    return signals


def strongest(signals: list[Signal]) -> Signal | None:
    if not signals:
        return None
    return max(signals, key=lambda s: len(s.terms))
