"""Turning a page into the few things worth comparing between runs.

We store visible text and links, not raw HTML. Raw HTML changes constantly for
boring reasons — a rotated nonce, a cache-busting query string, an ad slot — and
a monitor that cries wolf on those gets muted within a week, which is the same
as not having a monitor.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

IGNORED_TAGS = {"script", "style", "noscript", "svg", "template"}
WHITESPACE = re.compile(r"\s+")


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self.links: list[str] = []
        self.title: str = ""
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in IGNORED_TAGS:
            self._skip_depth += 1
            return
        if tag == "title":
            self._in_title = True
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in IGNORED_TAGS and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
            return
        text = data.strip()
        if text:
            self.chunks.append(text)


class Page:
    def __init__(self, url: str, html: str) -> None:
        parser = _Extractor()
        try:
            parser.feed(html)
        except Exception:  # noqa: BLE001 - malformed markup is common and not fatal
            pass

        self.url = url
        self.title = WHITESPACE.sub(" ", parser.title).strip()
        self.text = WHITESPACE.sub(" ", " ".join(parser.chunks)).strip()
        self.links = parser.links

    def internal_links(self) -> list[str]:
        """Absolute, same-host, de-duplicated, fragment- and query-free."""
        host = urlsplit(self.url).hostname
        found: dict[str, None] = {}
        for href in self.links:
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            absolute = urljoin(self.url, href)
            split = urlsplit(absolute)
            if split.scheme not in ("http", "https") or split.hostname != host:
                continue
            found.setdefault(f"{split.scheme}://{split.netloc}{split.path}".rstrip("/"), None)
        return list(found)


SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def sitemap_urls(xml: str) -> list[str]:
    return SITEMAP_LOC.findall(xml)


SITEMAP_DIRECTIVE = re.compile(r"^\s*sitemap:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def robots_sitemaps(robots_txt: str) -> list[str]:
    """Injected sitemap directives in robots.txt are a classic SEO-spam tell —
    it is how a compromised site tells Google to index the pages it just grew.
    The real one had 51 of them."""
    return SITEMAP_DIRECTIVE.findall(robots_txt)
