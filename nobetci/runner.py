"""The check loop: fetch, compare against the last snapshot, classify, report."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import extract, store
from .classify import Classifier
from .fetch import certificate, fetch
from .report import CRITICAL, INFO, WARNING, Finding, Run

CERT_CRITICAL_DAYS = 14
CERT_WARNING_DAYS = 30
SLOW_MS = 4000
# A handful of new pages is a business publishing things. Dozens overnight is
# not — the real case that prompted this tool grew 65 pages and 51 sitemaps.
BULK_NEW_PAGES = 15
# A real site declares one sitemap, sometimes a few. Dozens is an injection.
BULK_SITEMAPS = 5


def check_site(
    site: dict,
    *,
    state_dir: Path,
    classifier: Classifier,
    deep: bool = True,
) -> list[Finding]:
    url = site["url"].rstrip("/")
    name = site.get("name") or urlsplit(url).hostname or url
    business = site.get("business", name)
    findings: list[Finding] = []

    snapshot = store.Snapshot.load(state_dir, url)
    baseline = not snapshot.seen

    home = fetch(url)
    if not home.ok:
        findings.append(
            Finding(
                name,
                "unreachable",
                CRITICAL,
                "Site açılmıyor",
                f"{url} isteğe yanıt vermedi: {home.error or f'HTTP {home.status}'}. "
                "Müşteriniz bu sırada siteyi göremiyor.",
            )
        )
        snapshot.save(state_dir)
        return findings

    if home.elapsed_ms > SLOW_MS:
        findings.append(
            Finding(
                name,
                "slow",
                WARNING,
                "Site yavaş açılıyor",
                f"Ana sayfa {home.elapsed_ms} ms'de geldi. Ziyaretçilerin bir kısmı "
                "sayfa açılmadan vazgeçer.",
            )
        )

    findings += _check_https(url, name)
    findings += _check_certificate(url, name)

    robots_findings, robots_text, robots_maps = _check_robots(url, name, snapshot, baseline)
    findings += robots_findings

    page = extract.Page(home.final_url, home.body)
    pages_now = page.internal_links()
    sitemap_now: list[str] = []
    if deep:
        sitemap_now = _sitemap_urls(url, robots_maps)

    discovered = sorted(set(store.added(snapshot.pages, pages_now)) | set(store.added(snapshot.sitemap_urls, sitemap_now)))

    if not baseline and discovered:
        findings += _check_new_pages(name, business, discovered, classifier, deep=deep)

    # Content is judged on the first run too, not only on change. A client whose
    # site is already compromised when you take them on must be told on day one
    # — "baseline captured, nothing to report" would be the worst possible
    # answer to the exact situation this tool exists for.
    if baseline or (snapshot.homepage_text and page.text != snapshot.homepage_text):
        verdict = classifier.classify(business=business, url=home.final_url, text=page.text)
        if verdict.hostile:
            findings.append(
                Finding(
                    name,
                    "homepage_content",
                    CRITICAL,
                    "Ana sayfada olmaması gereken içerik var",
                    ("Ana sayfa zararlı içerik barındırıyor: " if baseline
                     else "Ana sayfanın metni değişti ve içerik zararlı görünüyor: ") + verdict.reason,
                    verdict.terms,
                )
            )

    snapshot.robots = robots_text
    snapshot.robots_sitemaps = robots_maps
    snapshot.sitemap_urls = sitemap_now or snapshot.sitemap_urls
    snapshot.pages = sorted(set(snapshot.pages) | set(pages_now)) if not baseline else pages_now
    snapshot.homepage_text = page.text
    snapshot.seen = True
    snapshot.save(state_dir)

    if baseline:
        findings.append(
            Finding(
                name,
                "baseline",
                INFO,
                "İlk kayıt alındı",
                f"{len(pages_now)} sayfa ve robots.txt kaydedildi. Bundan sonraki "
                "kontroller bu kayda göre karşılaştırılacak.",
            )
        )

    return findings


def _check_https(url: str, name: str) -> list[Finding]:
    """An https URL that works tells us nothing about what a visitor typing the
    bare domain gets. Ask for http:// explicitly and refuse to be redirected."""
    parts = urlsplit(url)
    plain = urlunsplit(("http", parts.netloc, parts.path or "/", "", ""))
    response = fetch(plain, follow_redirects=False)

    if response.status is None:
        return []
    location = response.headers.get("location", "")
    if response.status in (301, 302, 307, 308) and location.startswith("https://"):
        return []
    if response.status == 200:
        return [
            Finding(
                name,
                "no_https_redirect",
                WARNING,
                "HTTP adresi HTTPS'e yönlendirilmiyor",
                f"{plain} adresi düz HTTP üzerinden açılıyor. Tarayıcı adres "
                "çubuğunda \"Güvenli değil\" uyarısı gösterebilir.",
            )
        ]
    return []


def _check_certificate(url: str, name: str) -> list[Finding]:
    cert = certificate(url)
    if cert.error:
        return [
            Finding(
                name,
                "cert_error",
                CRITICAL,
                "Güvenlik sertifikası doğrulanmıyor",
                f"{cert.error}. Ziyaretçiler siteye girerken tam sayfa uyarı görür.",
            )
        ]
    days = cert.days_left
    if days is None:
        return []
    if days < 0:
        return [Finding(name, "cert_expired", CRITICAL, "Sertifika süresi dolmuş",
                        f"{abs(days)} gün önce doldu. Site şu anda uyarı veriyor.")]
    if days <= CERT_CRITICAL_DAYS:
        return [Finding(name, "cert_expiring", CRITICAL, "Sertifika birkaç gün içinde bitiyor",
                        f"{days} gün kaldı ({cert.issuer or 'sağlayıcı bilinmiyor'}). Yenilenmezse site uyarı vermeye başlar.")]
    if days <= CERT_WARNING_DAYS:
        return [Finding(name, "cert_expiring", WARNING, "Sertifika yakında bitiyor",
                        f"{days} gün kaldı ({cert.issuer or 'sağlayıcı bilinmiyor'}).")]
    return []


def _check_robots(url: str, name: str, snapshot: store.Snapshot, baseline: bool):
    response = fetch(f"{url}/robots.txt")
    if not response.ok:
        return [], snapshot.robots, snapshot.robots_sitemaps

    text = response.body
    maps = extract.robots_sitemaps(text)

    if baseline:
        # No previous snapshot to diff against, so judge the absolute count.
        # A legitimate site declares one sitemap, occasionally a handful; a
        # wall of them is the signature of an SEO-spam injection.
        if len(maps) >= BULK_SITEMAPS:
            return (
                [
                    Finding(
                        name,
                        "robots_sitemaps",
                        CRITICAL,
                        f"robots.txt dosyasında {len(maps)} adet site haritası var",
                        "Normal bir sitede bir, en fazla birkaç tane olur. Bu kadarı, "
                        "ele geçirilmiş sitelerde eklenen sayfaların Google'a taratılması "
                        "için kullanılan bilinen bir yöntemdir.",
                        maps[:10],
                    )
                ],
                text,
                maps,
            )
        return [], text, maps

    new_maps = store.added(snapshot.robots_sitemaps, maps)
    findings: list[Finding] = []
    if new_maps:
        severity = CRITICAL if len(new_maps) >= 5 else WARNING
        findings.append(
            Finding(
                name,
                "robots_sitemaps",
                severity,
                f"robots.txt dosyasına {len(new_maps)} yeni site haritası eklenmiş",
                "Site haritası satırları Google'a hangi sayfaların taranacağını söyler. "
                "Toplu eklenmeleri, ele geçirilmiş sitelerde eklenen sayfaların "
                "aratılmada çıkması için kullanılan bilinen bir yöntemdir.",
                new_maps,
            )
        )
    elif text != snapshot.robots:
        findings.append(
            Finding(name, "robots_changed", WARNING, "robots.txt değişmiş",
                    "Dosyanın içeriği son kontrolden bu yana değişti. Siz değiştirmediyseniz bakılmalı.")
        )
    return findings, text, maps


def _sitemap_urls(url: str, declared: list[str]) -> list[str]:
    """Read the site's own sitemaps. Only ones it declares or the conventional
    path — we never guess at URLs."""
    candidates = list(dict.fromkeys([*declared, f"{url}/sitemap.xml"]))
    found: list[str] = []
    for candidate in candidates[:12]:  # a compromised robots.txt can list dozens
        response = fetch(candidate)
        if response.ok:
            found.extend(extract.sitemap_urls(response.body))
    return list(dict.fromkeys(found))


def _check_new_pages(
    name: str,
    business: str,
    discovered: list[str],
    classifier: Classifier,
    *,
    deep: bool,
) -> list[Finding]:
    findings: list[Finding] = []

    if len(discovered) >= BULK_NEW_PAGES:
        findings.append(
            Finding(
                name,
                "bulk_new_pages",
                CRITICAL,
                f"{len(discovered)} yeni sayfa birden ortaya çıktı",
                "Bu kadar sayfanın aynı anda eklenmesi normal bir güncellemeye benzemiyor. "
                "Sitenin ele geçirilip toplu içerik basıldığı durumlarda görülür.",
                discovered[:10],
            )
        )

    if not deep:
        return findings

    hostile: list[str] = []
    reasons: list[str] = []
    for target in discovered[:8]:  # cap the per-run cost; the rest come next run
        response = fetch(target)
        if not response.ok:
            continue
        text = extract.Page(response.final_url, response.body).text
        if not text:
            continue
        verdict = classifier.classify(business=business, url=target, text=text)
        if verdict.hostile:
            hostile.append(target)
            if verdict.reason:
                reasons.append(verdict.reason)

    if hostile:
        findings.append(
            Finding(
                name,
                "spam_pages",
                CRITICAL,
                f"{len(hostile)} yeni sayfada zararlı içerik bulundu",
                (reasons[0] if reasons else "Sayfalar işletmenin işiyle ilgisiz görünüyor.")
                + " Bu sayfalar sizin markanız altında yayınlanıyor ve arama motorları bunları görüyor.",
                hostile,
            )
        )
    elif discovered and len(discovered) < BULK_NEW_PAGES:
        findings.append(
            Finding(name, "new_pages", INFO, f"{len(discovered)} yeni sayfa eklendi",
                    "İçerik zararlı görünmüyor. Sizin eklediğiniz sayfalarsa yapılacak bir şey yok.",
                    discovered[:6])
        )

    return findings


def run_all(sites: list[dict], *, state_dir: Path, classifier: Classifier, deep: bool = True) -> Run:
    run = Run.start()
    run.classifier = type(classifier).__name__
    for site in sites:
        name = site.get("name") or site["url"]
        run.checked.append(name)
        run.findings.extend(check_site(site, state_dir=state_dir, classifier=classifier, deep=deep))
    return run
