"""HTTP and TLS fetching.

Deliberately stdlib-only and read-only. Nöbetçi looks at pages the way any
visitor would: it requests public URLs and reads what comes back. It never
probes, never guesses paths, never sends anything but GET. A monitoring tool
that behaves like a scanner gets its IP blocked and its owner in trouble.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

USER_AGENT = "Nobetci/0.1 (+site monitoring; contact your provider)"
TIMEOUT = 20


@dataclass
class Response:
    url: str
    final_url: str
    status: int | None
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 400


def fetch(url: str, *, follow_redirects: bool = True) -> Response:
    """GET a URL. Never raises — a failure is a Response with `error` set,
    because an unreachable site is a finding, not a crash."""
    started = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    opener = urllib.request.build_opener()
    if not follow_redirects:
        opener = urllib.request.build_opener(_NoRedirect)

    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            raw = response.read(3_000_000)  # cap: we only need the document
            charset = response.headers.get_content_charset() or "utf-8"
            return Response(
                url=url,
                final_url=response.geturl(),
                status=response.status,
                body=raw.decode(charset, errors="replace"),
                headers={k.lower(): v for k, v in response.headers.items()},
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is a real answer from the server, not a transport failure.
        body = ""
        try:
            body = exc.read(200_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return Response(
            url=url,
            final_url=exc.geturl() if hasattr(exc, "geturl") else url,
            status=exc.code,
            body=body,
            headers={k.lower(): v for k, v in (exc.headers or {}).items()},
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except urllib.error.URLError as exc:
        return Response(url, url, None, "", {}, int((time.monotonic() - started) * 1000), str(exc.reason))
    except (TimeoutError, socket.timeout):
        return Response(url, url, None, "", {}, int((time.monotonic() - started) * 1000), "timed out")
    except Exception as exc:  # noqa: BLE001 - monitoring must never die on one site
        return Response(url, url, None, "", {}, int((time.monotonic() - started) * 1000), repr(exc))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Used to detect whether an HTTP URL redirects to HTTPS at all, rather
    than silently being carried there by the opener."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        return None


@dataclass
class Certificate:
    host: str
    not_after: datetime | None = None
    issuer: str = ""
    error: str | None = None

    @property
    def days_left(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.now(timezone.utc)).days


def certificate(url: str) -> Certificate:
    """Read the TLS certificate's expiry by opening a socket. Read-only:
    we complete the handshake and hang up."""
    host = urlsplit(url).hostname or ""
    port = urlsplit(url).port or 443
    if not host:
        return Certificate(host, error="no hostname")

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                data = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        return Certificate(host, error=f"certificate does not verify: {exc.verify_message or exc}")
    except Exception as exc:  # noqa: BLE001
        return Certificate(host, error=str(exc))

    not_after = None
    if raw := data.get("notAfter"):
        try:
            not_after = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    issuer = ""
    for group in data.get("issuer", ()):
        for key, value in group:
            if key == "organizationName":
                issuer = value

    return Certificate(host, not_after=not_after, issuer=issuer)
