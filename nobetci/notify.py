"""Getting a finding out of the terminal and in front of a person.

Two jobs, and the second one matters more than the first:

  1. Send the run's findings as an email.
  2. Refuse to send the same email over and over.

A site that is compromised stays compromised. Checked every six hours, a
naive notifier mails the identical alert four times a day, and the reader
mutes it inside a week — which leaves the site unwatched while everyone
believes it is watched. So an alert is sent when the set of findings
CHANGES, or when enough time has passed to be worth repeating, and not
otherwise.
"""

from __future__ import annotations

import hashlib
import json
import os
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from .report import CRITICAL, WARNING, Run, render_markdown

RENOTIFY_HOURS = 24
ALERT_STATE = "_alerts.json"


@dataclass
class MailConfig:
    host: str
    port: int
    user: str
    password: str
    to: str
    sender: str

    @classmethod
    def from_env(cls) -> MailConfig | None:
        """Returns None when mail isn't configured — not an error. The tool
        must stay useful before it is set up."""
        user = os.environ.get("NOBETCI_SMTP_USER", "").strip()
        password = os.environ.get("NOBETCI_SMTP_PASS", "").strip()
        if not user or not password:
            return None
        return cls(
            host=os.environ.get("NOBETCI_SMTP_HOST", "smtp.gmail.com").strip(),
            port=int(os.environ.get("NOBETCI_SMTP_PORT", "587")),
            user=user,
            password=password,
            to=os.environ.get("NOBETCI_MAIL_TO", "").strip() or user,
            sender=os.environ.get("NOBETCI_MAIL_FROM", "").strip() or user,
        )


def load_env(path: Path) -> None:
    """Minimal .env reader. A dependency for this would be absurd, and the
    file holds an app password, so it stays out of git."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def fingerprint(run: Run) -> str:
    """Identifies WHAT is wrong, ignoring wording and ordering, so a reworded
    detail line doesn't read as a new problem."""
    parts = sorted(
        f"{f.site}|{f.kind}|{f.severity}"
        for f in run.findings
        if f.severity in (CRITICAL, WARNING)
    )
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]


def should_send(run: Run, state_dir: Path, *, renotify_hours: int = RENOTIFY_HOURS) -> tuple[bool, str]:
    """(send?, why) — the 'why' is printed so the decision is never a mystery."""
    alarming = [f for f in run.findings if f.severity in (CRITICAL, WARNING)]
    if not alarming:
        return False, "nothing worth mailing"

    current = fingerprint(run)
    path = state_dir / ALERT_STATE
    previous, sent_at = "", None
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            previous = data.get("fingerprint", "")
            sent_at = datetime.fromisoformat(data["sent_at"]) if data.get("sent_at") else None
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    if current != previous:
        return True, "findings changed since the last alert"

    if sent_at is not None:
        hours = (datetime.now(timezone.utc) - sent_at).total_seconds() / 3600
        if hours >= renotify_hours:
            return True, f"same findings, but {int(hours)}h since the last alert"
        return False, f"identical alert sent {int(hours)}h ago — suppressed"

    return True, "no record of a previous alert"


def record_sent(run: Run, state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / ALERT_STATE).write_text(
        json.dumps(
            {
                "fingerprint": fingerprint(run),
                "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def subject(run: Run) -> str:
    """Readable on a phone lock screen without opening it."""
    critical = [f for f in run.findings if f.severity == CRITICAL]
    warnings = [f for f in run.findings if f.severity == WARNING]
    sites = sorted({f.site for f in critical + warnings})
    who = sites[0] if len(sites) == 1 else f"{len(sites)} site"

    if critical:
        return f"[Nöbetçi] ACİL — {critical[0].title.lower()} · {who}"
    return f"[Nöbetçi] {len(warnings)} uyarı · {who}"


def build(run: Run, config: MailConfig) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject(run)
    message["From"] = config.sender
    message["To"] = config.to
    message.set_content(render_markdown(run))
    return message


def send(run: Run, config: MailConfig) -> None:
    context = ssl.create_default_context()
    with smtplib.SMTP(config.host, config.port, timeout=30) as server:
        server.starttls(context=context)
        server.login(config.user, config.password)
        server.send_message(build(run, config))


def test_message(config: MailConfig) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = "[Nöbetçi] kurulum testi"
    message["From"] = config.sender
    message["To"] = config.to
    message.set_content(
        "Nöbetçi'nin e-posta ayarları çalışıyor.\n\n"
        "Bundan sonra yalnızca izlediğin sitelerden birinde bir sorun "
        "çıktığında ya da mevcut sorun değiştiğinde bu adrese yazacak. "
        "Her şey yolundayken sessiz kalır.\n"
    )
    return message


def send_test(config: MailConfig) -> None:
    context = ssl.create_default_context()
    with smtplib.SMTP(config.host, config.port, timeout=30) as server:
        server.starttls(context=context)
        server.login(config.user, config.password)
        server.send_message(test_message(config))
