# Nöbetçi

Watches websites you're responsible for and tells you when something is wrong —
before the client finds out.

Built after a real job: a construction firm's WordPress site had been
compromised, publishing 65 gambling pages under the company's own brand with 51
fake sitemaps injected into `robots.txt`. Nobody noticed for months. This finds
that in seconds.

```
$ python -m nobetci --url https://example.com.tr

Nöbetçi — 2026-08-24T13:55:52+00:00
1 site checked · classifier: HeuristicClassifier

!! [example.com.tr] robots.txt dosyasında 52 adet site haritası var
     Normal bir sitede bir, en fazla birkaç tane olur. Bu kadarı, ele geçirilmiş
     sitelerde eklenen sayfaların Google'a taratılması için kullanılan bilinen
     bir yöntemdir.
       · http://example.com.tr/sitemap-208.xml
       · http://example.com.tr/sitemap-943.xml
       · … and 4 more

 ! [example.com.tr] HTTP adresi HTTPS'e yönlendirilmiyor
```

## What it checks

| Check | Fires when |
|---|---|
| Reachability | The site doesn't answer |
| Speed | The homepage takes over 4 s |
| HTTPS | `http://` serves 200 instead of redirecting to `https://` |
| Certificate | Fails to verify, expired, or under 30 days left |
| `robots.txt` | Bulk sitemap injection, or any change since last run |
| New pages | Discovered via the site's own sitemaps and internal links |
| Bulk growth | 15+ new pages at once — not what normal publishing looks like |
| Content | Injected gambling / pharma / adult / backlink spam |

## Running it

No installation, no dependencies. Python 3.10+.

```bash
python -m nobetci --url https://example.com          # one site
python -m nobetci --sites sites.json                 # a list
python -m nobetci --sites sites.json --format markdown   # to paste to a client
python -m nobetci --sites sites.json --shallow       # skip sitemaps, faster
python -m nobetci --sites sites.json --no-ai         # never call the API
python -m nobetci --sites sites.json --email         # mail the findings
```

`sites.json`:

```json
{
  "sites": [
    { "name": "musteri-1", "business": "Ankara'da bir inşaat firması",
      "url": "https://example.com" }
  ]
}
```

## Getting emailed

```bash
cp .env.example .env          # then fill it in
python -m nobetci --test-email        # check the setup
python -m nobetci --sites sites.json --email
```

Gmail needs an **app password**, not your account password:
`myaccount.google.com` → Security → 2-Step Verification → App passwords.
`.env` is gitignored and must stay that way.

**It will not mail you the same thing twice.** A compromised site stays
compromised, so checking every six hours would send four identical alerts a
day and you would mute it inside a week — leaving the site unwatched while
everyone believes it is watched. An alert goes out when the set of findings
*changes*, or after 24 hours, and not otherwise. Wording and ordering are
ignored, so a reworded detail does not read as a new problem.

Mail is best-effort: a broken mailbox never turns a successful check into a
failed run, so the exit code keeps meaning what it says.

Exit codes: **0** nothing wrong · **1** needs attention · **2** couldn't run. So
as a cron job it only bothers you when it matters:

```cron
0 */6 * * *  cd /srv/nobetci && python -m nobetci --sites sites.json || mail -s "Site uyarısı" you@example.com
```

The first run on a site records a baseline — but it still reports spam and bulk
sitemaps it can see immediately, because a site you take on may already be
compromised.

## How the spam detection works

Two tiers, so it is cheap by default:

1. **Term matching** (`heuristics.py`) settles the blatant cases for free. Text
   is accent-folded and Turkish dotted/dotless `i` is normalised, so `BAHİS`,
   `bahis` and `bahıs` all match. Two or more distinct terms is a strong signal;
   one is not — a law firm may legitimately discuss gambling regulation.
2. **Claude** (`classify.py`) is asked only about the ambiguous remainder — it
   can tell a casino landing page from an article about casino regulation.

**The second tier is optional.** With no API key, Nöbetçi runs on tier one alone
and reports that it did, rather than pretending the ambiguous cases were
checked. Nothing prompts for a key and nothing fails without one.

To enable it: `pip install anthropic` and set `ANTHROPIC_API_KEY`. The model is
`claude-opus-5` at low effort, capped at 256 output tokens, with server-side
refusal fallbacks enabled — this tool asks a model to read gambling spam, which
is exactly the kind of request a safety classifier may decline, and a declined
request would otherwise become a silent monitoring gap.

## Design notes

- **Read-only.** It requests public URLs the way any visitor would. No probing,
  no path guessing, no method but GET. A monitor that behaves like a scanner
  gets blocked.
- **Stdlib only.** No dependencies for the monitoring core, so there is no
  supply-chain surface on a security tool and nothing to install on a server.
  `anthropic` is imported lazily and only if you use tier two.
- **Diffs, not snapshots of HTML.** Raw markup changes constantly for boring
  reasons. Storing visible text and link sets keeps false alarms down, and a
  monitor that cries wolf gets muted, which is the same as not having one.
- **Findings are written for the business owner**, not for an engineer. Every
  one says what it means and what happens if it's ignored.

## Tests

```bash
python -m unittest discover -s tests
```

23 tests, offline, no API key and no mailbox required.
