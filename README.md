# OSINT & Security Research Dashboard

A single-page launcher and live-lookup dashboard for common OSINT, DNS,
website-analysis, IP-reputation, breach, malware-analysis, vulnerability,
and CTF/lab tools.

**For authorized security research, pentesting, and CTF use only.** Always
confirm you have permission to investigate a given domain/IP/target before
querying these services.

## What it does

- Enter a domain, IP, hash, email, or keyword once, then either:
  - **Open** — jump straight to that service's own site with the query
    pre-filled (works for most services; a handful have no reliable
    query-string API and just open the tool's homepage).
  - **Run** — for services with a usable API, call it server-side and show
    a summarized result inline, without leaving the page.
- Services that need paid/authenticated APIs (Shodan, VirusTotal,
  AbuseIPDB, GreyNoise, SecurityTrails) prompt for your own API key via the
  **API Keys** button. Keys are stored only in the browser's
  `localStorage` and sent only with your own requests — the server never
  writes them to disk, a database, or a log.
- Everything else (Censys, IntelX, HTB, TryHackMe, sandboxes, etc.) is a
  deep-link launcher only, since those either require login-gated
  dashboards or have no public query API.

## Live (no key needed)

crt.sh, URLScan.io, Wayback Machine, NVD (CVE keyword search), IPinfo,
HIBP domain-breach search.

## Live (bring your own API key)

Shodan, VirusTotal, AbuseIPDB, GreyNoise, SecurityTrails.

## Running locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

## Adding or editing services

All service metadata (name, description, accepted input types, deep-link
template, and live-lookup wiring) lives in `services.py`. Add an entry to
the relevant category's `services` list; if you also want a live
integration, implement a `lookup_<name>` function in `app.py` and register
it in the `LIVE_LOOKUPS` dict.
