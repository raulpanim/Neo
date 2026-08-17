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

## Offline AI assistant (optional)

Neo can include a chat panel and per-result "Explain with AI" button
backed by a local [Ollama](https://ollama.com) instance — no cloud API,
so it keeps working with no internet connection (e.g. behind a travel
router with no upstream access), as long as the models were pulled once
beforehand.

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:1b   # chat model — small enough for a Pi 4
ollama pull all-minilm    # embedding model, used for local knowledge retrieval
ollama serve              # or run as a systemd service
```

Neo talks to Ollama at `http://127.0.0.1:11434` by default. Override with
environment variables if needed:

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
export AI_CHAT_MODEL=llama3.2:1b
export AI_EMBED_MODEL=all-minilm
```

If Ollama isn't running, the rest of the dashboard works normally — the
AI panel just reports that the AI service is unreachable.

The assistant is grounded with a small local knowledge base of markdown
notes in `knowledge/` (OSINT methodology, how to read Shodan/VirusTotal/
AbuseIPDB/GreyNoise results, CVE/CVSS basics, certificate-transparency
and Wayback caveats, authorization/legal reminders). It's embedded and
searched locally on first use. Add your own `.md` notes to that folder
to expand what it knows — no rebuild step needed, just restart the app.

On a Pi 4, expect chat replies to take several seconds to tens of
seconds depending on RAM/model size — CPU-only inference on a Pi is slow
by nature.

## Adding or editing services

All service metadata (name, description, accepted input types, deep-link
template, and live-lookup wiring) lives in `services.py`. Add an entry to
the relevant category's `services` list; if you also want a live
integration, implement a `lookup_<name>` function in `app.py` and register
it in the `LIVE_LOOKUPS` dict.
