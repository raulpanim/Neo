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
HIBP domain-breach search, Shodan InternetDB (free ports/CPEs/CVEs
lookup — no key, no rate limit, lighter than the full Shodan API).

## Live (bring your own API key)

Shodan, VirusTotal, AbuseIPDB, GreyNoise, SecurityTrails.

## Relationship graph

The **Graph** button builds a visual map for a domain: domain &rarr;
resolved IP(s) &rarr; open ports &rarr; detected software &rarr; matching
CVEs, correlated from DNS resolution and either Shodan or NVD. Click a
CVE node to ask the AI assistant about it. Rendered with a small
hand-rolled force-directed layout, no charting library or CDN involved.

Two data sources depending on whether you've set a Shodan key (under
**API Keys**):
- **With a Shodan key** — the full host API gives per-port
  product/version detail; CVEs are found via an NVD keyword search on
  the product name (NVD's keyword search has no version awareness, so
  this can surface CVEs for versions other than the one actually
  running).
- **Without one** — falls back to Shodan's free InternetDB endpoint
  (no key, no rate limit). Coarser: ports, software, and CVEs are all
  host-level rather than mapped to a specific port. Its CVE list is
  Shodan's own CPE-version-matched result (usually more accurate than
  the keyword-search path above), fetched by exact CVE ID from NVD —
  capped to 6 per host since a single old host can have hundreds.

## Running locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

## Exposing it beyond localhost (e.g. a Pi + travel router)

By default Neo binds to `127.0.0.1` only and the interactive debugger is
off — safe defaults for local use. To reach it from other devices on a
travel router's Wi-Fi, set a password first:

```bash
export NEO_AUTH_PASSWORD="something-long-and-random"
export HOST=0.0.0.0
python app.py
```

Any username plus that password (HTTP Basic Auth) is required for every
request once `NEO_AUTH_PASSWORD` is set. Without it, binding to `0.0.0.0`
leaves the dashboard — including your API keys flow and every live
lookup — open to anyone on that network with no login. The app prints a
warning at startup if it detects that combination.

**HTTPS is on by default for any non-loopback bind.** Basic Auth sends
your password (and every API key you type in) as plain base64 — not
encrypted — so without TLS anyone else on the same Wi-Fi can read them
straight off the wire. As soon as `HOST` isn't `127.0.0.1`/`localhost`,
Neo automatically serves over HTTPS with a temporary self-signed
certificate — your browser will show a security warning the first time
(expected, since it's not signed by a public CA); click through it.

For a certificate your browser won't warn about, generate one with
[mkcert](https://github.com/FiloSottile/mkcert) and point Neo at it:

```bash
export NEO_TLS_CERT=/path/to/cert.pem
export NEO_TLS_KEY=/path/to/key.pem
```

If you're terminating TLS yourself in a reverse proxy (Caddy, nginx) in
front of this app, set `NEO_TLS=0` to skip the built-in self-signed
cert — but only if that proxy is actually handling HTTPS, otherwise
you're back to serving everything in the clear.

Other environment variables: `PORT` (default `5000`), `FLASK_DEBUG=1` to
enable Werkzeug's interactive debugger for local development only —
never combine it with a non-loopback `HOST`, since the debugger allows
arbitrary code execution to anyone who can reach it.

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
