"""
OSINT / security-research dashboard.

A single-page launcher for common OSINT, recon, and threat-intel tools,
plus live server-side lookups for the handful of services that expose a
usable free or key-authenticated JSON API. API keys are supplied by the
caller on every request (kept in the browser's localStorage) and are
never persisted, logged, or stored on the server.

For authorized security research / pentesting / CTF use only.
"""
import ipaddress
import os
import re
import secrets
import socket

import requests
from flask import Flask, Response, jsonify, render_template, request

import ai
from services import CATEGORIES, homepages

app = Flask(__name__)

REQUEST_TIMEOUT = 15
USER_AGENT = "osint-dashboard/1.0 (+security-research)"

AUTH_PASSWORD = os.environ.get("NEO_AUTH_PASSWORD")


@app.before_request
def require_auth():
    if not AUTH_PASSWORD:
        return None
    auth = request.authorization
    if auth is None or not secrets.compare_digest(auth.password or "", AUTH_PASSWORD):
        return Response(
            "Authentication required.", 401, {"WWW-Authenticate": 'Basic realm="Neo"'}
        )
    return None

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_target(input_type, target):
    if not target or len(target) > 253:
        return False
    if input_type == "domain":
        return bool(DOMAIN_RE.match(target))
    if input_type == "ip":
        return is_ip(target)
    if input_type == "hash":
        return bool(HASH_RE.match(target))
    if input_type == "email":
        return bool(EMAIL_RE.match(target))
    if input_type == "keyword":
        return 0 < len(target) <= 200
    return False


def ok(items, raw=None):
    return {"ok": True, "error": None, "items": items, "raw": raw}


def fail(message):
    return {"ok": False, "error": message, "items": [], "raw": None}


def http_get(url, **kwargs):
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("User-Agent", USER_AGENT)
    return requests.get(url, **kwargs)


# ---------------------------------------------------------------------------
# Live lookup functions. Each takes (target, input_type, api_key) and returns
# a dict built with ok()/fail(). None of these ever put `target` into a URL
# host/authority component — only into validated path segments or into
# `params=` (which `requests` percent-encodes), so user input cannot redirect
# the outbound request to an attacker-chosen host.
# ---------------------------------------------------------------------------

def lookup_crtsh(target, input_type, api_key):
    if input_type != "domain":
        return fail("crt.sh only supports domain lookups.")
    # Large domains (e.g. google.com has 1000+ certificate rows) can take
    # crt.sh well over the default timeout to respond.
    r = http_get(
        "https://crt.sh/", params={"q": target, "output": "json"}, timeout=45
    )
    if r.status_code != 200:
        return fail(f"crt.sh returned HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        return fail("crt.sh returned no certificates for this domain.")
    # Each row's name_value can hold multiple SANs newline-separated within
    # one certificate; split before deduping or a single multi-SAN cert
    # swallows the "top 25" list as one giant blob instead of distinct names.
    names = set()
    for row in data:
        for name in row.get("name_value", "").split("\n"):
            name = name.strip()
            if name:
                names.add(name)
    names = sorted(names)[:25]
    items = [{"label": "Certificate name", "value": n} for n in names]
    return ok(items or [{"label": "Result", "value": "No certificates found."}], data[:25])


def lookup_urlscan(target, input_type, api_key):
    if input_type not in ("domain", "ip"):
        return fail("URLScan.io supports domain or IP lookups.")
    field = "domain" if input_type == "domain" else "ip"
    r = http_get(
        "https://urlscan.io/api/v1/search/",
        params={"q": f"{field}:{target}", "size": 10},
    )
    if r.status_code != 200:
        return fail(f"URLScan.io returned HTTP {r.status_code}")
    data = r.json()
    results = data.get("results", [])
    items = [
        {
            "label": res.get("page", {}).get("url", "scan"),
            "value": res.get("result", ""),
        }
        for res in results[:10]
    ]
    return ok(items or [{"label": "Result", "value": "No scans found."}], results[:10])


def lookup_wayback(target, input_type, api_key):
    if input_type != "domain":
        return fail("Wayback Machine only supports domain lookups.")
    r = http_get(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": target, "output": "json", "limit": 20, "collapse": "timestamp:8"},
    )
    if r.status_code != 200:
        return fail(f"Wayback Machine returned HTTP {r.status_code}")
    rows = r.json()
    if len(rows) <= 1:
        return ok([{"label": "Result", "value": "No archived snapshots found."}])
    header, records = rows[0], rows[1:]
    ts_idx = header.index("timestamp") if "timestamp" in header else 1
    items = [{"label": "Snapshot", "value": rec[ts_idx]} for rec in records[:20]]
    return ok(items, records[:20])


def _cve_best_score(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            score = m.get("cvssData", {}).get("baseScore")
            if score is not None:
                return score
    return -1  # no scoring data yet (e.g. very recently published) sorts last


def lookup_nvd(target, input_type, api_key):
    if input_type != "keyword":
        return fail("NVD only supports keyword lookups.")
    r = http_get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        # Fetch a wider pool than we display so sorting by severity below
        # isn't just re-ordering whatever 10 NVD happened to return first
        # (its default order is oldest-published-first, not by severity).
        params={"keywordSearch": target, "resultsPerPage": 50},
    )
    if r.status_code != 200:
        return fail(f"NVD returned HTTP {r.status_code} (rate-limited without an API key)")
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda v: _cve_best_score(v.get("cve", {})), reverse=True)
    items = []
    for v in vulns[:10]:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "?")
        score = _cve_best_score(cve)
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        label = f"{cve_id} (CVSS {score})" if score >= 0 else f"{cve_id} (unscored)"
        items.append({"label": label, "value": desc[:200]})
    return ok(items or [{"label": "Result", "value": "No matching CVEs found."}], vulns[:10])


def lookup_ipinfo(target, input_type, api_key):
    if input_type != "ip":
        return fail("IPinfo only supports IP lookups.")
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    r = http_get(f"https://ipinfo.io/{target}/json", headers=headers)
    if r.status_code != 200:
        return fail(f"IPinfo returned HTTP {r.status_code}")
    data = r.json()
    fields = ["ip", "hostname", "city", "region", "country", "org", "asn"]
    items = [{"label": f, "value": str(data[f])} for f in fields if f in data]
    return ok(items, data)


def lookup_shodan(target, input_type, api_key):
    if not api_key:
        return fail("Shodan requires an API key (add one in the key settings).")
    if input_type != "ip":
        return fail("Shodan host lookup only supports IP addresses.")
    r = http_get(f"https://api.shodan.io/shodan/host/{target}", params={"key": api_key})
    if r.status_code == 401:
        return fail("Shodan rejected the API key.")
    if r.status_code != 200:
        return fail(f"Shodan returned HTTP {r.status_code}")
    data = r.json()
    items = [
        {"label": "Org", "value": data.get("org", "")},
        {"label": "OS", "value": data.get("os", "")},
        {"label": "Open ports", "value": ", ".join(str(p) for p in data.get("ports", []))},
        {"label": "Hostnames", "value": ", ".join(data.get("hostnames", []))},
    ]
    return ok(items, {k: data[k] for k in data if k != "data"})


def lookup_virustotal(target, input_type, api_key):
    if not api_key:
        return fail("VirusTotal requires an API key (add one in the key settings).")
    endpoint_by_type = {
        "domain": f"https://www.virustotal.com/api/v3/domains/{target}",
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
        "hash": f"https://www.virustotal.com/api/v3/files/{target}",
    }
    url = endpoint_by_type.get(input_type)
    if not url:
        return fail("VirusTotal supports domain, IP, or file-hash lookups.")
    r = http_get(url, headers={"x-apikey": api_key})
    if r.status_code == 401:
        return fail("VirusTotal rejected the API key.")
    if r.status_code == 404:
        return ok([{"label": "Result", "value": "Not found in VirusTotal."}])
    if r.status_code != 200:
        return fail(f"VirusTotal returned HTTP {r.status_code}")
    data = r.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    items = [{"label": k, "value": str(v)} for k, v in stats.items()]
    reputation = attrs.get("reputation")
    if reputation is not None:
        items.insert(0, {"label": "Reputation", "value": str(reputation)})
    return ok(items or [{"label": "Result", "value": "No analysis data."}], attrs)


def lookup_abuseipdb(target, input_type, api_key):
    if not api_key:
        return fail("AbuseIPDB requires an API key (add one in the key settings).")
    if input_type != "ip":
        return fail("AbuseIPDB only supports IP lookups.")
    r = http_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": target, "maxAgeInDays": 90},
    )
    if r.status_code == 401:
        return fail("AbuseIPDB rejected the API key.")
    if r.status_code != 200:
        return fail(f"AbuseIPDB returned HTTP {r.status_code}")
    data = r.json().get("data", {})
    items = [
        {"label": "Abuse confidence score", "value": str(data.get("abuseConfidenceScore"))},
        {"label": "Total reports", "value": str(data.get("totalReports"))},
        {"label": "Country", "value": str(data.get("countryCode"))},
        {"label": "ISP", "value": str(data.get("isp"))},
    ]
    return ok(items, data)


def lookup_greynoise(target, input_type, api_key):
    if not api_key:
        return fail("GreyNoise requires a Community API key (add one in the key settings).")
    if input_type != "ip":
        return fail("GreyNoise only supports IP lookups.")
    r = http_get(f"https://api.greynoise.io/v3/community/{target}", headers={"key": api_key})
    if r.status_code == 401:
        return fail("GreyNoise rejected the API key.")
    if r.status_code != 200:
        return fail(f"GreyNoise returned HTTP {r.status_code}")
    data = r.json()
    items = [
        {"label": "Noise", "value": str(data.get("noise"))},
        {"label": "RIOT (known service)", "value": str(data.get("riot"))},
        {"label": "Classification", "value": str(data.get("classification"))},
        {"label": "Name", "value": str(data.get("name"))},
    ]
    return ok(items, data)


def lookup_hibp(target, input_type, api_key):
    if input_type == "email":
        return fail(
            "HIBP account search requires a paid subscription key; use the "
            "'Open' deep link to check on haveibeenpwned.com instead."
        )
    if input_type != "domain":
        return fail("HIBP live lookup supports domains (breach name search).")
    r = http_get(
        "https://haveibeenpwned.com/api/v3/breaches", params={"domain": target}
    )
    if r.status_code != 200:
        return fail(f"HIBP returned HTTP {r.status_code}")
    data = r.json()
    items = [{"label": b.get("Title", b.get("Name")), "value": b.get("BreachDate", "")} for b in data]
    return ok(items or [{"label": "Result", "value": "No breaches found for this domain."}], data)


def lookup_securitytrails(target, input_type, api_key):
    if not api_key:
        return fail("SecurityTrails requires an API key (add one in the key settings).")
    if input_type != "domain":
        return fail("SecurityTrails domain overview only supports domain lookups.")
    r = http_get(
        f"https://api.securitytrails.com/v1/domain/{target}", headers={"APIKEY": api_key}
    )
    if r.status_code == 401:
        return fail("SecurityTrails rejected the API key.")
    if r.status_code != 200:
        return fail(f"SecurityTrails returned HTTP {r.status_code}")
    data = r.json()
    items = [
        {"label": "Alexa rank", "value": str(data.get("alexa_rank"))},
        {"label": "Hostname", "value": str(data.get("hostname"))},
        {"label": "Apex domain", "value": str(data.get("apex_domain"))},
    ]
    return ok(items, data)


LIVE_LOOKUPS = {
    "crtsh": lookup_crtsh,
    "urlscan": lookup_urlscan,
    "wayback": lookup_wayback,
    "nvd": lookup_nvd,
    "ipinfo": lookup_ipinfo,
    "shodan": lookup_shodan,
    "virustotal": lookup_virustotal,
    "abuseipdb": lookup_abuseipdb,
    "greynoise": lookup_greynoise,
    "hibp": lookup_hibp,
    "securitytrails": lookup_securitytrails,
}


# ---------------------------------------------------------------------------
# Relationship graph: domain -> IP -> port -> software -> CVE. Built from the
# same live sources as the lookup cards above (DNS, Shodan, NVD), just
# correlated into a graph instead of shown as separate flat result lists.
# ---------------------------------------------------------------------------

GRAPH_MAX_IPS = 5
GRAPH_MAX_PORTS_PER_IP = 20
GRAPH_MAX_CVES_PER_SOFTWARE = 3


def _resolve_domain(domain):
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return sorted(set(ips))
    except socket.gaierror:
        return []


def _fetch_shodan_host(ip, api_key):
    r = http_get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key})
    if r.status_code != 200:
        return None
    return r.json()


def _nvd_top_cves(keyword, limit=GRAPH_MAX_CVES_PER_SOFTWARE):
    r = http_get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": keyword, "resultsPerPage": 20},
    )
    if r.status_code != 200:
        return []
    vulns = r.json().get("vulnerabilities", [])
    vulns.sort(key=lambda v: _cve_best_score(v.get("cve", {})), reverse=True)
    return vulns[:limit]


def build_graph(domain, shodan_key):
    nodes = {}
    edges = []

    def add_node(node_id, node_type, label, **extra):
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, "label": label, **extra}

    seen_edges = set()

    def add_edge(source, target, rel):
        key = (source, target, rel)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"source": source, "target": target, "rel": rel})

    domain_id = f"domain:{domain}"
    add_node(domain_id, "domain", domain)

    ips = _resolve_domain(domain)
    if not ips:
        return {"nodes": list(nodes.values()), "edges": edges, "note": "Domain did not resolve to an IP."}

    note = None if shodan_key else "Add a Shodan API key to expand ports, software, and CVEs."
    # Tracked across all IPs, not reset per-IP: the same software commonly
    # shows up on more than one IP for the same domain, and re-querying
    # NVD for CVEs we already fetched would waste calls against its public
    # rate limit for no new information.
    seen_software = set()

    for ip in ips[:GRAPH_MAX_IPS]:
        ip_id = f"ip:{ip}"
        add_node(ip_id, "ip", ip)
        add_edge(domain_id, ip_id, "RESOLVES_TO")

        if not shodan_key:
            continue
        try:
            host = _fetch_shodan_host(ip, shodan_key)
        except requests.RequestException:
            host = None
        if not host:
            continue

        for svc in host.get("data", [])[:GRAPH_MAX_PORTS_PER_IP]:
            port = svc.get("port")
            if port is None:
                continue
            port_id = f"port:{ip}:{port}"
            add_node(port_id, "port", f"{ip}:{port}")
            add_edge(ip_id, port_id, "HAS_PORT")

            product = svc.get("product")
            if not product:
                continue
            software_label = f"{product} {svc.get('version', '')}".strip()
            software_id = f"software:{software_label}"
            add_node(software_id, "software", software_label)
            add_edge(port_id, software_id, "RUNS_SOFTWARE")

            if software_label in seen_software:
                continue
            seen_software.add(software_label)
            try:
                # NVD keywordSearch does literal text matching against CVE
                # descriptions, which almost never contain an exact
                # "product version" phrase (they describe version ranges
                # in prose) — searching on the product name alone is what
                # actually returns matches.
                cves = _nvd_top_cves(product)
            except requests.RequestException:
                cves = []
            for cve in cves:
                cve_data = cve.get("cve", {})
                cve_id_str = cve_data.get("id")
                if not cve_id_str:
                    continue
                score = _cve_best_score(cve_data)
                descs = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                cve_node_id = f"cve:{cve_id_str}"
                add_node(
                    cve_node_id,
                    "cve",
                    f"{cve_id_str} ({score if score >= 0 else '?'})",
                    score=score,
                    desc=desc[:400],
                )
                add_edge(software_id, cve_node_id, "VULNERABLE_TO")

    return {"nodes": list(nodes.values()), "edges": edges, "note": note}


@app.route("/api/graph", methods=["POST"])
def api_graph():
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    shodan_key = (body.get("shodan_key") or "").strip() or None

    if not validate_target("domain", domain):
        return jsonify({"ok": False, "error": f"'{domain}' is not a valid domain.", "nodes": [], "edges": []}), 400

    try:
        graph = build_graph(domain, shodan_key)
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": f"Network error building graph: {exc}", "nodes": [], "edges": []})

    return jsonify({"ok": True, "error": None, **graph})


@app.route("/")
def index():
    return render_template("index.html", categories=CATEGORIES, homepages=homepages())


@app.route("/api/lookup/<service>", methods=["POST"])
def api_lookup(service):
    fn = LIVE_LOOKUPS.get(service)
    if fn is None:
        return jsonify(fail(f"Unknown live-lookup service '{service}'.")), 404

    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    input_type = (body.get("input_type") or "").strip()
    api_key = (body.get("api_key") or "").strip() or None

    if not validate_target(input_type, target):
        return jsonify(fail(f"'{target}' is not a valid {input_type or 'target'}.")), 400

    try:
        result = fn(target, input_type, api_key)
    except requests.RequestException as exc:
        result = fail(f"Network error contacting {service}: {exc}")
    except Exception as exc:  # noqa: BLE001 - surface any unexpected upstream shape as a lookup error
        result = fail(f"Unexpected error from {service}: {exc}")

    return jsonify(result)


AI_MESSAGE_MAX_LEN = 4000
AI_CONTEXT_MAX_LEN = 2000


@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    body = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    context = (body.get("context") or "").strip()[:AI_CONTEXT_MAX_LEN] or None
    if not message or len(message) > AI_MESSAGE_MAX_LEN:
        return jsonify(
            {"ok": False, "error": f"Message is required (max {AI_MESSAGE_MAX_LEN} chars).", "reply": None, "sources": []}
        ), 400
    return jsonify(ai.chat(message, extra_context=context))


@app.route("/api/ai/explain", methods=["POST"])
def api_ai_explain():
    body = request.get_json(silent=True) or {}
    service = (body.get("service") or "").strip()[:100]
    result_data = body.get("result")
    if not isinstance(result_data, dict) or not result_data.get("items"):
        return jsonify({"ok": False, "error": "No result data to explain.", "reply": None, "sources": []}), 400

    items = result_data.get("items")
    if not isinstance(items, list):
        return jsonify({"ok": False, "error": "No result data to explain.", "reply": None, "sources": []}), 400

    lines = []
    for item in items[:25]:
        if isinstance(item, dict):
            lines.append(f"- {item.get('label')}: {item.get('value')}")
    context = f"Service: {service or 'unknown'}\n" + "\n".join(lines)
    message = f"Explain what these {service or 'lookup'} results mean for a security researcher, in plain language."
    return jsonify(ai.chat(message, extra_context=context))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG") == "1"

    if host not in ("127.0.0.1", "localhost") and not AUTH_PASSWORD:
        print(
            f"WARNING: binding to {host} with no NEO_AUTH_PASSWORD set — "
            "this dashboard (and its API keys/lookups) will be reachable "
            "by anyone on this network, with no login.",
        )
    if debug and host not in ("127.0.0.1", "localhost"):
        print(
            "WARNING: FLASK_DEBUG=1 with a non-loopback host exposes the "
            "Werkzeug interactive debugger on the network — this allows "
            "arbitrary code execution to anyone who can reach it. Do not "
            "combine FLASK_DEBUG=1 with HOST=0.0.0.0 outside local dev.",
        )

    app.run(debug=debug, host=host, port=port)
