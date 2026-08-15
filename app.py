"""
OSINT / security-research dashboard.

A single-page launcher for common OSINT, recon, and threat-intel tools,
plus live server-side lookups for the handful of services that expose a
usable free or key-authenticated JSON API. API keys are supplied by the
caller on every request (kept in the browser's localStorage) and are
never persisted, logged, or stored on the server.

For authorized security research / pentesting / CTF use only.
"""
import base64
import ipaddress
import re

import requests
from flask import Flask, jsonify, render_template, request

from services import CATEGORIES, homepages

app = Flask(__name__)

REQUEST_TIMEOUT = 15
USER_AGENT = "osint-dashboard/1.0 (+security-research)"

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
    r = http_get("https://crt.sh/", params={"q": target, "output": "json"})
    if r.status_code != 200:
        return fail(f"crt.sh returned HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        return fail("crt.sh returned no certificates for this domain.")
    names = sorted({row.get("name_value", "") for row in data})[:25]
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


def lookup_nvd(target, input_type, api_key):
    if input_type != "keyword":
        return fail("NVD only supports keyword lookups.")
    r = http_get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": target, "resultsPerPage": 10},
    )
    if r.status_code != 200:
        return fail(f"NVD returned HTTP {r.status_code} (rate-limited without an API key)")
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    items = []
    for v in vulns[:10]:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "?")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        items.append({"label": cve_id, "value": desc[:200]})
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


def build_infra_graph(target):
    """
    Map a single authorized domain's own subdomains and related hosts/IPs
    using crt.sh (certificate transparency), urlscan.io (recent scans), and
    IPinfo (ASN/org enrichment). Scoped to one queried domain — this does not
    crawl or index unrelated internet hosts.
    """
    if not DOMAIN_RE.match(target):
        return fail("Enter a valid domain.")

    nodes = {}
    edges = []
    seen_edges = set()

    def add_node(node_id, label, node_type):
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "label": label, "type": node_type}
        return nodes[node_id]

    def add_edge(a, b):
        if a == b:
            return
        pair = (a, b)
        if pair not in seen_edges:
            seen_edges.add(pair)
            edges.append({"source": a, "target": b})

    add_node(target, target, "domain")

    try:
        r = http_get("https://crt.sh/", params={"q": target, "output": "json"})
        if r.status_code == 200:
            names = set()
            for row in r.json():
                for name in row.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and name.endswith(f".{target}") and name != target:
                        names.add(name)
            for name in sorted(names)[:40]:
                add_node(name, name, "subdomain")
                add_edge(target, name)
    except requests.RequestException:
        pass

    try:
        r = http_get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{target}", "size": 15},
        )
        if r.status_code == 200:
            for res in r.json().get("results", []):
                page = res.get("page", {})
                host = page.get("domain")
                ip = page.get("ip")
                if host:
                    add_node(host, host, "domain" if host == target else "subdomain")
                    add_edge(target, host)
                if ip:
                    add_node(ip, ip, "ip")
                    add_edge(host or target, ip)
    except requests.RequestException:
        pass

    for node in [n for n in nodes.values() if n["type"] == "ip"][:15]:
        try:
            r = http_get(f"https://ipinfo.io/{node['id']}/json")
            if r.status_code == 200:
                org = r.json().get("org")
                if org:
                    node["label"] = f"{node['id']} ({org})"
        except requests.RequestException:
            pass

    if len(nodes) <= 1:
        return fail("No related infrastructure found for this domain.")

    return {"ok": True, "error": None, "nodes": list(nodes.values()), "edges": edges}


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


@app.route("/api/graph", methods=["POST"])
def api_graph():
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip().lower()

    if not validate_target("domain", target):
        return jsonify(fail(f"'{target}' is not a valid domain.")), 400

    try:
        result = build_infra_graph(target)
    except requests.RequestException as exc:
        result = fail(f"Network error building graph: {exc}")
    except Exception as exc:  # noqa: BLE001 - surface any unexpected upstream shape as a lookup error
        result = fail(f"Unexpected error building graph: {exc}")

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
