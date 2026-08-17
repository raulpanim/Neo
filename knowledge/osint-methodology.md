# OSINT recon methodology

## Passive vs active recon
Passive recon pulls information from sources that never touch the target
directly: certificate transparency logs (crt.sh), archived snapshots
(Wayback Machine), WHOIS/DNS history, search engines, and third-party
indexes (Shodan, Censys, VirusTotal). It leaves no trace on the target.
Active recon sends traffic to the target itself — port scans, banner
grabs, directory brute-forcing — and requires explicit authorization
before it is run against anything you do not own.

## A typical passive-first workflow
1. Confirm scope and written authorization before touching a target.
2. Enumerate subdomains passively (certificate transparency, DNS
   history, search engines) before any active scanning.
3. Cross-reference IPs and hostnames across multiple sources (Shodan,
   VirusTotal, AbuseIPDB, GreyNoise) rather than trusting one source.
4. Check historical exposure: Wayback Machine snapshots and breach
   databases (HIBP) can reveal old configs, leaked files, or credentials
   that are no longer live but still relevant.
5. Document findings with source and timestamp — OSINT data changes, and
   a screenshot or saved response is worth more later than a memory of
   what a dashboard once showed.

## Signal vs noise
A single indicator (one open port, one negative VirusTotal hit) rarely
proves anything. Corroborate across independent sources before drawing a
conclusion, and prefer recent data — DNS, hosting, and reputation data
all drift over time.
