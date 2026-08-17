# Reading Shodan results

## Fields Neo shows
- **Org** — the registered organization/ISP for the IP, from WHOIS-style
  data. Often a hosting provider, not the actual operator of the host.
- **OS** — Shodan's best-guess OS fingerprint from banners (SSH version
  strings, HTTP headers, TCP/IP stack quirks). It can be wrong or stale.
- **Open ports** — TCP/UDP ports Shodan observed responding the last time
  it scanned the host. This is a point-in-time snapshot, not a live scan.
- **Hostnames** — reverse-DNS or certificate-derived names associated
  with the IP.

## Interpreting open ports
A handful of ports come up constantly and are worth knowing at a glance:
21 (FTP), 22 (SSH), 23 (Telnet — legacy/insecure), 25 (SMTP), 80/443
(HTTP/HTTPS), 445 (SMB), 3306 (MySQL), 3389 (RDP), 6379 (Redis), 27017
(MongoDB). Databases or RDP exposed directly to the internet on default
ports/no auth is a very common and very serious finding — but confirm
before reporting: Shodan's snapshot can be days or weeks old, and the
service may have moved or been patched since.

## Caveats
Shodan indexes what it scanned, not everything that exists. A host
showing no results in Shodan is not proven "clean" — it may simply not
have been scanned recently, or it may sit behind a firewall that blocks
Shodan's scanners specifically.
