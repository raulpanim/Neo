# Certificate transparency and Wayback Machine

## crt.sh / Certificate Transparency logs
Every publicly trusted TLS certificate issued since ~2013 is logged in
append-only, publicly auditable Certificate Transparency (CT) logs. crt.sh
searches these logs. Because CT logs are permanent, a subdomain that only
existed briefly (e.g. a staging or internal-sounding host that briefly
had a public cert) stays discoverable forever, even after the DNS record
is removed. This makes crt.sh one of the highest-signal passive
subdomain-enumeration sources: certificate `name_value` fields
frequently reveal subdomains never linked from anywhere on the public
web (internal tools, staging environments, forgotten test hosts).

Caveat: a name appearing in a certificate does not prove the host is
still live or still resolves — always verify with a fresh DNS lookup
before treating it as a current attack surface.

## Wayback Machine (web.archive.org)
The Internet Archive periodically crawls and snapshots public web pages.
Neo's Wayback lookup uses the CDX API to list snapshot timestamps for a
domain. Useful for:
- Recovering content that has since been taken down or changed (old
  admin panels, exposed files, prior versions of a page that leaked
  something since redacted).
- Establishing a timeline — when did a page, header, or piece of content
  first/last appear.

Caveat: the Wayback Machine only has what its crawler reached and chose
to archive — absence of a snapshot doesn't mean a page never existed,
and robots.txt or exclusion requests can hide historical snapshots even
if they were originally captured.
