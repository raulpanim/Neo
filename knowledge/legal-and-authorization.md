# Authorization and legal reminders

This is general background, not legal advice — laws vary by
jurisdiction and you should get real legal guidance for anything beyond
casual research on your own assets.

## Before running anything active
Passive OSINT (public records, CT logs, archived pages, third-party
indexes like Shodan/VirusTotal) generally carries low legal risk because
you are not sending traffic to the target. The moment recon becomes
active — port scans, login attempts, fuzzing, exploitation — you need
clear, written authorization from someone with the authority to grant it
for that specific target: a signed pentest engagement letter, a bug
bounty program's published scope, or a system you personally own.
Unauthorized access to computer systems is a criminal offense in most
jurisdictions (e.g. the U.S. Computer Fraud and Abuse Act, the UK
Computer Misuse Act) regardless of intent.

## Scope discipline
Stay inside the agreed scope even when recon surfaces something
interesting just outside it (a related domain, a third-party vendor, a
neighboring IP range). Findings outside scope should be reported to the
engagement owner, not investigated further on your own authority.

## Responsible disclosure
If you find a real vulnerability outside an authorized engagement (e.g.
while doing personal research), report it to the vendor or via a
recognized program rather than exploiting or publicizing it. Most
vendors and bug bounty platforms have a disclosure policy; follow it.

## Handling sensitive data
Breach-database and leak-search results can contain real people's
personal data. Treat anything you retrieve as sensitive: don't store it
longer than needed for the authorized purpose, and don't share it beyond
what the engagement requires.
