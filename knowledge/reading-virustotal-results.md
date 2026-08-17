# Reading VirusTotal results

## last_analysis_stats
VirusTotal runs a submitted domain/IP/hash past dozens of independent
antivirus and URL-reputation engines and buckets each engine's verdict:
- **malicious** — the engine flagged it as bad.
- **suspicious** — flagged as possibly bad, lower confidence.
- **harmless** — the engine explicitly checked and found nothing.
- **undetected** — the engine had no opinion (not the same as harmless).

There is no universally "safe" threshold — a handful of malicious
detections out of 70+ engines can be a false positive from one
overly-aggressive vendor, while even 2-3 hits from major, well-regarded
engines (on a specific hash, especially) is worth taking seriously.
Cross-check which engines fired before drawing a conclusion.

## Reputation
A community-driven score, roughly negative-is-bad. It reflects VirusTotal
users' votes and historical detections, and drifts over time — a
domain's reputation today does not describe what it looked like when a
suspicious event actually happened.

## Not found (404)
A "not found in VirusTotal" result means nobody has submitted that
domain/IP/hash for analysis yet — it says nothing about whether the
target is safe or malicious, only that VirusTotal has no opinion.
