# Reading AbuseIPDB and GreyNoise results

## AbuseIPDB
- **Abuse confidence score** (0-100) — the likelihood the IP is malicious,
  based on user-submitted abuse reports over the lookup window (Neo
  queries the last 90 days). Above ~50 is generally worth attention;
  scores near 100 with many reports indicate persistent, corroborated
  bad behavior (scanning, brute-forcing, spam).
- **Total reports** — report volume matters as much as the score itself;
  a 100% score from a single report is far weaker evidence than a 70%
  score backed by hundreds of independent reporters.
- Residential/dynamic ISP ranges churn users frequently — a high score
  can reflect the previous occupant of that IP, not its current user.

## GreyNoise
GreyNoise focuses on a different question than AbuseIPDB: is this IP
part of mass internet-wide scanning/background noise, rather than a
targeted actor?
- **Noise** — true means GreyNoise has observed this IP scanning or
  crawling broad swaths of the internet (mass scanners, researchers,
  botnets). A "noisy" source hitting your logs is very likely
  opportunistic, not targeted at you specifically.
- **RIOT** — true means the IP belongs to a known common business
  service (e.g. a CDN, cloud provider health-check, or SaaS crawler) that
  is expected to appear in normal traffic and is not inherently
  suspicious.
- **Classification** — GreyNoise's verdict: benign, malicious, or
  unknown, based on observed scanning behavior and intent signals.

Use GreyNoise to triage: an IP hitting your logs that GreyNoise marks
"noise: true, classification: benign" is usually safe to deprioritize;
one with no GreyNoise record at all warrants more scrutiny, since it
means the source isn't part of known broad scanning.
