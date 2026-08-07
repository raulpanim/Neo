import axios from 'axios';

const FEED =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/**
 * CISA's Known Exploited Vulnerabilities catalogue. Public, no key, one file.
 * A CVE appearing here means confirmed exploitation in the wild — the single
 * strongest prioritisation signal we can get for free.
 */
export async function fetchKev() {
  try {
    const { data } = await axios.get(FEED, { timeout: 30_000 });
    const items = (data.vulnerabilities || []).map((v) => ({
      id: v.cveID,
      kev_added: v.dateAdded ?? null,
      kev_due: v.dueDate ?? null,
      kev_action: (v.requiredAction ?? '').slice(0, 300),
      ransomware: v.knownRansomwareCampaignUse === 'Known',
    }));
    return { ok: true, catalogVersion: data.catalogVersion ?? null, items };
  } catch (err) {
    return {
      ok: false,
      error: err.response
        ? `CISA KEV feed returned ${err.response.status}.`
        : 'CISA KEV feed is unreachable.',
      items: [],
    };
  }
}
