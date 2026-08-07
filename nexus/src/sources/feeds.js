import axios from 'axios';
import { parseFeed, extractCveIds } from './feedParser.js';

// Security outlets that write about individual CVEs. These are *not* CVE data
// sources — the facts still come from NVD. What they add is attention: which
// vulnerabilities the industry is actively talking about, which correlates with
// how fast exploitation follows. Keep that signal in its own lane.

export const FEEDS = {
  thehackerwire: {
    label: 'TheHackerWire',
    url: 'https://www.thehackerwire.com/feed/',
    site: 'https://www.thehackerwire.com/',
    note: 'Publishes per-CVE writeups; CVE id usually appears in the title.',
  },
};

/** Fetches and parses one registered feed. Never throws. */
export async function fetchFeed(name) {
  const feed = FEEDS[name];
  if (!feed) return { ok: false, error: `Unknown feed "${name}".`, items: [] };

  try {
    const { data } = await axios.get(feed.url, {
      timeout: 20_000,
      responseType: 'text',
      headers: { Accept: 'application/rss+xml, application/xml, text/xml' },
    });
    const items = parseFeed(data).filter((i) => i.cves.length > 0);
    return { ok: true, outlet: name, label: feed.label, items };
  } catch (err) {
    return {
      ok: false,
      error: err.response
        ? `${feed.label} feed returned ${err.response.status}.`
        : `${feed.label} feed is unreachable.`,
      items: [],
    };
  }
}

export { parseFeed, extractCveIds };
