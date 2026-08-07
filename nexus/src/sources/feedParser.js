// Pure parsing, deliberately free of any I/O import. Feed documents come from
// untrusted remote servers, so the code that interprets them is kept separate
// and directly testable without a network stack or a database behind it.

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

/** Pulls CVE ids out of any text. Deduped and upper-cased. */
export function extractCveIds(text = '') {
  return [...new Set((String(text).match(CVE_RE) ?? []).map((m) => m.toUpperCase()))];
}

const unwrap = (v = '') =>
  v
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&#8217;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/<[^>]+>/g, '')
    .trim();

const tag = (block, name) => {
  const m = block.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? unwrap(m[1]) : null;
};

/**
 * Minimal RSS 2.0 / Atom parser. Written by hand rather than pulling in a
 * dependency: we need four fields, and an XML library is a large attack surface
 * to bolt onto a tool that fetches untrusted remote documents.
 */
export function parseFeed(xml) {
  const blocks = xml.match(/<(item|entry)[\s\S]*?<\/\1>/gi) ?? [];
  return blocks.map((block) => {
    const link =
      tag(block, 'link') ||
      (block.match(/<link[^>]*href="([^"]+)"/i) ?? [])[1] ||
      null;
    const title = tag(block, 'title');
    const published = tag(block, 'pubDate') || tag(block, 'published') || tag(block, 'updated');
    const summary =
      tag(block, 'description') || tag(block, 'summary') || tag(block, 'content:encoded') || '';
    const categories = [...block.matchAll(/<category[^>]*>([\s\S]*?)<\/category>/gi)].map((m) =>
      unwrap(m[1]),
    );

    return {
      title,
      link,
      published: published ? new Date(published).toISOString() : null,
      summary: summary.slice(0, 400),
      categories,
      cves: extractCveIds(`${title} ${summary} ${link}`),
    };
  });
}
