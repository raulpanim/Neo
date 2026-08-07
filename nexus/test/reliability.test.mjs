import {
  combineConfidence, bestSource, staleness, sourceInfo, matrix, PREDICATES,
} from '../src/sources/reliability.js';

let fails = 0;
const eq = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); }
  else console.log(`ok   ${label}`);
};
const daysAgo = (d) => new Date(Date.now() - d * 86400000).toISOString();

// noisy-OR: agreement helps, never certifies
eq('single dns', combineConfidence(['dns']), 0.95);
eq('two weak sources beat one', combineConfidence(['github','http-headers']) > combineConfidence(['github']), true);
eq('never reaches 1', combineConfidence(['dns','nvd','bgp','crtsh']) <= 0.99, true);
eq('duplicates ignored', combineConfidence(['dns','dns','dns']), combineConfidence(['dns']));
eq('empty is zero', combineConfidence([]), 0);

// unknown sources degrade rather than throw
eq('unknown source graded F', sourceInfo('some-scraper').reliability, 'F');
eq('unknown weight low', sourceInfo('some-scraper').weight < 0.3, true);

// best source picks the strongest
eq('best of mixed', bestSource(['guess','github','dns']), 'dns');

// staleness respects the tighter of source ttl and predicate ttl
eq('fresh dns', staleness('dns', daysAgo(0), 'RESOLVES_TO').stale, false);
eq('day-old dns is stale', staleness('dns', daysAgo(3), 'RESOLVES_TO').stale, true);
eq('analyst note survives', staleness('analyst', daysAgo(200), 'CHAINS_TO').stale, false);
eq('predicate ttl can win', staleness('exploit-db', daysAgo(60), 'VULNERABLE_TO').ttlDays, 30);
eq('missing timestamp is stale', staleness('dns', null, 'RESOLVES_TO').stale, true);

// predicate rules
eq('resolves_to is multi-valued', PREDICATES.RESOLVES_TO.cardinality, 'many');
eq('owned_by is functional', PREDICATES.OWNED_BY.cardinality, 'one');
eq('matrix sorted strongest first', matrix()[0].weight >= matrix().at(-1).weight, true);

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);
