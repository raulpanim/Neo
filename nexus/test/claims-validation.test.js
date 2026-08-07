import { test } from 'node:test';
import assert from 'node:assert/strict';
import { addClaim, addPropertyClaim, recompute, recomputeProperty } from '../src/ingest/claims.js';

// These validate synchronously before any query.run() call, so a null
// session proves no DB access was attempted for a rejected input.

test('addClaim rejects an unknown subject label without touching the DB', async () => {
  await assert.rejects(
    () =>
      addClaim(null, {
        subject: { label: 'NotALabel', value: 'x' },
        predicate: 'RESOLVES_TO',
        object: { label: 'Host', value: '1.2.3.4' },
        source: 'test',
        confidence: 0.5,
      }),
    /unknown node label/
  );
});

test('addClaim rejects an unknown predicate', async () => {
  await assert.rejects(
    () =>
      addClaim(null, {
        subject: { label: 'Domain', value: 'x' },
        predicate: 'DESTROYS',
        object: { label: 'Host', value: '1.2.3.4' },
        source: 'test',
        confidence: 0.5,
      }),
    /unknown relationship predicate/
  );
});

test('addPropertyClaim rejects a property not on the allowlist', async () => {
  await assert.rejects(
    () =>
      addPropertyClaim(null, {
        subject: { label: 'CVE', value: 'CVE-0000-0000' },
        property: 'arbitraryProp',
        value: true,
        source: 'test',
        confidence: 0.5,
      }),
    /unknown property/
  );
});

test('recompute rejects an unknown predicate', async () => {
  await assert.rejects(
    () => recompute(null, { subjectId: 'x', predicate: 'DESTROYS', objectId: 'y' }),
    /unknown relationship predicate/
  );
});

test('recomputeProperty rejects a property not on the allowlist', async () => {
  await assert.rejects(
    () => recomputeProperty(null, { subjectId: 'x', property: 'nope' }),
    /unknown property/
  );
});
