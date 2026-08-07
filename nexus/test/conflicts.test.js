import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { findPropertyConflicts, findRelationshipConflicts, findConflicts, timeline } from '../src/ingest/conflicts.js';
import { closeDriver } from '../src/db.js';
import { withSession, setupFixtures, teardownFixtures, createFixture } from './helpers.js';
import { addPropertyClaim } from '../src/ingest/claims.js';

const fixture = createFixture(2);

before(() => setupFixtures(fixture));
after(async () => {
  await teardownFixtures(fixture);
  await closeDriver();
});

test('findPropertyConflicts surfaces the seeded disagreement on CVE-2022-1234.exploited', async () => {
  await withSession(async (session) => {
    const conflicts = await findPropertyConflicts(session);
    const match = conflicts.find(
      (c) => c.subject.label === 'CVE' && c.subject.key === 'CVE-2022-1234' && c.property === 'exploited'
    );
    assert.ok(match, 'expected a conflict for CVE-2022-1234.exploited');
    assert.strictEqual(match.claims.length, 2);
    const values = new Set(match.claims.map((c) => c.value));
    assert.deepStrictEqual(values, new Set([true, false]));
  });
});

test('findRelationshipConflicts returns [] when no domain has two live RESOLVES_TO targets', async () => {
  await withSession(async (session) => {
    const conflicts = await findRelationshipConflicts(session);
    assert.deepStrictEqual(conflicts, []);
  });
});

test('a fixture CVE with a single live property claim is not reported as a conflict', async () => {
  await withSession(async (session) => {
    await addPropertyClaim(session, {
      subject: { label: 'CVE', value: fixture.cveC },
      property: 'exploited',
      value: true,
      source: 'solo-source',
      confidence: 0.8,
    });
    const conflicts = await findConflicts(session);
    const match = conflicts.find((c) => c.subject.key === fixture.cveC);
    assert.strictEqual(match, undefined);
  });
});

test('findConflicts does not throw (single-session sequential execution)', async () => {
  await withSession(async (session) => {
    await assert.doesNotReject(() => findConflicts(session));
  });
});

test('timeline returns claims for a subject in ascending assertedAt order, including retracted ones', async () => {
  await withSession(async (session) => {
    const events = await timeline(session, { label: 'CVE', value: 'CVE-2022-1234' });
    assert.ok(events.length >= 2);
    for (let i = 1; i < events.length; i++) {
      assert.ok(
        new Date(events[i - 1].assertedAt) <= new Date(events[i].assertedAt),
        'timeline must be sorted ascending by assertedAt'
      );
    }
    assert.ok(events.every((e) => typeof e.retracted === 'boolean'));
  });
});

test('timeline returns an empty array for a subject with no claims', async () => {
  await withSession(async (session) => {
    const events = await timeline(session, { label: 'CVE', value: fixture.cveA });
    assert.deepStrictEqual(events, []);
  });
});

test('timeline rejects an unknown label', async () => {
  await withSession(async (session) => {
    await assert.rejects(() => timeline(session, { label: 'NotALabel', value: 'x' }), /unknown node label/);
  });
});
