import { test } from 'node:test';
import assert from 'node:assert/strict';
import neo4j from 'neo4j-driver';
import { toJSONSafe } from '../src/serialize.js';

test('toJSONSafe passes through primitives and null', () => {
  assert.strictEqual(toJSONSafe(1), 1);
  assert.strictEqual(toJSONSafe('x'), 'x');
  assert.strictEqual(toJSONSafe(true), true);
  assert.strictEqual(toJSONSafe(null), null);
  assert.strictEqual(toJSONSafe(undefined), undefined);
});

test('toJSONSafe converts neo4j Integer to a plain number', () => {
  const int = neo4j.int(42);
  assert.strictEqual(toJSONSafe(int), 42);
});

test('toJSONSafe converts temporal types to ISO-ish strings', () => {
  const dt = neo4j.types.DateTime.fromStandardDate(new Date('2024-01-10T00:00:00Z'));
  const result = toJSONSafe(dt);
  assert.strictEqual(typeof result, 'string');
  assert.ok(result.startsWith('2024-01-10'));
});

test('toJSONSafe recurses into arrays and plain objects', () => {
  const input = { a: [neo4j.int(1), neo4j.int(2)], b: { c: neo4j.int(3) } };
  assert.deepStrictEqual(toJSONSafe(input), { a: [1, 2], b: { c: 3 } });
});

test('toJSONSafe unwraps Node and Relationship wrappers', () => {
  const node = new neo4j.types.Node('4:x:0', ['CVE'], { id: 'CVE-1', cvss: neo4j.int(9) });
  const rel = new neo4j.types.Relationship('4:x:1', '4:x:0', '4:x:2', 'CHAINS_TO', {
    confidence: 0.5,
  });
  assert.deepStrictEqual(toJSONSafe(node), {
    elementId: '4:x:0',
    label: 'CVE',
    properties: { id: 'CVE-1', cvss: 9 },
  });
  assert.deepStrictEqual(toJSONSafe(rel), {
    elementId: '4:x:1',
    type: 'CHAINS_TO',
    properties: { confidence: 0.5 },
  });
});
