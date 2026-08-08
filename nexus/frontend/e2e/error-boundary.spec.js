import { test, expect } from '@playwright/test';

test('a malformed API response is contained by the error boundary, not a white screen', async ({ page }) => {
  // Reproduces the exact bug class serialize.js had earlier this session:
  // an edge whose source/target elementId was never registered as a node.
  // Mocking the response (rather than adding a test-only hook to app code)
  // means this test exercises the real contract - the UI must survive
  // whatever the API hands it, not just today's known-good shape.
  await page.route('**/api/graph/attack-surface/example.com*', async (route) => {
    const response = await route.fetch();
    const json = await response.json();
    json.elements.edges.push({
      data: {
        id: 'fake-edge',
        source: 'nonexistent-node-id',
        target: json.elements.nodes[0].data.id,
        type: 'FAKE',
      },
    });
    await route.fulfill({ response, json });
  });

  await page.goto('/');

  await expect(page.getByText(/couldn't be rendered/i)).toBeVisible();

  // The point of the boundary: everything outside the broken panel keeps
  // working, instead of the whole app white-screening.
  await expect(page.getByPlaceholder('example.com')).toBeVisible();
  await expect(page.getByRole('button', { name: 'exploitable now' })).toBeVisible();
  await expect(page.getByText('NEXUS')).toBeVisible();
});

test('the boundary auto-recovers once new data loads', async ({ page }) => {
  let broken = true;
  await page.route('**/api/graph/attack-surface/**', async (route) => {
    const response = await route.fetch();
    const json = await response.json();
    if (broken) {
      json.elements.edges.push({
        data: { id: 'fake-edge', source: 'nonexistent-node-id', target: json.elements.nodes[0].data.id, type: 'FAKE' },
      });
    }
    await route.fulfill({ response, json });
  });

  await page.goto('/');
  await expect(page.getByText(/couldn't be rendered/i)).toBeVisible();

  // Loading a different (now unmocked-broken) domain should clear the error
  // without a manual "try again" - App.jsx's resetKeys ties this to `elements`.
  broken = false;
  await page.getByPlaceholder('example.com').fill('api.example.com');
  await page.getByRole('button', { name: 'surface', exact: true }).click();

  await expect(page.getByText(/couldn't be rendered/i)).not.toBeVisible();
  await expect(page.locator('canvas').first()).toBeVisible();
});
