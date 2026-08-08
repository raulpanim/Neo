import { test, expect } from '@playwright/test';

test.describe('boot and graph render', () => {
  test('loads the example.com attack surface automatically', async ({ page }) => {
    await page.goto('/');

    // App.jsx's boot effect fires `surface example.com` automatically.
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    // Cytoscape renders into a canvas - if the graph never populated (or
    // crashed, per the serialize.js bug this session already found once)
    // there would be no canvas element at all.
    await expect(page.locator('canvas').first()).toBeVisible();

    // The findings drawer opens automatically once vulnerabilities load.
    await expect(page.getByText(/CVE-2021-44228/)).toBeVisible();
  });

  test('status bar reflects live counts, not placeholders', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    const counts = page.getByText(/\d+ nodes · \d+ edges/);
    await expect(counts).toBeVisible();
    const text = await counts.textContent();
    const [, nodes, edges] = text.match(/(\d+) nodes · (\d+) edges/);
    expect(Number(nodes)).toBeGreaterThan(0);
    expect(Number(edges)).toBeGreaterThan(0);

    // API health dot - green (online) once boot's health check resolves.
    await expect(page.getByLabel('API online')).toBeVisible();
  });

  test('selecting a node populates the inspector', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    // The Log4j CVE node - present in every seeded attack-surface load.
    await page.getByText('CVE-2021-44228', { exact: true }).first().click();

    await expect(page.getByText(/cvss 10/i)).toBeVisible();
    await expect(page.getByText(/exploited in the wild/i)).toBeVisible();
  });
});
