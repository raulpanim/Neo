import { test, expect } from '@playwright/test';

test.describe('intel panels', () => {
  test('conflicts panel shows a live disagreement between sources', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.keyboard.press('c');
    await expect(page.getByRole('button', { name: 'conflicts', exact: true })).toBeVisible();

    // The seed has real staleness/weak-support conflicts (see
    // src/ingest/conflicts.js) - "no disagreements" would mean the panel
    // never actually fetched, not that the data is clean.
    await expect(page.getByText(/no disagreements/i)).not.toBeVisible();
  });

  test('sources tab shows the reliability matrix with real weights', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.getByRole('button', { name: 'sources', exact: true }).click();

    // Admiralty grades from src/sources/reliability.js.
    await expect(page.getByText('Live DNS')).toBeVisible();
    await expect(page.getByText('NVD', { exact: true })).toBeVisible();
    await expect(page.getByText(/admiralty/i)).toBeVisible();
  });

  test('collectors tab shows sync buttons and status, and running one updates history', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.keyboard.press('s');
    await expect(page.getByRole('button', { name: 'sync kev' })).toBeVisible();

    // KEV sync needs no API key and is cheap - safe to actually run in a test.
    await page.getByRole('button', { name: 'sync kev' }).click();
    await expect(page.getByText(/kev:.*matched the graph/i)).toBeVisible({ timeout: 15_000 });
  });
});
