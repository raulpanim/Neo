import { test, expect } from '@playwright/test';

test.describe('command rail', () => {
  test('search finds entities by name', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.getByPlaceholder('example.com').fill('log4j');
    await page.getByRole('button', { name: 'search', exact: true }).click();

    await expect(page.getByText(/\d+ match(es)?/i)).toBeVisible();
  });

  test('search for garbage reports zero matches without crashing', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.getByPlaceholder('example.com').fill('zzz-nonexistent-zzz');
    await page.getByRole('button', { name: 'search', exact: true }).click();

    await expect(page.getByText(/no match for/i)).toBeVisible();
  });

  test('surface loads a different domain and its own findings', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.getByPlaceholder('example.com').fill('api.example.com');
    await page.getByRole('button', { name: 'surface', exact: true }).click();

    await expect(page.getByText(/surface of api\.example\.com/i)).toBeVisible();
  });

  test('the standing "exploitable now" view works', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.getByRole('button', { name: 'exploitable now' }).click();

    await expect(page.getByText(/exploitable finding/i)).toBeVisible();
    // Log4Shell is the one CVE in the seed with a recorded HAS_EXPLOIT edge.
    await expect(page.getByText('CVE-2021-44228').first()).toBeVisible();
  });
});
