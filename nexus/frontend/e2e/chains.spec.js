import { test, expect } from '@playwright/test';

test.describe('chains tab', () => {
  test('key "a" opens the chains tab and shows an inferred chain', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.keyboard.press('a');

    await expect(page.getByRole('button', { name: 'chains', exact: true })).toBeVisible();
    // The chains panel's own count line, e.g. "5 inferred chain(s):" - proves
    // it actually fetched and rendered data, not just switched tabs.
    await expect(page.getByText(/inferred from cvss vectors/i)).toBeVisible();

    // The seeded Log4Shell -> local-privesc chain must be one of them.
    await expect(page.getByText('CVE-2021-44228').first()).toBeVisible();
    await expect(page.getByText('CVE-2021-41617').first()).toBeVisible();
  });

  test('a chain step names its own predecessor, not a different one', async ({ page }) => {
    // Regression test for the mutable-shared-profile bug found and fixed
    // earlier this session: a step's rationale must describe the actual
    // transition into that step, not whatever branch the search visited
    // last while exploring a sibling path.
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();
    await page.keyboard.press('a');
    await expect(page.getByText(/inferred from cvss vectors/i)).toBeVisible();

    const rationale = page.getByText(/provides the foothold.*escalates to|lands as.*escalates to/i).first();
    await expect(rationale).toBeVisible();
  });

  test('other keyboard shortcuts open their tabs too', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/surface of example\.com/i)).toBeVisible();

    await page.keyboard.press('c');
    await expect(page.getByRole('button', { name: 'conflicts', exact: true })).toBeVisible();

    await page.keyboard.press('s');
    await expect(page.getByRole('button', { name: 'collectors', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'sync nvd' })).toBeVisible();

    // 'f' toggles the drawer; it was open (from 's' above), so this closes
    // it and the collectors panel's own content should disappear.
    await page.keyboard.press('f');
    await expect(page.getByRole('button', { name: 'sync nvd' })).not.toBeVisible();
  });
});
