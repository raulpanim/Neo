import { defineConfig, devices } from '@playwright/test';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

// This dev sandbox ships a pre-installed Chromium outside Playwright's own
// cache to avoid re-downloading it; CI and anyone else running these tests
// normally installs its own via `npx playwright install chromium`, so this
// only applies when that sandbox path actually exists.
function findSandboxChromium() {
  const root = '/opt/pw-browsers';
  if (!existsSync(root)) return null;
  const dir = readdirSync(root).find((name) => name.startsWith('chromium-'));
  if (!dir) return null;
  const bin = join(root, dir, 'chrome-linux', 'chrome');
  return existsSync(bin) ? bin : null;
}

const sandboxChromium = findSandboxChromium();

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false, // the graph-load tests share the one live API/DB - keep them sequential
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        ...(sandboxChromium ? { launchOptions: { executablePath: sandboxChromium } } : {}),
      },
    },
  ],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
