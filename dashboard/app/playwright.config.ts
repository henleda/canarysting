import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';

const goBuildCache = path.resolve(__dirname, '../../.test-artifacts/cache/go-build');

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:3101',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], channel: 'chrome' },
    },
  ],
  webServer: [
    {
      command: 'npm run test:e2e:backend',
      url: 'http://127.0.0.1:3102/readyz',
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        GOCACHE: goBuildCache,
      },
    },
    {
      command: 'npm run test:e2e:serve',
      url: 'http://127.0.0.1:3101',
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        DASHBOARD_BACKEND_URL: 'http://127.0.0.1:3102',
        NEXT_TELEMETRY_DISABLED: '1',
      },
    },
  ],
});
