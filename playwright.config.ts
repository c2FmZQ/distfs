import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './web/tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'list',
  use: {
    baseURL: 'https://web-test-server',
    trace: 'on-first-retry',
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: [
            '--ignore-certificate-errors',
            '--disable-web-security',
            '--allow-running-insecure-content'
          ]
        }
      },
    },
  ],
});