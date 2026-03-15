import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './web/tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'list',
  use: {
    baseURL: 'http://web-test-server:8091',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: ['--unsafely-treat-insecure-origin-as-secure=http://web-test-server:8091']
        }
      },
    },
  ],
});