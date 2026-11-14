// Browser tests: Chromium, Firefox and WebKit on the desktop, plus phone-sized Chromium and WebKit for the layout
// checks. The site is served from dist/site/ under /mailanalyzer/ (tools/serve.mjs), the path it has when deployed.
// Locally the Chromium project uses the installed Google Chrome (set PW_CHROMIUM_CHANNEL= to use Playwright's own
// Chromium); CI installs Playwright's browsers.
// SPDX-License-Identifier: MIT
import { defineConfig, devices } from '@playwright/test';

const CI = !!process.env.CI;
const channel = process.env.PW_CHROMIUM_CHANNEL ?? (CI ? '' : 'chrome');
const chromium = channel ? { channel } : {};

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 30_000,
  fullyParallel: true,
  forbidOnly: CI,
  retries: 0,
  workers: CI ? 2 : 4,
  reporter: CI ? [['list'], ['github']] : 'list',
  use: { baseURL: 'http://127.0.0.1:4174/mailanalyzer/', trace: 'off', acceptDownloads: true },
  webServer: { command: 'node tools/serve.mjs --port 4174', url: 'http://127.0.0.1:4174/mailanalyzer/', reuseExistingServer: !CI },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], ...chromium }, testIgnore: /layout\.spec/ },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testIgnore: /layout\.spec/ },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, testIgnore: /layout\.spec/ },
    { name: 'layout-chromium', use: { ...devices['Desktop Chrome'], ...chromium }, testMatch: /layout\.spec/ },
    { name: 'layout-firefox', use: { ...devices['Desktop Firefox'] }, testMatch: /layout\.spec/ },
    { name: 'layout-webkit', use: { ...devices['Desktop Safari'] }, testMatch: /layout\.spec/ }
  ]
});
