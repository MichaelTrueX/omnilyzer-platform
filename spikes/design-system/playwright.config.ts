/**
 * File: spikes/design-system/playwright.config.ts
 * Purpose: Runs deterministic Chromium validation against the local Vite design-system demo.
 * Related: src/demo/App.tsx, tests/browser/demo.spec.ts, package.json
 */

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/browser",
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:4173",
    browserName: "chromium",
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev:web",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
