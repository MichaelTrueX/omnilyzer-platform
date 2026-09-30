/**
 * File: spikes/design-system/vitest.config.ts
 * Purpose: Configures jsdom unit/component tests while excluding real-browser Playwright specs.
 * Related: tests/, tests/browser/, playwright.config.ts
 */

import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    include: ["tests/**/*.test.{ts,tsx}"],
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    css: false,
  },
});
