/**
 * File: spikes/design-system/tests/browser/demo.spec.ts
 * Purpose: Validates accessible interaction, target sizing, and responsive layout in real Chromium.
 * Related: ../../src/demo/App.tsx, ../../playwright.config.ts, ../../README.md
 */

import axe from "axe-core";
import { expect, test, type Locator, type Page } from "@playwright/test";

type AxeViolation = {
  id: string;
  impact: string | null;
  nodes: Array<{ target: string[] }>;
};

/** Run WCAG 2.x A/AA axe rules using the browser's real DOM and computed styles. */
async function collectAxeViolations(page: Page): Promise<AxeViolation[]> {
  await page.addScriptTag({ content: axe.source });
  return page.evaluate(async () => {
    const browserAxe = (
      window as unknown as {
        axe: {
          run: (
            context: Document,
            options: object,
          ) => Promise<{ violations: AxeViolation[] }>;
        };
      }
    ).axe;

    const result = await browserAxe.run(document, {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
      },
    });
    return result.violations;
  });
}

/** Return the rendered height for an element and fail clearly if it is not visible. */
async function renderedHeight(locator: Locator): Promise<number> {
  const box = await locator.boundingBox();
  expect(box).not.toBeNull();
  return box!.height;
}

test.describe("design-system demo in Chromium", () => {
  test("has no automated WCAG A/AA violations with real computed styles", async ({ page }) => {
    await page.goto("/");
    const violations = await collectAxeViolations(page);
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
  });

  test("preserves 44px controls and restores dialog trigger focus", async ({ page }) => {
    await page.goto("/");

    const primary = page.getByRole("button", { name: "Primary" }).first();
    const field = page.getByRole("textbox", { name: "Evidence field" }).first();
    expect(await renderedHeight(primary)).toBeGreaterThanOrEqual(44);
    expect(await renderedHeight(field)).toBeGreaterThanOrEqual(44);
    const trigger = page.getByRole("button", { name: "Open dialog" }).first();
    await trigger.click();

    const dialog = page.getByRole("dialog", { name: "Architecture dialog" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAccessibleDescription(
      "Radix behavior is available only through the Omnilyzer wrapper.",
    );

    const close = dialog.getByRole("button", { name: "Close" });
    expect(await renderedHeight(close)).toBeGreaterThanOrEqual(44);

    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
  });

  test("switches from stacked mobile fixtures to two desktop columns", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");

    const sections = page.locator("main > section");
    const mobileFirst = await sections.nth(0).boundingBox();
    const mobileSecond = await sections.nth(1).boundingBox();
    expect(mobileFirst).not.toBeNull();
    expect(mobileSecond).not.toBeNull();
    expect(mobileSecond!.y).toBeGreaterThan(mobileFirst!.y);

    await page.setViewportSize({ width: 1280, height: 800 });
    const desktopFirst = await sections.nth(0).boundingBox();
    const desktopSecond = await sections.nth(1).boundingBox();
    expect(desktopFirst).not.toBeNull();
    expect(desktopSecond).not.toBeNull();
    expect(desktopSecond!.x).toBeGreaterThan(desktopFirst!.x);
    expect(Math.abs(desktopSecond!.y - desktopFirst!.y)).toBeLessThan(2);
  });
});
