import axe from "axe-core";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Button, Dialog, TextField } from "../src";

async function expectNoAxeViolations(container: HTMLElement) {
  const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(result.violations.map((violation) => violation.id)).toEqual([]);
}

describe("Omnilyzer component accessibility", () => {
  it("gives Button an accessible name and semantic target/focus classes", async () => {
    const { container } = render(<Button>Analyze</Button>);
    const button = screen.getByRole("button", { name: "Analyze" });
    expect(button.className).toContain("min-h-hit-target");
    expect(button.className).toContain("ring-focus");
    await expectNoAxeViolations(container);
  });

  it("associates TextField label, hint, invalid state, and error", async () => {
    const { container } = render(<TextField label="Dataset" hint="CSV only" error="Required" />);
    const input = screen.getByRole("textbox", { name: "Dataset" });
    expect(input.getAttribute("aria-invalid")).toBe("true");
    const descriptions = input.getAttribute("aria-describedby")!.split(" ");
    expect(descriptions).toHaveLength(2);
    expect(descriptions.every((id: string) => document.getElementById(id))).toBe(true);
    expect(input.className).toContain("min-h-hit-target");
    await expectNoAxeViolations(container);
  });

  it("labels Dialog, closes with Escape, and restores trigger focus", async () => {
    const user = userEvent.setup();
    render(
      <Dialog trigger={<Button>Open evidence</Button>} title="Evidence" description="Architecture validation details">
        <p>Dialog body</p>
      </Dialog>,
    );
    const trigger = screen.getByRole("button", { name: "Open evidence" });
    await user.click(trigger);
    const dialog = await screen.findByRole("dialog", { name: "Evidence", description: "Architecture validation details" });
    expect(screen.getByRole("button", { name: "Close" }).className).toContain("min-h-hit-target");
    await expectNoAxeViolations(dialog);
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });
});
