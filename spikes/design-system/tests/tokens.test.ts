import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error Runtime validation module intentionally remains plain ESM.
import { SCHEMA, loadCanonical, validateDocument } from "../scripts/dtcg-profile.mjs";

const root = path.resolve(import.meta.dirname, "..");
const generated = path.join(root, "generated");

function ratio(foreground: string, background: string) {
  const luminance = (hex: string) => {
    const channels = [1, 3, 5].map((index) => Number.parseInt(hex.slice(index, index + 2), 16) / 255);
    const linear = channels.map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
  };
  const values = [luminance(foreground), luminance(background)].sort((left, right) => right - left);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

async function hashes() {
  const files = [
    path.join(generated, "web/tokens.css"),
    path.join(generated, "native/tokens.light.json"),
    path.join(generated, "native/tokens.dark.json"),
  ];
  return Promise.all(files.map(async (file) => createHash("sha256").update(await readFile(file)).digest("hex")));
}

describe("canonical DTCG profile", () => {
  it("uses the 2025.10 schema and identical semantic keys", async () => {
    const canonical = await loadCanonical(root);
    expect(Object.values(canonical.documents as Record<string, { $schema: string }>).every((document) => document.$schema === SCHEMA)).toBe(true);
    expect(canonical.semanticKeys).toHaveLength(31);
  });

  it.each([
    ["incorrect schema", (doc: any) => { doc.$schema = "wrong"; }],
    ["unsupported type", (doc: any) => { doc.test = { $type: "shadow", $value: "none" }; }],
    ["malformed color", (doc: any) => { doc.test = { $type: "color", $value: { colorSpace: "srgb" } }; }],
    ["out-of-range color", (doc: any) => { doc.test = { $type: "color", $value: { colorSpace: "srgb", components: [2, 0, 0], alpha: 1, hex: "#FF0000" } }; }],
    ["mismatched color", (doc: any) => { doc.test = { $type: "color", $value: { colorSpace: "srgb", components: [0, 0, 0], alpha: 1, hex: "#FFFFFF" } }; }],
    ["malformed dimension", (doc: any) => { doc.test = { $type: "dimension", $value: 4 }; }],
    ["unsupported unit", (doc: any) => { doc.test = { $type: "dimension", $value: { value: 1, unit: "rem" } }; }],
  ])("fails closed for %s", (_name, mutate) => {
    const document: any = { $schema: SCHEMA, valid: { $type: "number", $value: 1 } };
    mutate(document);
    expect(() => validateDocument(document, "fixture")).toThrow();
  });
});

describe("generated platform outputs", () => {
  it("exposes semantic web variables and theme selectors without primitives", async () => {
    const css = await readFile(path.join(generated, "web/tokens.css"), "utf8");
    expect(css).toContain("--omni-color-canvas");
    expect(css).toContain("--omni-color-text-danger");
    expect(css).toContain(":root");
    expect(css).toContain('[data-theme="light"]');
    expect(css).toContain('[data-theme="dark"]');
    expect(css).not.toContain("--omni-primitive-");
  });

  it("emits matching, resolved native semantic values", async () => {
    const light = JSON.parse(await readFile(path.join(generated, "native/tokens.light.json"), "utf8"));
    const dark = JSON.parse(await readFile(path.join(generated, "native/tokens.dark.json"), "utf8"));
    expect(Object.keys(light).sort()).toEqual(Object.keys(dark).sort());
    expect(JSON.stringify([light, dark])).not.toMatch(/primitive|\{[A-Za-z][A-Za-z0-9_.-]+\}/);
    expect(light["color.canvas"]).not.toBe(dark["color.canvas"]);
    expect(light["color.textDanger"]).toBe("#B91C1C");
    expect(dark["color.textDanger"]).toBe("#FCA5A5");
    expect(light["space.hitTarget"]).toBe(44);
  });

  it("meets contrast thresholds in both themes", async () => {
    for (const theme of ["light", "dark"]) {
      const tokens = JSON.parse(await readFile(path.join(generated, `native/tokens.${theme}.json`), "utf8"));
      for (const [foreground, background] of [
        ["color.textPrimary", "color.canvas"],
        ["color.textSecondary", "color.canvas"],
        ["color.actionPrimaryForeground", "color.actionPrimaryBackground"],
        ["color.dangerForeground", "color.dangerBackground"],
        ["color.textDanger", "color.canvas"],
        ["color.textDanger", "color.surface"],
      ]) expect(ratio(tokens[foreground], tokens[background]), `${theme}: ${foreground} on ${background}`).toBeGreaterThanOrEqual(4.5);
      for (const [foreground, background] of [
        ["color.focusRing", "color.canvas"],
        ["color.borderControl", "color.surface"],
      ]) expect(ratio(tokens[foreground], tokens[background]), `${theme}: ${foreground} on ${background}`).toBeGreaterThanOrEqual(3);
    }
  });

  it("rebuilds deterministically in the same test process", async () => {
    const before = await hashes();
    const result = spawnSync(process.execPath, [path.join(root, "scripts/build-tokens.mjs")], { cwd: root, encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
    expect(await hashes()).toEqual(before);
    expect((await readdir(path.join(generated, "web"))).sort()).toEqual(["tokens.css"]);
  });
});
