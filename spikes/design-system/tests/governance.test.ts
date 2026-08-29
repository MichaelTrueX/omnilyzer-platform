import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "..");
const components = path.join(root, "src/components");

async function componentSource() {
  const files = (await readdir(components)).filter((name) => name.endsWith(".tsx"));
  return Promise.all(files.map(async (name) => [name, await readFile(path.join(components, name), "utf8")] as const));
}

describe("shared-source governance", () => {
  it("pins and enforces the supported Node 24 tooling runtime", async () => {
    const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
    expect(packageJson.engines).toEqual({ node: ">=24.15.0 <25" });
    expect(await readFile(path.join(root, ".node-version"), "utf8")).toBe("24.20.0\n");
    expect(await readFile(path.join(root, ".npmrc"), "utf8")).toBe("engine-strict=true\n");
    expect(JSON.stringify(packageJson.scripts)).not.toMatch(/NODE_OPTIONS|node20-test-compat/);
    expect((await readdir(path.join(root, "scripts"))).some((name) => /node20.*compat/i.test(name))).toBe(false);
  });

  it("contains exactly the three representative components", async () => {
    expect((await readdir(components)).filter((name) => name.endsWith(".tsx")).sort()).toEqual(["Button.tsx", "Dialog.tsx", "TextField.tsx"]);
  });

  it("contains no primitive, arbitrary, inline, or product-specific styling", async () => {
    for (const [name, source] of await componentSource()) {
      expect(source, name).not.toMatch(/#[0-9a-f]{3,8}|\b(?:rgb|rgba|hsl|oklch)\s*\(/i);
      expect(source, name).not.toMatch(/\b(?:[a-z][a-z0-9-]*:)*[a-z][a-z0-9-]*-\[[^\]]+\]|\b(?:bg|text|border|ring)-(?:blue|red|neutral)-\d+/);
      expect(source, name).not.toMatch(/\bstyle\s*=\s*\{\{|Bisma|SHSLearningStudio|Valoria|\bHR\b/);
      expect(source, name).not.toMatch(/from ["'][^"']*(?:product|app)\//);
    }
  });

  it("keeps Radix behind the public index", async () => {
    const publicApi = await readFile(path.join(root, "src/index.ts"), "utf8");
    expect(publicApi).not.toMatch(/@radix-ui|export \*|primitive/i);
    const imports = (await componentSource()).filter(([, source]) => source.includes("@radix-ui"));
    expect(imports.map(([name]) => name)).toEqual(["Dialog.tsx"]);
  });

  it("uses semantic classes without theme branches", async () => {
    const source = (await componentSource()).map(([, content]) => content).join("\n");
    expect(source).toContain("bg-action-primary");
    expect(source).toContain("border-border-control");
    expect(source).not.toMatch(/data-theme|theme\s*===|primitive\.color/);
  });
});
