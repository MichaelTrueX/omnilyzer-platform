import { readFile } from "node:fs/promises";
import { loadCanonical } from "./dtcg-profile.mjs";

const baseDirectory = new URL("../", import.meta.url).pathname;
const { semanticKeys } = await loadCanonical(baseDirectory);

async function validateGenerated() {
  try {
    const css = await readFile(`${baseDirectory}generated/web/tokens.css`, "utf8");
    const light = JSON.parse(await readFile(`${baseDirectory}generated/native/tokens.light.json`, "utf8"));
    const dark = JSON.parse(await readFile(`${baseDirectory}generated/native/tokens.dark.json`, "utf8"));
    if (css.includes("--omni-primitive-")) throw new Error("Primitive token leaked into generated CSS");
    if (!css.includes(":root") || !css.includes('[data-theme="light"]') || !css.includes('[data-theme="dark"]')) throw new Error("Generated CSS theme selectors are incomplete");
    for (const output of [light, dark]) {
      if (Object.keys(output).some((key) => key.includes("primitive")) || JSON.stringify(output).includes("{primitive.")) throw new Error("Primitive or unresolved alias leaked into native output");
    }
    const expected = semanticKeys.map((key) => key.replace(/^semantic\./, "")).sort();
    if (JSON.stringify(Object.keys(light).sort()) !== JSON.stringify(expected) || JSON.stringify(Object.keys(dark).sort()) !== JSON.stringify(expected)) throw new Error("Generated native semantic keys do not match canonical keys");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

await validateGenerated();
console.log(`Validated ${semanticKeys.length} semantic tokens against the Omnilyzer DTCG 2025.10 profile.`);
