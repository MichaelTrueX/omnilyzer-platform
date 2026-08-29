import { readdir, readFile, stat } from "node:fs/promises";

const baseDirectory = new URL("../", import.meta.url).pathname;
const assetDirectory = `${baseDirectory}dist/assets/`;
const files = await readdir(assetDirectory);
const cssFiles = files.filter((name) => name.endsWith(".css"));
if (cssFiles.length !== 1) throw new Error(`Expected one production CSS asset, found ${cssFiles.length}`);
const css = await readFile(`${assetDirectory}${cssFiles[0]}`, "utf8");
for (const evidence of ["--omni-color-canvas", ".bg-canvas", ".min-h-hit-target", ".ring-focus"]) {
  if (!css.includes(evidence)) throw new Error(`Production CSS is missing ${evidence}`);
}
if (/--color-(?:blue|red|neutral)-/.test(css)) throw new Error("Tailwind default color palette variables leaked into the production theme API");
const sizes = await Promise.all(files.filter((name) => /\.(?:css|js)$/.test(name)).map(async (name) => [name, (await stat(`${assetDirectory}${name}`)).size]));
console.log(`Validated static production assets: ${sizes.map(([name, size]) => `${name} ${size} bytes`).join(", ")}`);
