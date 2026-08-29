import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const sourceRoot = new URL("../src/", import.meta.url).pathname;
const failures = [
  ["hard-coded color", /#[0-9a-fA-F]{3,8}\b|\b(?:rgb|rgba|hsl|oklch)\s*\(/],
  ["Tailwind arbitrary value", /\b(?:[a-z][a-z0-9-]*:)*[a-z][a-z0-9-]*-\[[^\]]+\]/],
  ["raw palette utility", /\b(?:bg|text|border|ring)-(?:blue|red|neutral|black|white)-?\d*\b/],
  ["inline React style", /\bstyle\s*=\s*\{\{/],
];

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => entry.isDirectory() ? files(path.join(directory, entry.name)) : [path.join(directory, entry.name)]));
  return nested.flat().filter((file) => /\.(?:ts|tsx|css)$/.test(file));
}

const violations = [];
for (const filename of await files(sourceRoot)) {
  const content = await readFile(filename, "utf8");
  for (const [label, pattern] of failures) if (pattern.test(content)) violations.push(`${path.relative(sourceRoot, filename)}: ${label}`);
}
if (violations.length) throw new Error(`Semantic usage violations:\n${violations.join("\n")}`);
console.log("Semantic source governance passed.");
