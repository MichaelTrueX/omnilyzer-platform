import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const RULES = [
  [/(?:^|[^\w-])#[0-9a-fA-F]{3,8}\b/, "hard-coded hex color"],
  [/\b(?:rgb|rgba|hsl|oklch)\s*\(/i, "raw color function"],
  [/\b(?:(?:[a-z0-9_-]+):)*(?:bg|text|border|ring|outline|decoration|fill|stroke|shadow)-(?:red|blue|green|gray|slate|amber|yellow|purple|pink|neutral)-\d{2,3}\b/i, "raw Tailwind palette"],
  [/\b(?:(?:[a-z0-9_-]+):)*[a-z][a-z0-9_-]*-\[[^\]\r\n]+\]/i, "Tailwind arbitrary styling"],
  [/style\s*=\s*\{\s*\{/, "inline React style"],
];

async function filesBelow(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await filesBelow(path));
    else if (/\.(?:js|jsx|mjs|ts|tsx|css|html)$/.test(entry.name)) output.push(path);
  }
  return output.sort();
}

export async function lintDirectory(directory) {
  const violations = [];
  for (const path of await filesBelow(directory)) {
    const source = await readFile(path, "utf8");
    for (const [pattern, label] of RULES) if (pattern.test(source)) violations.push(`${path}: ${label}`);
  }
  return violations;
}
