import { mkdir, readFile } from "node:fs/promises";
import StyleDictionary from "style-dictionary";
import { kebab, loadCanonical, toStyleDictionary } from "./dtcg-profile.mjs";

const baseDirectory = new URL("../", import.meta.url).pathname;
const outputDirectory = `${baseDirectory}generated/`;

const semanticTokens = (dictionary) => dictionary.allTokens
  .filter((token) => token.path[0] === "semantic")
  .sort((left, right) => left.path.join(".").localeCompare(right.path.join(".")));

const cssValue = (token) => Array.isArray(token.$value) ? token.$value.join(", ") : String(token.$value);
const nativeValue = (token) => {
  if (token.$type === "dimension") return Number.parseFloat(token.$value);
  return token.$value;
};

StyleDictionary.registerTransform({
  name: "omnilyzer/name",
  type: "name",
  transform: (token) => token.path.join("-"),
});

StyleDictionary.registerFormat({
  name: "omnilyzer/css-theme",
  format: ({ dictionary, options }) => {
    const declarations = semanticTokens(dictionary).map((token) => {
      const name = token.path.slice(1).map(kebab).join("-");
      return `  --omni-${name}: ${cssValue(token)};`;
    }).join("\n");
    return `${options.selectors.join(",\n")} {\n${declarations}\n}\n`;
  },
});

StyleDictionary.registerFormat({
  name: "omnilyzer/native-json",
  format: ({ dictionary }) => {
    const result = Object.fromEntries(semanticTokens(dictionary).map((token) => [token.path.slice(1).join("."), nativeValue(token)]));
    return `${JSON.stringify(result, null, 2)}\n`;
  },
});

async function buildTheme(theme, source, webFile, selectors) {
  const dictionary = new StyleDictionary({
    tokens: toStyleDictionary(source),
    usesDtcg: true,
    platforms: {
      native: {
        buildPath: `${outputDirectory}native/`,
        transforms: ["omnilyzer/name"],
        files: [{ destination: `tokens.${theme}.json`, format: "omnilyzer/native-json" }],
      },
      ...(webFile ? {
        web: {
          buildPath: `${outputDirectory}web/`,
          transforms: ["omnilyzer/name"],
          files: [{ destination: webFile, format: "omnilyzer/css-theme", options: { selectors } }],
        },
      } : {}),
    },
  });
  await dictionary.buildAllPlatforms();
}

const { light, dark } = await loadCanonical(baseDirectory);
await mkdir(`${outputDirectory}web/`, { recursive: true });
await mkdir(`${outputDirectory}native/`, { recursive: true });
await buildTheme("light", light, "tokens.light.css", [":root", '[data-theme="light"]']);
await buildTheme("dark", dark, "tokens.dark.css", ['[data-theme="dark"]']);
const lightCss = await readFile(`${outputDirectory}web/tokens.light.css`, "utf8");
const darkCss = await readFile(`${outputDirectory}web/tokens.dark.css`, "utf8");
const { writeFile, rm } = await import("node:fs/promises");
await writeFile(`${outputDirectory}web/tokens.css`, `${lightCss}\n${darkCss}`);
await rm(`${outputDirectory}web/tokens.light.css`);
await rm(`${outputDirectory}web/tokens.dark.css`);
