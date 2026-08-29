import { readFile } from "node:fs/promises";
import path from "node:path";

export const SCHEMA = "https://www.designtokens.org/schemas/2025.10/format.json";
export const SUPPORTED_TYPES = new Set(["color", "dimension", "number", "fontFamily", "fontWeight"]);
export const TOKEN_FILES = {
  primitives: "tokens/primitives.tokens.json",
  shared: "tokens/semantic.shared.tokens.json",
  light: "tokens/semantic.light.tokens.json",
  dark: "tokens/semantic.dark.tokens.json",
};

const aliasPattern = /^\{([A-Za-z0-9_.-]+)\}$/;
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function mergeObjects(...objects) {
  const result = {};
  for (const object of objects) {
    for (const [key, value] of Object.entries(object)) {
      if (key === "$schema") continue;
      result[key] = isObject(value) && isObject(result[key])
        ? mergeObjects(result[key], value)
        : structuredClone(value);
    }
  }
  return result;
}

export function walkTokens(root, visit, segments = []) {
  if (!isObject(root)) throw new Error(`Token group ${segments.join(".") || "root"} must be an object`);
  for (const [key, value] of Object.entries(root)) {
    if (key === "$schema") continue;
    const tokenPath = [...segments, key];
    if (isObject(value) && Object.hasOwn(value, "$value")) visit(value, tokenPath);
    else walkTokens(value, visit, tokenPath);
  }
}

function validateColor(value, tokenPath) {
  if (!isObject(value) || value.colorSpace !== "srgb" || !Array.isArray(value.components) || value.components.length !== 3 || value.alpha === undefined || typeof value.hex !== "string") {
    throw new Error(`${tokenPath}: malformed structured sRGB color`);
  }
  if (![...value.components, value.alpha].every((part) => typeof part === "number" && Number.isFinite(part) && part >= 0 && part <= 1)) {
    throw new Error(`${tokenPath}: color components and alpha must be within 0..1`);
  }
  if (!/^#[0-9A-Fa-f]{6}$/.test(value.hex)) throw new Error(`${tokenPath}: color hex must be #RRGGBB`);
  const fromHex = [1, 3, 5].map((index) => Number.parseInt(value.hex.slice(index, index + 2), 16) / 255);
  if (fromHex.some((component, index) => Math.abs(component - value.components[index]) > 0.000001)) {
    throw new Error(`${tokenPath}: color hex/components mismatch`);
  }
}

function validateDimension(value, tokenPath) {
  if (!isObject(value) || typeof value.value !== "number" || !Number.isFinite(value.value) || value.unit !== "px") {
    throw new Error(`${tokenPath}: malformed dimension or unsupported unit (only px is allowed)`);
  }
}

export function validateDocument(document, filename) {
  if (document.$schema !== SCHEMA) throw new Error(`${filename}: missing or incorrect DTCG 2025.10 schema identifier`);
  walkTokens(document, (token, tokenSegments) => {
    const tokenPath = tokenSegments.join(".");
    if (!SUPPORTED_TYPES.has(token.$type)) throw new Error(`${tokenPath}: unsupported token type ${String(token.$type)}`);
    const alias = typeof token.$value === "string" && token.$value.match(aliasPattern);
    if (alias) return;
    if (token.$type === "color") validateColor(token.$value, tokenPath);
    else if (token.$type === "dimension") validateDimension(token.$value, tokenPath);
    else if (token.$type === "number" && (typeof token.$value !== "number" || !Number.isFinite(token.$value))) throw new Error(`${tokenPath}: number value required`);
    else if (token.$type === "fontWeight" && (typeof token.$value !== "number" || !Number.isInteger(token.$value))) throw new Error(`${tokenPath}: numeric font weight required`);
    else if (token.$type === "fontFamily" && !(typeof token.$value === "string" || (Array.isArray(token.$value) && token.$value.every((item) => typeof item === "string")))) throw new Error(`${tokenPath}: font family must be a string or string array`);
  });
}

function tokenPaths(root) {
  const paths = new Set();
  walkTokens(root, (_token, segments) => paths.add(segments.join(".")));
  return paths;
}

export function validateAliases(root) {
  const paths = tokenPaths(root);
  walkTokens(root, (token, segments) => {
    if (typeof token.$value !== "string") return;
    const match = token.$value.match(aliasPattern);
    if (token.$value.includes("{") && !match) throw new Error(`${segments.join(".")}: only whole-token aliases are supported`);
    if (match && !paths.has(match[1])) throw new Error(`${segments.join(".")}: unresolved alias ${token.$value}`);
  });
}

export function semanticPaths(root) {
  const paths = [];
  walkTokens(root.semantic, (_token, segments) => paths.push(["semantic", ...segments].join(".")));
  return paths.sort();
}

function compatibleValue(type, value) {
  if (typeof value === "string" && aliasPattern.test(value)) return value;
  if (type === "color") {
    if (value.alpha === 1) return value.hex.toUpperCase();
    const [red, green, blue] = value.components.map((part) => Math.round(part * 255));
    return `rgba(${red}, ${green}, ${blue}, ${value.alpha})`;
  }
  if (type === "dimension") return `${value.value}px`;
  return value;
}

export function toStyleDictionary(root) {
  const convert = (node) => {
    const output = {};
    for (const [key, value] of Object.entries(node)) {
      if (key === "$schema") continue;
      if (isObject(value) && Object.hasOwn(value, "$value")) {
        output[key] = { $type: value.$type, $value: compatibleValue(value.$type, value.$value) };
      } else output[key] = convert(value);
    }
    return output;
  };
  return convert(root);
}

export async function loadCanonical(baseDirectory = process.cwd()) {
  const entries = await Promise.all(Object.entries(TOKEN_FILES).map(async ([name, relative]) => {
    const filename = path.join(baseDirectory, relative);
    const document = JSON.parse(await readFile(filename, "utf8"));
    validateDocument(document, relative);
    return [name, document];
  }));
  const documents = Object.fromEntries(entries);
  const shared = mergeObjects(documents.primitives, documents.shared);
  const light = mergeObjects(shared, documents.light);
  const dark = mergeObjects(shared, documents.dark);
  validateAliases(light);
  validateAliases(dark);
  const lightKeys = semanticPaths(light);
  const darkKeys = semanticPaths(dark);
  if (JSON.stringify(lightKeys) !== JSON.stringify(darkKeys)) throw new Error("Light and dark semantic token key sets differ");
  return { documents, light, dark, semanticKeys: lightKeys };
}

export function kebab(value) {
  return value.replace(/([a-z0-9])([A-Z])/g, "$1-$2").replaceAll("_", "-").toLowerCase();
}
