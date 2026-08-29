#!/usr/bin/env node
import { lintDirectory } from "./rules.js";
const directory = process.argv[2];
if (!directory) { console.error("usage: omnilyzer-semantic-lint <source-directory>"); process.exit(2); }
const violations = await lintDirectory(directory);
for (const violation of violations) console.error(violation);
process.exit(violations.length ? 1 : 0);
