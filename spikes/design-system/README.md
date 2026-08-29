# Omnilyzer design-system foundation spike

This spike validates one canonical DTCG token vocabulary flowing through Style Dictionary to semantic web and native outputs, then through a constrained Tailwind v4 bridge to three Omnilyzer components. Radix Dialog is an internal behavior primitive, not part of the public API.

## Foundation

- Canonical sources use the DTCG 2025.10 schema identifier and structured sRGB colors/dimensions. Primitive values feed stable semantic names; primitives are never consumer output.
- Shared dimensions and typography plus theme-specific colors produce identical light/dark semantic key sets. Components do not branch on theme.
- A narrow, fail-closed adapter validates this spike's `color`, `dimension`, `number`, `fontFamily`, and `fontWeight` profile, converts supported structured values in memory, preserves aliases, and delegates reference resolution/platform builds to Style Dictionary.
- `generated/web/tokens.css` contains static semantic custom properties. `generated/native/` contains resolved semantic JSON with numeric px-derived design values.
- `src/styles.css` resets Tailwind's theme namespaces and deliberately bridges only semantic design values. Structural utilities remain available. Repository linting detects common arbitrary/raw styling because Tailwind itself cannot prohibit arbitrary values.
- Button, TextField, and Dialog provide the representative public boundary. Radix is wrapped only by Dialog and is not re-exported.

Accessibility is an architecture requirement: tests calculate WCAG 2.2 AA contrast for both themes, assert semantic relationships and the 44px target contract, and run axe A/AA-applicable rules. axe color contrast is disabled only in jsdom because layout/style evaluation is not reliable there; deterministic token contrast tests provide that evidence. Static CSS avoids CSS-in-JS, component runtime style injection, inline style objects, remote fonts, and remote assets. This does not prove a final application's complete CSP configuration or characterize Radix internals as Omnilyzer policy.

## Versions and commands

Node.js 24 LTS is the validated frontend/design-system JavaScript tooling runtime. This spike uses Node.js 24.20.0, pinned for development by `.node-version`; `package.json` and `.npmrc` reject unsupported engines. Node 20 is not supported by this tooling baseline. Validation used an isolated Node distribution and did not replace or modify the server's global Node installation. This frontend tooling decision does not change Django or its Python runtime.

Pinned spike dependencies: Style Dictionary 5.5.2, Tailwind CSS and `@tailwindcss/vite` 4.3.3, React/React DOM 19.2.8, TypeScript 7.0.2, Vite 8.2.2, React Vite plugin 6.1.0, Radix Dialog 1.1.23, Vitest 4.1.10, Testing Library React 16.3.2, user-event 14.6.6, axe-core 4.13.0, jsdom 30.0.1, and React types 19.2.18/19.2.5.

```bash
npm run tokens:validate
npm run tokens:build
npm run lint:semantic
npm run typecheck
npm test
npm run build:web
npm run validate
```

## Boundaries and limitations

Style Dictionary 5.5.2 does not constitute proof of complete DTCG 2025.10 feature support. The adapter supports only the declared spike profile; it is not a general token framework. Native output proves cross-platform transformation only—not React Native rendering, Dynamic Type, Android/iOS font mapping, or device-density behavior. Packaging/version distribution and equivalent governance distribution to product repositories remain later work.

The synthetic palette, system typography, and spacing are validation evidence only. Task 005 decides token/component architecture, not Omnilyzer's final brand identity. Final brand primitives can replace these values without changing semantic component APIs.
